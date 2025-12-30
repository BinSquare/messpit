//! Cheat Table Export/Import
//!
//! Cheat tables are portable files (.mct) that contain:
//! - Target process information
//! - Memory entries (direct addresses, pointer chains, or signatures)
//! - Freeze values
//!
//! Unlike full project files, cheat tables are designed to be shared
//! and work across different game versions when using pointer chains or signatures.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use messpit_protocol::{Value, ValueType};

/// Cheat table file extension
pub const CHEAT_TABLE_EXTENSION: &str = "mct";

/// Cheat table schema version
pub const CHEAT_TABLE_VERSION: u32 = 1;

/// A Messpit cheat table file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheatTable {
    /// Schema version
    pub version: u32,
    /// Table name/title
    pub name: String,
    /// Author/creator
    pub author: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Target process information
    pub target: CheatTableTarget,
    /// Cheat entries
    pub entries: Vec<CheatEntry>,
    /// Creation timestamp (ISO8601)
    pub created: String,
    /// Last modified timestamp (ISO8601)
    pub modified: String,
}

impl CheatTable {
    /// Create a new empty cheat table
    pub fn new(name: impl Into<String>, process_name: impl Into<String>) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            version: CHEAT_TABLE_VERSION,
            name: name.into(),
            author: None,
            description: None,
            target: CheatTableTarget {
                process_name: process_name.into(),
                module_hash: None,
            },
            entries: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }

    /// Add an entry to the table
    pub fn add_entry(&mut self, entry: CheatEntry) {
        self.entries.push(entry);
        self.modified = chrono::Utc::now().to_rfc3339();
    }

    /// Load a cheat table from a file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CheatTableError> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| CheatTableError::Io {
            path: path.as_ref().display().to_string(),
            error: e.to_string(),
        })?;

        let table: Self =
            serde_json::from_str(&content).map_err(|e| CheatTableError::ParseError {
                path: path.as_ref().display().to_string(),
                error: e.to_string(),
            })?;

        // Check version compatibility
        if table.version > CHEAT_TABLE_VERSION {
            return Err(CheatTableError::VersionMismatch {
                file_version: table.version,
                supported_version: CHEAT_TABLE_VERSION,
            });
        }

        Ok(table)
    }

    /// Save the cheat table to a file
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<(), CheatTableError> {
        self.modified = chrono::Utc::now().to_rfc3339();

        let content =
            serde_json::to_string_pretty(self).map_err(|e| CheatTableError::SerializeError {
                error: e.to_string(),
            })?;

        fs::write(path.as_ref(), content).map_err(|e| CheatTableError::Io {
            path: path.as_ref().display().to_string(),
            error: e.to_string(),
        })?;

        Ok(())
    }

    /// Export to a compact JSON string (for clipboard, etc.)
    pub fn to_json(&self) -> Result<String, CheatTableError> {
        serde_json::to_string_pretty(self).map_err(|e| CheatTableError::SerializeError {
            error: e.to_string(),
        })
    }

    /// Import from a JSON string
    pub fn from_json(json: &str) -> Result<Self, CheatTableError> {
        serde_json::from_str(json).map_err(|e| CheatTableError::ParseError {
            path: "<string>".to_string(),
            error: e.to_string(),
        })
    }
}

/// Target process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheatTableTarget {
    /// Process name (e.g., "game.exe")
    pub process_name: String,
    /// Optional module hash for verification
    pub module_hash: Option<String>,
}

/// A single cheat entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheatEntry {
    /// Unique ID
    pub id: String,
    /// User-friendly label
    pub label: String,
    /// Optional group/category
    pub group: Option<String>,
    /// Value type
    #[serde(rename = "type")]
    pub value_type: ValueType,
    /// How to locate the address
    pub locator: AddressLocator,
    /// Whether this entry is frozen
    pub frozen: bool,
    /// Freeze value (if frozen)
    pub freeze_value: Option<Value>,
    /// Optional hotkey binding
    pub hotkey: Option<String>,
    /// Optional description
    pub description: Option<String>,
}

impl CheatEntry {
    /// Create a new entry with a direct address
    pub fn direct(id: impl Into<String>, label: impl Into<String>, address: u64, value_type: ValueType) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            group: None,
            value_type,
            locator: AddressLocator::Direct { address },
            frozen: false,
            freeze_value: None,
            hotkey: None,
            description: None,
        }
    }

    /// Create a new entry with a pointer chain
    pub fn pointer_chain(
        id: impl Into<String>,
        label: impl Into<String>,
        value_type: ValueType,
        module: impl Into<String>,
        module_offset: u64,
        offsets: Vec<i64>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            group: None,
            value_type,
            locator: AddressLocator::PointerChain {
                module: module.into(),
                module_offset,
                offsets,
            },
            frozen: false,
            freeze_value: None,
            hotkey: None,
            description: None,
        }
    }

    /// Create a new entry with a signature
    pub fn signature(
        id: impl Into<String>,
        label: impl Into<String>,
        value_type: ValueType,
        module: impl Into<String>,
        pattern: impl Into<String>,
        offset: i64,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            group: None,
            value_type,
            locator: AddressLocator::Signature {
                module: module.into(),
                pattern: pattern.into(),
                offset,
            },
            frozen: false,
            freeze_value: None,
            hotkey: None,
            description: None,
        }
    }
}

/// How to locate the address of an entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AddressLocator {
    /// Direct static address (not portable across game versions)
    #[serde(rename = "direct")]
    Direct {
        /// The memory address
        address: u64,
    },

    /// Pointer chain from a module base (portable)
    #[serde(rename = "pointer_chain")]
    PointerChain {
        /// Module name (e.g., "game.exe")
        module: String,
        /// Offset from module base to first pointer
        module_offset: u64,
        /// Chain of offsets to follow
        offsets: Vec<i64>,
    },

    /// Pattern/signature scan (most portable)
    #[serde(rename = "signature")]
    Signature {
        /// Module to search in
        module: String,
        /// Pattern in IDA format (e.g., "48 8B ?? ?? 00")
        pattern: String,
        /// Offset from pattern match to target
        offset: i64,
    },
}

impl AddressLocator {
    /// Format as a human-readable string
    pub fn format(&self) -> String {
        match self {
            AddressLocator::Direct { address } => format!("0x{:016X}", address),
            AddressLocator::PointerChain { module, module_offset, offsets } => {
                let mut s = format!("[{}+0x{:X}]", module, module_offset);
                for offset in offsets {
                    if *offset >= 0 {
                        s.push_str(&format!("+0x{:X}", offset));
                    } else {
                        s.push_str(&format!("-0x{:X}", offset.unsigned_abs()));
                    }
                }
                s
            }
            AddressLocator::Signature { module, pattern, offset } => {
                let offset_str = if *offset >= 0 {
                    format!("+0x{:X}", offset)
                } else {
                    format!("-0x{:X}", offset.unsigned_abs())
                };
                format!("{}!\"{}\"{}",  module, pattern, offset_str)
            }
        }
    }
}

/// Cheat table errors
#[derive(Debug, thiserror::Error)]
pub enum CheatTableError {
    #[error("I/O error at {path}: {error}")]
    Io { path: String, error: String },

    #[error("Parse error in {path}: {error}")]
    ParseError { path: String, error: String },

    #[error("Serialization error: {error}")]
    SerializeError { error: String },

    #[error("Version mismatch: file is v{file_version}, we support up to v{supported_version}")]
    VersionMismatch {
        file_version: u32,
        supported_version: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cheat_table_new() {
        let table = CheatTable::new("My Cheats", "game.exe");
        assert_eq!(table.name, "My Cheats");
        assert_eq!(table.target.process_name, "game.exe");
        assert!(table.entries.is_empty());
    }

    #[test]
    fn test_address_locator_format() {
        let direct = AddressLocator::Direct { address: 0x12345678 };
        assert_eq!(direct.format(), "0x0000000012345678");

        let chain = AddressLocator::PointerChain {
            module: "game.exe".to_string(),
            module_offset: 0x1234,
            offsets: vec![0x20, -0x10, 0x8],
        };
        assert_eq!(chain.format(), "[game.exe+0x1234]+0x20-0x10+0x8");

        let sig = AddressLocator::Signature {
            module: "game.exe".to_string(),
            pattern: "48 8B ?? 00".to_string(),
            offset: 0x10,
        };
        assert_eq!(sig.format(), "game.exe!\"48 8B ?? 00\"+0x10");
    }

    #[test]
    fn test_entry_creation() {
        let entry = CheatEntry::direct("1", "Health", 0x12345678, ValueType::I32);
        assert_eq!(entry.label, "Health");
        assert!(matches!(entry.locator, AddressLocator::Direct { address: 0x12345678 }));

        let chain_entry = CheatEntry::pointer_chain(
            "2",
            "Gold",
            ValueType::I32,
            "game.exe",
            0x1000,
            vec![0x20, 0x8],
        );
        assert!(matches!(chain_entry.locator, AddressLocator::PointerChain { .. }));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut table = CheatTable::new("Test", "test.exe");
        table.add_entry(CheatEntry::direct("1", "Value", 0x1000, ValueType::I32));

        let json = table.to_json().unwrap();
        let loaded = CheatTable::from_json(&json).unwrap();

        assert_eq!(loaded.name, "Test");
        assert_eq!(loaded.entries.len(), 1);
    }
}
