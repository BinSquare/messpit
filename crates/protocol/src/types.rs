//! Common types used across commands and events

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommandId(pub Uuid);

impl CommandId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CommandId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub Uuid);

impl EventId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

/// Process identifier (platform-native)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub u32);

/// Memory address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub u64);

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

/// Value types supported for scanning and reading/writing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    /// Fixed-size byte array
    Bytes { len: usize },
    /// Null-terminated or fixed-length string
    String { max_len: usize },
}

impl ValueType {
    /// Returns the size in bytes for fixed-size types
    #[must_use]
    pub const fn size(&self) -> Option<usize> {
        match self {
            Self::I8 | Self::U8 => Some(1),
            Self::I16 | Self::U16 => Some(2),
            Self::I32 | Self::U32 | Self::F32 => Some(4),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            Self::Bytes { len } => Some(*len),
            Self::String { .. } => None, // Variable length
        }
    }
}

/// A typed value for reading/writing memory
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Value {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    String(String),
}

impl Value {
    #[must_use]
    pub const fn value_type(&self) -> ValueType {
        match self {
            Self::I8(_) => ValueType::I8,
            Self::I16(_) => ValueType::I16,
            Self::I32(_) => ValueType::I32,
            Self::I64(_) => ValueType::I64,
            Self::U8(_) => ValueType::U8,
            Self::U16(_) => ValueType::U16,
            Self::U32(_) => ValueType::U32,
            Self::U64(_) => ValueType::U64,
            Self::F32(_) => ValueType::F32,
            Self::F64(_) => ValueType::F64,
            Self::Bytes(b) => ValueType::Bytes { len: b.len() },
            Self::String(s) => ValueType::String { max_len: s.len() },
        }
    }
}

/// Memory region permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// A memory region in the target process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub base: Address,
    pub size: u64,
    pub permissions: Permissions,
    /// Associated module name, if any
    pub module: Option<String>,
}

/// A loaded module in the target process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub base: Address,
    pub size: u64,
    pub path: Option<String>,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
    pub path: Option<String>,
    /// Whether the process is likely attachable (not hardened on macOS)
    /// Defaults to true on platforms where we can't detect this
    #[serde(default = "default_attachable")]
    pub attachable: bool,
}

fn default_attachable() -> bool {
    true
}

/// Target process architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X86_64,
    Arm64,
}

/// Target fingerprint for project association
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFingerprint {
    pub process_name: String,
    pub arch: Architecture,
    /// Optional hash of main module for verification
    pub module_hash: Option<String>,
}

/// Scan parameters for starting a new scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParams {
    pub value_type: ValueType,
    pub comparison: ScanComparison,
    /// Alignment in bytes (1, 2, 4, 8)
    pub alignment: u8,
    /// Only scan writable regions
    pub writable_only: bool,
    /// Scan specific regions (empty = all)
    pub region_filter: Vec<Address>,
}

/// Comparison mode for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum ScanComparison {
    /// Exact value match
    Exact { value: Value },
    /// Unknown initial value (first scan only)
    Unknown,
    /// Value in range [min, max]
    Range { min: Value, max: Value },
    /// Float comparison with epsilon tolerance
    FloatEpsilon { value: f64, epsilon: f64 },
}

/// Refinement mode for subsequent scans
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum Refinement {
    /// Value changed from previous scan
    Changed,
    /// Value unchanged from previous scan
    Unchanged,
    /// Value increased from previous scan
    Increased,
    /// Value decreased from previous scan
    Decreased,
    /// New exact value
    Exact { value: Value },
    /// New range
    Range { min: Value, max: Value },
}

/// Filter options for listing regions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionFilter {
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
    pub module_name: Option<String>,
}

/// Unique identifier for a scan session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanId(pub Uuid);

impl ScanId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ScanId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a background job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub Uuid);

impl JobId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for watch/freeze entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(pub Uuid);

impl EntryId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EntryId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScriptId(pub Uuid);

impl ScriptId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ScriptId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for script runs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub Uuid);

impl RunId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_type_sizes() {
        assert_eq!(ValueType::I8.size(), Some(1));
        assert_eq!(ValueType::I32.size(), Some(4));
        assert_eq!(ValueType::F64.size(), Some(8));
        assert_eq!(ValueType::Bytes { len: 16 }.size(), Some(16));
        assert_eq!(ValueType::String { max_len: 100 }.size(), None);
    }

    #[test]
    fn value_serialization() {
        let val = Value::I32(42);
        let json = serde_json::to_string(&val).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val, parsed);
    }
}
