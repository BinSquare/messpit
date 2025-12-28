//! Project persistence
//!
//! Saves and loads .messpit project files (JSON format)

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use messpit_protocol::{Address, Architecture, EntryId, Value, ValueType};

/// Project file schema version
pub const PROJECT_VERSION: u32 = 1;

/// A Messpit project file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Schema version
    pub version: u32,
    /// Project name
    pub name: String,
    /// Target process information
    pub target: Option<ProjectTarget>,
    /// Watch entries
    pub watch_entries: Vec<ProjectWatchEntry>,
    /// Saved signatures for pattern scanning
    pub signatures: Vec<ProjectSignature>,
    /// Saved scripts
    pub scripts: Vec<ProjectScript>,
    /// Scan history (metadata only, not full results)
    pub scan_history: Vec<ScanHistoryEntry>,
    /// User notes (markdown)
    pub notes: String,
}

impl Project {
    /// Create a new empty project
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            version: PROJECT_VERSION,
            name: name.into(),
            target: None,
            watch_entries: Vec::new(),
            signatures: Vec::new(),
            scripts: Vec::new(),
            scan_history: Vec::new(),
            notes: String::new(),
        }
    }

    /// Load a project from a file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProjectError> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| ProjectError::Io {
            path: path.as_ref().display().to_string(),
            error: e.to_string(),
        })?;

        let project: Self =
            serde_json::from_str(&content).map_err(|e| ProjectError::ParseError {
                path: path.as_ref().display().to_string(),
                error: e.to_string(),
            })?;

        // Check version compatibility
        if project.version > PROJECT_VERSION {
            return Err(ProjectError::VersionMismatch {
                file_version: project.version,
                supported_version: PROJECT_VERSION,
            });
        }

        Ok(project)
    }

    /// Save the project to a file
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ProjectError> {
        let content =
            serde_json::to_string_pretty(self).map_err(|e| ProjectError::SerializeError {
                error: e.to_string(),
            })?;

        fs::write(path.as_ref(), content).map_err(|e| ProjectError::Io {
            path: path.as_ref().display().to_string(),
            error: e.to_string(),
        })?;

        Ok(())
    }

    /// Add a watch entry
    pub fn add_watch(&mut self, entry: ProjectWatchEntry) {
        // Remove existing with same ID
        self.watch_entries.retain(|e| e.id != entry.id);
        self.watch_entries.push(entry);
    }

    /// Remove a watch entry
    pub fn remove_watch(&mut self, id: &str) {
        self.watch_entries.retain(|e| e.id != id);
    }

    /// Add a signature
    pub fn add_signature(&mut self, sig: ProjectSignature) {
        self.signatures.retain(|s| s.id != sig.id);
        self.signatures.push(sig);
    }

    /// Remove a signature
    pub fn remove_signature(&mut self, id: &str) {
        self.signatures.retain(|s| s.id != id);
    }

    /// Get a signature by ID
    pub fn get_signature(&self, id: &str) -> Option<&ProjectSignature> {
        self.signatures.iter().find(|s| s.id == id)
    }

    /// Add a script
    pub fn add_script(&mut self, script: ProjectScript) {
        self.scripts.retain(|s| s.id != script.id);
        self.scripts.push(script);
    }

    /// Record a scan in history
    pub fn record_scan(&mut self, entry: ScanHistoryEntry) {
        self.scan_history.push(entry);
        // Keep only last 100 entries
        if self.scan_history.len() > 100 {
            self.scan_history.remove(0);
        }
    }
}

impl Default for Project {
    fn default() -> Self {
        Self::new("Untitled")
    }
}

/// Target process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTarget {
    /// Process name (e.g., "game.exe")
    pub process_name: String,
    /// Optional fingerprint for verification
    pub fingerprint: Option<String>,
    /// Target architecture
    pub arch: Architecture,
}

/// A saved watch entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectWatchEntry {
    /// Unique ID (UUID string)
    pub id: String,
    /// User label
    pub label: String,
    /// Address (may be 0 if resolved from signature)
    pub address: u64,
    /// Value type
    #[serde(rename = "type")]
    pub value_type: ValueType,
    /// Whether frozen
    pub frozen: bool,
    /// Freeze value (if frozen)
    pub freeze_value: Option<Value>,
    /// Associated signature ID (for re-resolution)
    pub signature_id: Option<String>,
}

/// A saved pattern signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSignature {
    /// Unique ID
    pub id: String,
    /// User label
    pub label: String,
    /// Module name to search in
    pub module: String,
    /// Pattern in IDA format (e.g., "48 8B ?? ?? 00")
    pub pattern: String,
    /// Offset from match to target address
    pub offset: i64,
    /// Expected value type at target
    #[serde(rename = "type")]
    pub value_type: ValueType,
}

/// A saved script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectScript {
    /// Unique ID
    pub id: String,
    /// Script name
    pub name: String,
    /// Script source code
    pub source: String,
    /// Whether enabled for auto-run
    pub enabled: bool,
}

/// A scan history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    /// ISO8601 timestamp
    pub timestamp: String,
    /// Scan type description
    pub scan_type: String,
    /// Number of results
    pub result_count: usize,
    /// Optional notes
    pub notes: Option<String>,
}

/// Project-related errors
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_project_new() {
        let project = Project::new("Test Project");
        assert_eq!(project.name, "Test Project");
        assert_eq!(project.version, PROJECT_VERSION);
        assert!(project.watch_entries.is_empty());
    }

    #[test]
    fn test_project_save_load() {
        let mut project = Project::new("Test");
        project.notes = "Hello world".into();
        project.add_watch(ProjectWatchEntry {
            id: "uuid-1".into(),
            label: "Health".into(),
            address: 0x12345678,
            value_type: ValueType::I32,
            frozen: false,
            freeze_value: None,
            signature_id: None,
        });

        // Save to temp file
        let temp = NamedTempFile::new().unwrap();
        project.save(temp.path()).unwrap();

        // Load it back
        let loaded = Project::load(temp.path()).unwrap();
        assert_eq!(loaded.name, "Test");
        assert_eq!(loaded.notes, "Hello world");
        assert_eq!(loaded.watch_entries.len(), 1);
        assert_eq!(loaded.watch_entries[0].label, "Health");
    }

    #[test]
    fn test_version_mismatch() {
        let json = r#"{"version": 999, "name": "Future", "target": null, "watch_entries": [], "signatures": [], "scripts": [], "scan_history": [], "notes": ""}"#;

        let temp = NamedTempFile::new().unwrap();
        writeln!(temp.as_file(), "{}", json).unwrap();

        let result = Project::load(temp.path());
        assert!(matches!(result, Err(ProjectError::VersionMismatch { .. })));
    }

    #[test]
    fn test_scan_history_limit() {
        let mut project = Project::new("Test");

        for i in 0..150 {
            project.record_scan(ScanHistoryEntry {
                timestamp: format!("2024-01-{:02}T00:00:00Z", i % 28 + 1),
                scan_type: "exact_i32".into(),
                result_count: i,
                notes: None,
            });
        }

        assert_eq!(project.scan_history.len(), 100);
    }
}
