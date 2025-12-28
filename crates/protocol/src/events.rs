//! Engine events (Engine → UI)

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Address, CommandId, EntryId, EventId, JobId, Module, ProcessInfo, Region, RunId, ScanId,
    TargetFingerprint, Value,
};

/// Envelope for all events with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: EventId,
    /// The command this event is responding to (if any)
    pub command_id: Option<CommandId>,
    pub event: EngineEvent,
}

impl EventEnvelope {
    #[must_use]
    pub fn new(event: EngineEvent, command_id: Option<CommandId>) -> Self {
        Self {
            id: EventId::new(),
            command_id,
            event,
        }
    }

    #[must_use]
    pub fn response(event: EngineEvent, command_id: CommandId) -> Self {
        Self::new(event, Some(command_id))
    }

    #[must_use]
    pub fn unsolicited(event: EngineEvent) -> Self {
        Self::new(event, None)
    }
}

/// All events that can be emitted by the engine
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    // === Process Management ===
    /// List of available processes
    ProcessList { processes: Vec<ProcessInfo> },

    /// Successfully attached to a process
    Attached { fingerprint: TargetFingerprint },

    /// Detached from process (requested or process exited)
    Detached { reason: DetachReason },

    // === Memory Inspection ===
    /// List of loaded modules
    ModuleList { modules: Vec<Module> },

    /// List of memory regions
    RegionList { regions: Vec<Region> },

    /// Values read from addresses
    ValuesRead { values: Vec<(Address, Option<Value>)> },

    /// Value successfully written
    ValueWritten { address: Address },

    // === Scanning ===
    /// Scan progress update
    ScanProgress {
        scan_id: ScanId,
        /// 0.0 to 1.0
        percent: f32,
        /// Bytes scanned per second
        throughput: u64,
    },

    /// Scan completed with results
    ScanResults {
        scan_id: ScanId,
        /// Total number of matches
        count: usize,
        /// First page of results for preview
        preview: Vec<ScanResultEntry>,
    },

    /// Page of scan results
    ScanResultsPage {
        scan_id: ScanId,
        offset: usize,
        entries: Vec<ScanResultEntry>,
    },

    /// Scan cancelled
    ScanCancelled { scan_id: ScanId },

    // === Watch & Freeze ===
    /// Periodic update of watched values
    WatchUpdate { entries: Vec<WatchEntryUpdate> },

    /// Freeze failed (address became invalid, permission denied, etc.)
    FreezeFailed { entry_id: EntryId, reason: String },

    // === Pattern Scanning ===
    /// Pattern scan completed
    PatternScanResults {
        job_id: JobId,
        matches: Vec<PatternMatch>,
    },

    /// Symbol resolved to runtime address
    SymbolResolved {
        module: String,
        offset: u64,
        address: Address,
    },

    // === Scripting ===
    /// Script output (stdout/stderr combined)
    ScriptOutput { run_id: RunId, text: String },

    /// Script finished execution
    ScriptFinished { run_id: RunId, status: ScriptStatus },

    // === Policy ===
    /// Command was denied by policy
    PolicyDenied {
        command_id: CommandId,
        reason: PolicyDenialReason,
    },

    /// Audit record for mutating operations
    AuditRecord { record: AuditEntry },

    // === Errors ===
    /// An error occurred processing a command
    Error(EngineError),

    // === Project ===
    /// Project saved successfully
    ProjectSaved { path: String },

    /// Project loaded successfully
    ProjectLoaded { path: String },
}

/// A single scan result entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultEntry {
    pub address: Address,
    pub current_value: Option<Value>,
    pub previous_value: Option<Value>,
}

/// Update for a watch entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEntryUpdate {
    pub entry_id: EntryId,
    pub address: Address,
    pub value: Option<Value>,
    pub frozen: bool,
}

/// A pattern scan match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub address: Address,
    /// Module the match was found in, if any
    pub module: Option<String>,
    /// Offset within the module
    pub module_offset: Option<u64>,
}

/// Reason for detachment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachReason {
    Requested,
    ProcessExited,
    AccessDenied,
    Error { message: String },
}

/// Script execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptStatus {
    Success,
    Error { message: String },
    Cancelled,
    Timeout,
}

/// Reason for policy denial
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDenialReason {
    pub code: String,
    pub message: String,
    /// Actionable suggestion for the user
    pub suggestion: Option<String>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub operation: String,
    pub target_pid: Option<u32>,
    pub address: Option<Address>,
    pub details: Option<String>,
}

/// Structured error from the engine
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct EngineError {
    pub code: ErrorCode,
    pub message: String,
    /// Additional structured context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl EngineError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Error codes for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // Transient errors (retry may succeed)
    ProcessBusy,
    MemoryChanged,
    TemporaryFailure,

    // Permanent errors (user action required)
    ProcessNotFound,
    PermissionDenied,
    InvalidAddress,
    InvalidPattern,
    InvalidValue,
    NotAttached,
    AlreadyAttached,
    UnsupportedPlatform,
    UnsupportedArchitecture,

    // Internal errors (bugs)
    InternalError,
}

impl ErrorCode {
    /// Whether this error is transient (retry may succeed)
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::ProcessBusy | Self::MemoryChanged | Self::TemporaryFailure
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization() {
        let event = EngineEvent::Attached {
            fingerprint: TargetFingerprint {
                process_name: "game.exe".to_string(),
                arch: crate::Architecture::X86_64,
                module_hash: None,
            },
        };
        let envelope = EventEnvelope::unsolicited(event);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("attached"));
        assert!(json.contains("game.exe"));
    }

    #[test]
    fn error_serialization() {
        let err = EngineError::new(ErrorCode::PermissionDenied, "Access denied to process")
            .with_details(serde_json::json!({"pid": 1234}));
        let json = serde_json::to_string_pretty(&err).unwrap();
        assert!(json.contains("permission_denied"));
        assert!(json.contains("1234"));
    }
}
