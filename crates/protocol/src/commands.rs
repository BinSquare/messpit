//! Engine commands (UI → Engine)

use serde::{Deserialize, Serialize};

use crate::{
    Address, CommandId, EntryId, JobId, Pid, RegionFilter, Refinement, RunId, ScanId, ScanParams,
    ScriptId, Value, ValueType,
};

/// Envelope for all commands with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub id: CommandId,
    pub command: EngineCommand,
}

impl CommandEnvelope {
    #[must_use]
    pub fn new(command: EngineCommand) -> Self {
        Self {
            id: CommandId::new(),
            command,
        }
    }
}

/// All commands that can be sent to the engine
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineCommand {
    // === Process Management ===
    /// List all attachable processes
    ListProcesses,

    /// Attach to a process by PID
    Attach { pid: Pid },

    /// Detach from the currently attached process
    Detach,

    // === Memory Inspection ===
    /// List loaded modules in the attached process
    ListModules,

    /// List memory regions with optional filtering
    ListRegions { filter: Option<RegionFilter> },

    /// Read values at specific addresses
    ReadValues { addresses: Vec<Address>, ty: ValueType },

    /// Write a value to an address (policy-gated)
    WriteValue {
        address: Address,
        value: Value,
        /// Reason for the write
        reason: String,
    },

    // === Scanning ===
    /// Start a new scan
    StartScan { scan_id: ScanId, params: ScanParams },

    /// Refine an existing scan
    RefineScan { scan_id: ScanId, refinement: Refinement },

    /// Get a page of scan results
    GetScanResults {
        scan_id: ScanId,
        offset: usize,
        limit: usize,
    },

    /// Cancel and discard a scan
    CancelScan { scan_id: ScanId },

    // === Watch & Freeze ===
    /// Add an address to the watch list
    AddWatch {
        entry_id: EntryId,
        address: Address,
        ty: ValueType,
        label: String,
    },

    /// Remove an entry from the watch list
    RemoveWatch { entry_id: EntryId },

    /// Enable or disable freezing for an entry
    SetFreeze {
        entry_id: EntryId,
        enabled: bool,
        value: Option<Value>,
        /// Freeze interval in milliseconds
        interval_ms: u32,
    },

    /// Global freeze kill switch
    DisableAllFreezes,

    // === Pattern Scanning ===
    /// Start a pattern/signature scan
    StartPatternScan {
        job_id: JobId,
        /// Module to scan (None = all regions)
        module: Option<String>,
        /// Pattern bytes (0xFF = wildcard represented by None)
        pattern: Vec<Option<u8>>,
        /// Region filters
        region_filter: Option<RegionFilter>,
    },

    /// Resolve a module-relative offset to runtime address
    ResolveSymbol { module: String, offset: u64 },

    // === Scripting ===
    /// Execute a script
    RunScript {
        run_id: RunId,
        script_id: ScriptId,
        source: String,
        args: Vec<String>,
    },

    /// Cancel a running job (scan, pattern scan, or script)
    CancelJob { job_id: JobId },

    // === Project ===
    /// Save current session to a project file
    SaveProject { path: String },

    /// Load a project file
    LoadProject { path: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serialization() {
        let cmd = EngineCommand::Attach { pid: Pid(1234) };
        let envelope = CommandEnvelope::new(cmd);
        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: CommandEnvelope = serde_json::from_str(&json).unwrap();

        match parsed.command {
            EngineCommand::Attach { pid } => assert_eq!(pid.0, 1234),
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn scan_command_serialization() {
        let cmd = EngineCommand::StartScan {
            scan_id: ScanId::new(),
            params: ScanParams {
                value_type: ValueType::I32,
                comparison: crate::ScanComparison::Exact {
                    value: Value::I32(100),
                },
                alignment: 4,
                writable_only: true,
                region_filter: vec![],
            },
        };
        let json = serde_json::to_string_pretty(&cmd).unwrap();
        assert!(json.contains("start_scan"));
        assert!(json.contains("i32"));
    }
}
