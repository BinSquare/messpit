//! Messpit Script Host
//!
//! QuickJS sandbox for running user scripts with capability-limited host API.
//!
//! ## Host API
//!
//! Scripts have access to the following API:
//!
//! - `mem.read(addr, type)` - Read memory at address
//! - `mem.write(addr, type, value)` - Write memory at address (policy-gated)
//! - `watch.add(addr, type, label)` - Add a watch entry
//! - `freeze.set(addr, type, value, interval)` - Set a freeze on address
//! - `freeze.clear(addr)` - Clear a freeze
//! - `ui.notify(msg)` - Show a notification to the user
//! - `ui.print(msg)` - Print to script output
//! - `time.sleep(ms)` - Sleep for milliseconds (max 10000ms)

mod bindings;
mod runtime;

pub use bindings::*;
pub use runtime::*;

use messpit_protocol::{Address, RunId, Value, ValueType};
use thiserror::Error;

/// Errors from script execution
#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Script execution timed out")]
    Timeout,

    #[error("Script exceeded memory limit ({0} bytes)")]
    MemoryLimit(usize),

    #[error("Script was cancelled")]
    Cancelled,

    #[error("JavaScript error: {0}")]
    JsError(String),

    #[error("Host API error: {0}")]
    HostError(String),

    #[error("Runtime initialization failed: {0}")]
    InitError(String),
}

/// Script execution result
#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub output: String,
    pub return_value: Option<String>,
}

/// Configuration for script execution
#[derive(Debug, Clone)]
pub struct ScriptConfig {
    /// Maximum execution time in milliseconds
    pub timeout_ms: u64,
    /// Maximum memory usage in bytes
    pub memory_limit: usize,
    /// Maximum single sleep duration in milliseconds
    pub max_sleep_ms: u64,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,              // 30 seconds
            memory_limit: 64 * 1024 * 1024,  // 64 MB
            max_sleep_ms: 10_000,            // 10 seconds max sleep
        }
    }
}

/// Request from script to host
#[derive(Debug, Clone)]
pub enum HostRequest {
    /// Read memory at address
    ReadMemory {
        address: Address,
        value_type: ValueType,
    },
    /// Write memory at address
    WriteMemory {
        address: Address,
        value: Value,
    },
    /// Add a watch entry
    AddWatch {
        address: Address,
        value_type: ValueType,
        label: String,
    },
    /// Set a freeze on address
    SetFreeze {
        address: Address,
        value: Value,
        interval_ms: u32,
    },
    /// Clear a freeze
    ClearFreeze {
        address: Address,
    },
    /// Show notification
    Notify {
        message: String,
    },
    /// Print to output
    Print {
        message: String,
    },
    /// Sleep for duration
    Sleep {
        duration_ms: u64,
    },
}

/// Response from host to script
#[derive(Debug, Clone)]
pub enum HostResponse {
    /// Memory read result
    Value(Option<Value>),
    /// Operation succeeded
    Ok,
    /// Operation failed
    Error(String),
}

/// Event emitted during script execution
#[derive(Debug, Clone)]
pub enum ScriptEvent {
    /// Script produced output
    Output { run_id: RunId, text: String },
    /// Script finished
    Finished { run_id: RunId, status: ScriptStatus },
}

/// Script completion status
#[derive(Debug, Clone)]
pub enum ScriptStatus {
    Success,
    Error { message: String },
    Cancelled,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = ScriptConfig::default();
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.memory_limit, 64 * 1024 * 1024);
        assert_eq!(config.max_sleep_ms, 10_000);
    }
}
