//! Platform error types

use thiserror::Error;

/// Errors that can occur during platform operations
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Process not found: PID {0}")]
    ProcessNotFound(u32),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid address: 0x{0:016X}")]
    InvalidAddress(u64),

    #[error("Memory read failed at 0x{address:016X}: {reason}")]
    ReadFailed { address: u64, reason: String },

    #[error("Memory write failed at 0x{address:016X}: {reason}")]
    WriteFailed { address: u64, reason: String },

    #[error("Not attached to any process")]
    NotAttached,

    #[error("Already attached to a process")]
    AlreadyAttached,

    #[error("Process has exited")]
    ProcessExited,

    #[error("Architecture mismatch: expected {expected}, got {actual}")]
    ArchitectureMismatch { expected: String, actual: String },

    #[error("Platform not supported")]
    UnsupportedPlatform,

    #[error("Operation not supported on this platform: {0}")]
    UnsupportedOperation(String),

    #[error("I/O error: {0}")]
    IOError(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("macOS specific: {0}")]
    #[cfg(target_os = "macos")]
    MacOSError(String),

    #[error("Linux specific: {0}")]
    #[cfg(target_os = "linux")]
    LinuxError(String),

    #[error("Windows specific: {0}")]
    #[cfg(target_os = "windows")]
    WindowsError(String),
}

impl PlatformError {
    /// Create a permission denied error with actionable guidance
    pub fn permission_denied_with_guidance(operation: &str, guidance: &str) -> Self {
        Self::PermissionDenied(format!("{operation}. {guidance}"))
    }
}
