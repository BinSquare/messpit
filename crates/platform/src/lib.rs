//! Messpit Platform Abstraction
//!
//! Provides cross-platform abstractions for process memory operations.
//!
//! Platform support levels:
//! - Windows: Primary (full support)
//! - Linux: Secondary (ptrace-based)
//! - macOS: 2nd-class (best-effort, some targets may fail)

mod error;
mod traits;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub use error::*;
pub use traits::*;

// Re-export platform-specific implementations
#[cfg(target_os = "macos")]
pub use macos::MacOSProcess;

#[cfg(target_os = "linux")]
pub use linux::LinuxProcess;

#[cfg(target_os = "windows")]
pub use windows::WindowsProcess;

/// List all processes with optional attachable checks
pub fn list_processes_with_options(
    check_attachable: bool,
    include_path: bool,
) -> Result<Vec<messpit_protocol::ProcessInfo>, PlatformError> {
    #[cfg(target_os = "macos")]
    return macos::list_processes(check_attachable, include_path);

    #[cfg(target_os = "linux")]
    return linux::list_processes(check_attachable, include_path);

    #[cfg(target_os = "windows")]
    return windows::list_processes(check_attachable, include_path);

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Err(PlatformError::UnsupportedPlatform)
}

/// List all processes that can potentially be attached to
pub fn list_processes() -> Result<Vec<messpit_protocol::ProcessInfo>, PlatformError> {
    list_processes_with_options(true, true)
}

/// Attach to a process by PID
pub fn attach(pid: messpit_protocol::Pid) -> Result<Box<dyn ProcessHandle>, PlatformError> {
    #[cfg(target_os = "macos")]
    return macos::MacOSProcess::attach(pid).map(|p| Box::new(p) as Box<dyn ProcessHandle>);

    #[cfg(target_os = "linux")]
    return linux::LinuxProcess::attach(pid).map(|p| Box::new(p) as Box<dyn ProcessHandle>);

    #[cfg(target_os = "windows")]
    return windows::WindowsProcess::attach(pid).map(|p| Box::new(p) as Box<dyn ProcessHandle>);

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Err(PlatformError::UnsupportedPlatform)
}
