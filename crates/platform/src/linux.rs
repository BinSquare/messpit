//! Linux platform implementation using ptrace and /proc
//!
//! Note: ptrace restrictions may apply. Check /proc/sys/kernel/yama/ptrace_scope

use messpit_protocol::{Address, Architecture, Module, Pid, ProcessInfo, Region, TargetFingerprint};

use crate::{PlatformError, ProcessHandle};

/// Linux process handle using ptrace and /proc/pid/mem
pub struct LinuxProcess {
    pid: Pid,
    name: String,
    // TODO: Add mem_fd for reading/writing via /proc/pid/mem
}

impl LinuxProcess {
    /// Attach to a process by PID
    pub fn attach(pid: Pid) -> Result<Self, PlatformError> {
        // TODO: Implement ptrace attach and /proc/pid/mem opening
        Err(PlatformError::UnsupportedOperation(
            "Linux implementation not yet complete".into(),
        ))
    }
}

impl ProcessHandle for LinuxProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn architecture(&self) -> Architecture {
        #[cfg(target_arch = "x86_64")]
        return Architecture::X86_64;

        #[cfg(target_arch = "x86")]
        return Architecture::X86;

        #[cfg(target_arch = "aarch64")]
        return Architecture::Arm64;

        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        return Architecture::X86_64;
    }

    fn fingerprint(&self) -> TargetFingerprint {
        TargetFingerprint {
            process_name: self.name.clone(),
            arch: self.architecture(),
            module_hash: None,
        }
    }

    fn is_alive(&self) -> bool {
        std::path::Path::new(&format!("/proc/{}", self.pid.0)).exists()
    }

    fn read_memory(&self, _address: Address, _buffer: &mut [u8]) -> Result<usize, PlatformError> {
        Err(PlatformError::UnsupportedOperation(
            "Linux read not yet implemented".into(),
        ))
    }

    fn write_memory(&self, _address: Address, _data: &[u8]) -> Result<usize, PlatformError> {
        Err(PlatformError::UnsupportedOperation(
            "Linux write not yet implemented".into(),
        ))
    }

    fn regions(&self) -> Result<Vec<Region>, PlatformError> {
        // TODO: Parse /proc/pid/maps
        Err(PlatformError::UnsupportedOperation(
            "Linux regions not yet implemented".into(),
        ))
    }

    fn modules(&self) -> Result<Vec<Module>, PlatformError> {
        // TODO: Parse /proc/pid/maps for module info
        Err(PlatformError::UnsupportedOperation(
            "Linux modules not yet implemented".into(),
        ))
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        // TODO: ptrace detach
        Ok(())
    }
}

/// List all processes on the system
pub fn list_processes() -> Result<Vec<ProcessInfo>, PlatformError> {
    // TODO: Read /proc to enumerate processes
    Err(PlatformError::UnsupportedOperation(
        "Linux process listing not yet implemented".into(),
    ))
}
