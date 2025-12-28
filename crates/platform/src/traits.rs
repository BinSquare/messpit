//! Platform trait definitions

use messpit_protocol::{Address, Architecture, Module, Pid, Region, TargetFingerprint};

use crate::PlatformError;

/// Maximum allowed size for a single memory read (64 MB)
pub const MAX_READ_SIZE: usize = 64 * 1024 * 1024;

/// Maximum allowed size for a single memory write (1 MB)
pub const MAX_WRITE_SIZE: usize = 1024 * 1024;

/// Minimum valid user-space address (skip null page)
pub const MIN_USER_ADDRESS: u64 = 0x1000;

/// Handle to an attached process
pub trait ProcessHandle: Send + Sync {
    /// Get the process ID
    fn pid(&self) -> Pid;

    /// Get the target architecture
    fn architecture(&self) -> Architecture;

    /// Get fingerprint for project association
    fn fingerprint(&self) -> TargetFingerprint;

    /// Check if the process is still running
    fn is_alive(&self) -> bool;

    /// Read memory from the target process
    ///
    /// Returns the number of bytes actually read. May be less than requested
    /// if the read crosses into an unmapped region.
    fn read_memory(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError>;

    /// Write memory to the target process
    ///
    /// Returns the number of bytes actually written.
    fn write_memory(&self, address: Address, data: &[u8]) -> Result<usize, PlatformError>;

    /// Enumerate memory regions
    fn regions(&self) -> Result<Vec<Region>, PlatformError>;

    /// Enumerate loaded modules
    fn modules(&self) -> Result<Vec<Module>, PlatformError>;

    /// Detach from the process (called on drop, but can be called explicitly)
    fn detach(&mut self) -> Result<(), PlatformError>;
}

/// Extension trait for convenient memory operations
pub trait ProcessHandleExt: ProcessHandle {
    /// Read a single value from memory
    fn read_value<T: Copy>(&self, address: Address) -> Result<T, PlatformError> {
        let size = std::mem::size_of::<T>();

        // Validate address
        if address.0 < MIN_USER_ADDRESS {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: "Address is in protected memory region".into(),
            });
        }

        let mut buffer = vec![0u8; size];
        let read = self.read_memory(address, &mut buffer)?;
        if read < buffer.len() {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: format!("Incomplete read: got {read} bytes, expected {}", buffer.len()),
            });
        }
        // SAFETY: We've verified the buffer is the right size and fully read
        Ok(unsafe { std::ptr::read(buffer.as_ptr().cast()) })
    }

    /// Write a single value to memory
    fn write_value<T: Copy>(&self, address: Address, value: T) -> Result<(), PlatformError> {
        let size = std::mem::size_of::<T>();

        // Validate address
        if address.0 < MIN_USER_ADDRESS {
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: "Address is in protected memory region".into(),
            });
        }

        let data =
            unsafe { std::slice::from_raw_parts(std::ptr::from_ref(&value).cast(), size) };
        let written = self.write_memory(address, data)?;
        if written < data.len() {
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: format!(
                    "Incomplete write: wrote {written} bytes, expected {}",
                    data.len()
                ),
            });
        }
        Ok(())
    }

    /// Read memory with size validation
    fn read_memory_validated(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        // Validate address
        if address.0 < MIN_USER_ADDRESS {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: "Address is in protected memory region".into(),
            });
        }

        // Validate size
        if buffer.len() > MAX_READ_SIZE {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: format!("Read size {} exceeds maximum {}", buffer.len(), MAX_READ_SIZE),
            });
        }

        self.read_memory(address, buffer)
    }

    /// Write memory with size validation
    fn write_memory_validated(&self, address: Address, data: &[u8]) -> Result<usize, PlatformError> {
        // Validate address
        if address.0 < MIN_USER_ADDRESS {
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: "Address is in protected memory region".into(),
            });
        }

        // Validate size
        if data.len() > MAX_WRITE_SIZE {
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: format!("Write size {} exceeds maximum {}", data.len(), MAX_WRITE_SIZE),
            });
        }

        self.write_memory(address, data)
    }

    /// Find regions that match the given criteria
    fn find_regions(
        &self,
        readable: Option<bool>,
        writable: Option<bool>,
        executable: Option<bool>,
    ) -> Result<Vec<Region>, PlatformError> {
        let regions = self.regions()?;
        Ok(regions
            .into_iter()
            .filter(|r| {
                readable.is_none_or(|v| r.permissions.read == v)
                    && writable.is_none_or(|v| r.permissions.write == v)
                    && executable.is_none_or(|v| r.permissions.execute == v)
            })
            .collect())
    }

    /// Find a module by name (case-insensitive)
    fn find_module(&self, name: &str) -> Result<Option<Module>, PlatformError> {
        let name_lower = name.to_lowercase();
        let modules = self.modules()?;
        Ok(modules
            .into_iter()
            .find(|m| m.name.to_lowercase() == name_lower))
    }
}

// Blanket implementation
impl<T: ProcessHandle + ?Sized> ProcessHandleExt for T {}

/// Information about the current platform's capabilities
pub struct PlatformCapabilities {
    /// Whether the platform is fully supported
    pub fully_supported: bool,
    /// Whether we can attach to arbitrary processes
    pub can_attach: bool,
    /// Known limitations or requirements
    pub notes: Vec<String>,
}

impl PlatformCapabilities {
    /// Get capabilities for the current platform
    #[must_use]
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        return Self {
            fully_supported: true,
            can_attach: true,
            notes: vec!["Administrator privileges may be required for some processes".into()],
        };

        #[cfg(target_os = "linux")]
        return Self {
            fully_supported: true,
            can_attach: true,
            notes: vec![
                "ptrace scope may restrict attaching (check /proc/sys/kernel/yama/ptrace_scope)"
                    .into(),
                "Root or CAP_SYS_PTRACE may be required".into(),
            ],
        };

        #[cfg(target_os = "macos")]
        return Self {
            fully_supported: false,
            can_attach: true,
            notes: vec![
                "macOS is 2nd-class: attach may fail for hardened/SIP-protected processes".into(),
                "Debugging entitlement or SIP disable may be required for some targets".into(),
                "Success is not guaranteed for all processes".into(),
            ],
        };

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return Self {
            fully_supported: false,
            can_attach: false,
            notes: vec!["This platform is not supported".into()],
        };
    }
}
