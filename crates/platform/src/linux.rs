//! Linux platform implementation using /proc filesystem and process_vm_readv/writev
//!
//! Note: ptrace restrictions may apply. Check /proc/sys/kernel/yama/ptrace_scope
//! - 0: classic ptrace permissions (any process can trace any other)
//! - 1: restricted ptrace (only descendants can be traced without CAP_SYS_PTRACE)
//! - 2: admin-only attach (only CAP_SYS_PTRACE processes can trace)
//! - 3: no attach (ptrace completely disabled)
//!
//! This implementation uses process_vm_readv/process_vm_writev which may have
//! similar restrictions depending on kernel configuration.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write as IoWrite};
use std::os::unix::fs::FileExt;
use std::path::Path;

use messpit_protocol::{Address, Architecture, Module, Permissions, Pid, ProcessInfo, Region, TargetFingerprint};

use crate::{PlatformError, ProcessHandle};

/// Linux process handle using /proc/pid/mem for memory access
pub struct LinuxProcess {
    pid: Pid,
    name: String,
    path: Option<String>,
    /// File handle for /proc/pid/mem (for read/write operations)
    mem_file: Option<File>,
}

impl LinuxProcess {
    /// Attach to a process by PID
    pub fn attach(pid: Pid) -> Result<Self, PlatformError> {
        let proc_path = format!("/proc/{}", pid.0);

        // Check if process exists
        if !Path::new(&proc_path).exists() {
            return Err(PlatformError::ProcessNotFound(pid.0));
        }

        // Get process name from /proc/pid/comm
        let name = read_proc_comm(pid.0).unwrap_or_else(|| format!("pid_{}", pid.0));

        // Get executable path from /proc/pid/exe
        let path = fs::read_link(format!("/proc/{}/exe", pid.0))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // Try to open /proc/pid/mem for read/write access
        // This may fail due to ptrace restrictions
        let mem_path = format!("/proc/{}/mem", pid.0);
        let mem_file = File::options()
            .read(true)
            .write(true)
            .open(&mem_path)
            .or_else(|_| {
                // Try read-only if read-write fails
                File::options().read(true).open(&mem_path)
            })
            .ok();

        if mem_file.is_none() {
            // Check if we can at least read maps (to give a better error)
            let maps_path = format!("/proc/{}/maps", pid.0);
            if fs::read_to_string(&maps_path).is_err() {
                return Err(PlatformError::PermissionDenied(
                    "Cannot access process memory. Check ptrace_scope or run as root.".into(),
                ));
            }
        }

        Ok(Self {
            pid,
            name,
            path,
            mem_file,
        })
    }
}

impl ProcessHandle for LinuxProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn architecture(&self) -> Architecture {
        // Try to detect from ELF header of the executable
        if let Some(ref path) = self.path {
            if let Ok(arch) = detect_elf_architecture(path) {
                return arch;
            }
        }

        // Fall back to host architecture
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
        Path::new(&format!("/proc/{}", self.pid.0)).exists()
    }

    fn read_memory(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        if buffer.is_empty() {
            return Ok(0);
        }

        // Try using /proc/pid/mem first (if we have a file handle)
        if let Some(ref mem_file) = self.mem_file {
            match mem_file.read_at(buffer, address.0) {
                Ok(n) => return Ok(n),
                Err(e) => {
                    // If it fails, we'll try process_vm_readv below
                    tracing::debug!("proc/mem read failed: {}, trying process_vm_readv", e);
                }
            }
        }

        // Fall back to process_vm_readv
        read_process_memory_vm(self.pid.0, address.0, buffer)
    }

    fn write_memory(&self, address: Address, data: &[u8]) -> Result<usize, PlatformError> {
        if data.is_empty() {
            return Ok(0);
        }

        // Try using /proc/pid/mem first (if we have a writable file handle)
        if let Some(ref mem_file) = self.mem_file {
            match mem_file.write_at(data, address.0) {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::debug!("proc/mem write failed: {}, trying process_vm_writev", e);
                }
            }
        }

        // Fall back to process_vm_writev
        write_process_memory_vm(self.pid.0, address.0, data)
    }

    fn regions(&self) -> Result<Vec<Region>, PlatformError> {
        parse_proc_maps(self.pid.0)
    }

    fn modules(&self) -> Result<Vec<Module>, PlatformError> {
        parse_proc_maps_modules(self.pid.0)
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        // Drop the mem file handle
        self.mem_file = None;
        Ok(())
    }
}

/// Read process name from /proc/pid/comm
fn read_proc_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Read command line from /proc/pid/cmdline
fn read_proc_cmdline(pid: u32) -> Option<String> {
    fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .and_then(|bytes| {
            // cmdline is null-separated; take the first argument (the executable)
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8(bytes[..end].to_vec()).ok()
        })
        .map(|s| {
            // Extract just the filename from the path
            s.rsplit('/').next().unwrap_or(&s).to_string()
        })
}

/// Detect ELF architecture from file
fn detect_elf_architecture(path: &str) -> Result<Architecture, PlatformError> {
    let mut file = File::open(path).map_err(|e| PlatformError::IOError(e.to_string()))?;

    let mut header = [0u8; 20];
    file.read_exact(&mut header).map_err(|e| PlatformError::IOError(e.to_string()))?;

    // Check ELF magic
    if &header[0..4] != b"\x7fELF" {
        return Err(PlatformError::InvalidData("Not an ELF file".into()));
    }

    // e_machine is at offset 18 (2 bytes, little endian on x86/arm)
    let e_machine = u16::from_le_bytes([header[18], header[19]]);

    match e_machine {
        0x3E => Ok(Architecture::X86_64),    // EM_X86_64
        0x03 => Ok(Architecture::X86),       // EM_386
        0xB7 => Ok(Architecture::Arm64),     // EM_AARCH64
        _ => Err(PlatformError::UnsupportedArchitecture(format!("e_machine: {}", e_machine))),
    }
}

/// Parse /proc/pid/maps to get memory regions
fn parse_proc_maps(pid: u32) -> Result<Vec<Region>, PlatformError> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = File::open(&maps_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            PlatformError::PermissionDenied("Cannot read /proc/pid/maps".into())
        } else if e.kind() == std::io::ErrorKind::NotFound {
            PlatformError::ProcessNotFound(pid)
        } else {
            PlatformError::IOError(e.to_string())
        }
    })?;

    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| PlatformError::IOError(e.to_string()))?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }

    Ok(regions)
}

/// Parse a single line from /proc/pid/maps
/// Format: address perms offset dev inode pathname
/// Example: 7f9c8a600000-7f9c8a800000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
fn parse_maps_line(line: &str) -> Option<Region> {
    let mut parts = line.split_whitespace();

    // Parse address range
    let addr_range = parts.next()?;
    let (start_str, end_str) = addr_range.split_once('-')?;
    let start = u64::from_str_radix(start_str, 16).ok()?;
    let end = u64::from_str_radix(end_str, 16).ok()?;

    // Parse permissions (rwxp or rwxs)
    let perms_str = parts.next()?;
    let permissions = Permissions {
        read: perms_str.contains('r'),
        write: perms_str.contains('w'),
        execute: perms_str.contains('x'),
    };

    // Skip offset, device, inode
    parts.next(); // offset
    parts.next(); // device
    parts.next(); // inode

    // Get pathname (may be empty, or contain spaces in theory)
    let pathname = parts.next().map(|s| s.to_string());

    // Extract module name from pathname
    let module = pathname.as_ref().and_then(|p| {
        if p.starts_with('/') || p.starts_with('[') {
            // It's a file path or special region like [heap], [stack]
            Some(p.rsplit('/').next().unwrap_or(p).to_string())
        } else {
            None
        }
    });

    Some(Region {
        base: Address(start),
        size: end - start,
        permissions,
        module,
    })
}

/// Parse /proc/pid/maps to extract loaded modules (shared libraries and executables)
fn parse_proc_maps_modules(pid: u32) -> Result<Vec<Module>, PlatformError> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            PlatformError::PermissionDenied("Cannot read /proc/pid/maps".into())
        } else if e.kind() == std::io::ErrorKind::NotFound {
            PlatformError::ProcessNotFound(pid)
        } else {
            PlatformError::IOError(e.to_string())
        }
    })?;

    // Group regions by path to determine module extents
    let mut module_map: HashMap<String, (u64, u64)> = HashMap::new(); // path -> (base, end)

    for line in content.lines() {
        let mut parts = line.split_whitespace();

        // Parse address range
        let Some(addr_range) = parts.next() else { continue };
        let Some((start_str, end_str)) = addr_range.split_once('-') else { continue };
        let Ok(start) = u64::from_str_radix(start_str, 16) else { continue };
        let Ok(end) = u64::from_str_radix(end_str, 16) else { continue };

        // Skip perms, offset, device, inode
        parts.next();
        parts.next();
        parts.next();
        parts.next();

        // Get pathname
        let Some(pathname) = parts.next() else { continue };

        // Only include actual files (not [heap], [stack], [vdso], etc.)
        if !pathname.starts_with('/') {
            continue;
        }

        // Update or create module entry
        module_map
            .entry(pathname.to_string())
            .and_modify(|(base, module_end)| {
                *base = (*base).min(start);
                *module_end = (*module_end).max(end);
            })
            .or_insert((start, end));
    }

    // Convert to Module structs
    let modules: Vec<Module> = module_map
        .into_iter()
        .map(|(path, (base, end))| {
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            Module {
                name,
                base: Address(base),
                size: end - base,
                path: Some(path),
            }
        })
        .collect();

    Ok(modules)
}

/// Read memory using process_vm_readv syscall
fn read_process_memory_vm(pid: u32, address: u64, buffer: &mut [u8]) -> Result<usize, PlatformError> {
    use libc::{c_void, iovec, process_vm_readv, pid_t};

    let local_iov = iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };

    let remote_iov = iovec {
        iov_base: address as *mut c_void,
        iov_len: buffer.len(),
    };

    let result = unsafe {
        process_vm_readv(
            pid as pid_t,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ESRCH) => PlatformError::ProcessNotFound(pid),
            Some(libc::EPERM) => PlatformError::PermissionDenied(
                "process_vm_readv permission denied. Check ptrace_scope.".into(),
            ),
            Some(libc::EFAULT) => PlatformError::InvalidAddress(address),
            _ => PlatformError::IOError(format!("process_vm_readv failed: {}", err)),
        });
    }

    Ok(result as usize)
}

/// Write memory using process_vm_writev syscall
fn write_process_memory_vm(pid: u32, address: u64, data: &[u8]) -> Result<usize, PlatformError> {
    use libc::{c_void, iovec, process_vm_writev, pid_t};

    let local_iov = iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    let remote_iov = iovec {
        iov_base: address as *mut c_void,
        iov_len: data.len(),
    };

    let result = unsafe {
        process_vm_writev(
            pid as pid_t,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ESRCH) => PlatformError::ProcessNotFound(pid),
            Some(libc::EPERM) => PlatformError::PermissionDenied(
                "process_vm_writev permission denied. Check ptrace_scope.".into(),
            ),
            Some(libc::EFAULT) => PlatformError::InvalidAddress(address),
            _ => PlatformError::IOError(format!("process_vm_writev failed: {}", err)),
        });
    }

    Ok(result as usize)
}

/// Check if a process is likely attachable (not a kernel thread, exists, etc.)
fn is_process_attachable(pid: u32) -> bool {
    // Kernel threads have no cmdline
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = fs::read(&cmdline_path) {
        if content.is_empty() {
            return false; // Kernel thread
        }
    } else {
        return false; // Can't read
    }

    // Check if we can read the maps file (basic permission check)
    let maps_path = format!("/proc/{}/maps", pid);
    fs::read_to_string(&maps_path).is_ok()
}

/// List all processes on the system
pub fn list_processes() -> Result<Vec<ProcessInfo>, PlatformError> {
    let mut processes = Vec::new();

    // Read /proc directory
    let proc_dir = fs::read_dir("/proc").map_err(|e| PlatformError::IOError(e.to_string()))?;

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Check if the entry name is a number (PID)
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip PID 0 and kernel threads
        if pid == 0 {
            continue;
        }

        // Get process name
        let name = read_proc_comm(pid)
            .or_else(|| read_proc_cmdline(pid))
            .unwrap_or_else(|| format!("pid_{}", pid));

        // Get executable path
        let path = fs::read_link(format!("/proc/{}/exe", pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // Check if attachable
        let attachable = is_process_attachable(pid);

        processes.push(ProcessInfo {
            pid: Pid(pid),
            name,
            path,
            attachable,
        });
    }

    // Sort by name for easier browsing
    processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(processes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_list_processes() {
        let processes = list_processes().expect("Should list processes");
        assert!(!processes.is_empty(), "Should find at least one process");

        // Should find ourselves
        let my_pid = std::process::id();
        let found = processes.iter().any(|p| p.pid.0 == my_pid);
        assert!(found, "Should find our own process");
    }

    #[test]
    fn can_attach_to_self() {
        let my_pid = Pid(std::process::id());
        let result = LinuxProcess::attach(my_pid);

        // This may fail due to ptrace restrictions, which is fine
        match result {
            Ok(proc) => {
                assert_eq!(proc.pid(), my_pid);
                assert!(proc.is_alive());
            }
            Err(PlatformError::PermissionDenied(_)) => {
                // Expected on systems with restrictive ptrace_scope
                println!("Permission denied (expected with restrictive ptrace_scope)");
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test]
    fn can_parse_maps_line() {
        let line = "7f9c8a600000-7f9c8a800000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6";
        let region = parse_maps_line(line).expect("Should parse");

        assert_eq!(region.base.0, 0x7f9c8a600000);
        assert_eq!(region.size, 0x200000);
        assert!(region.permissions.read);
        assert!(!region.permissions.write);
        assert!(region.permissions.execute);
        assert_eq!(region.module, Some("libc.so.6".to_string()));
    }

    #[test]
    fn can_parse_anonymous_maps_line() {
        let line = "7fff12345000-7fff12367000 rw-p 00000000 00:00 0 [stack]";
        let region = parse_maps_line(line).expect("Should parse");

        assert!(region.permissions.read);
        assert!(region.permissions.write);
        assert!(!region.permissions.execute);
        assert_eq!(region.module, Some("[stack]".to_string()));
    }

    #[test]
    fn can_read_own_memory() {
        let my_pid = Pid(std::process::id());

        match LinuxProcess::attach(my_pid) {
            Ok(proc) => {
                // Read some known memory (a stack variable)
                let test_value: u32 = 0xDEADBEEF;
                let addr = &test_value as *const u32 as u64;

                let mut buffer = [0u8; 4];
                match proc.read_memory(Address(addr), &mut buffer) {
                    Ok(n) => {
                        assert_eq!(n, 4);
                        assert_eq!(u32::from_ne_bytes(buffer), 0xDEADBEEF);
                    }
                    Err(PlatformError::PermissionDenied(_)) => {
                        println!("Permission denied for memory read");
                    }
                    Err(e) => {
                        panic!("Unexpected read error: {:?}", e);
                    }
                }
            }
            Err(PlatformError::PermissionDenied(_)) => {
                println!("Permission denied for attach");
            }
            Err(e) => {
                panic!("Unexpected attach error: {:?}", e);
            }
        }
    }
}
