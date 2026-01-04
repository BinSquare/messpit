//! macOS platform implementation using Mach APIs
//!
//! Note: macOS is 2nd-class. Attach may fail for:
//! - SIP-protected processes
//! - Hardened runtime apps without debugging entitlement
//! - System processes
//!
//! Running as root or with debugging entitlements may help.

use std::ffi::CStr;
use std::fs::File;
use std::io::Read as IoRead;
use std::mem::MaybeUninit;

use libc::{c_int, pid_t, proc_listallpids, proc_pidpath, PROC_PIDPATHINFO_MAXSIZE};
use mach2::kern_return::{kern_return_t, KERN_SUCCESS};
use mach2::mach_types::task_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::traps::mach_task_self;
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region, mach_vm_write};
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{vm_region_basic_info_64, VM_REGION_BASIC_INFO_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use sha2::{Sha256, Digest};

use messpit_protocol::{Address, Architecture, Module, Permissions, Pid, ProcessInfo, Region, TargetFingerprint};

use crate::{PlatformError, ProcessHandle};

// Additional Mach constants and functions not in mach2
const VM_REGION_BASIC_INFO_COUNT_64: mach_msg_type_number_t = 9;

// Task info flavors for dyld
const TASK_DYLD_INFO: u32 = 17;
const TASK_DYLD_INFO_COUNT: mach_msg_type_number_t = 5;

/// Structure returned by task_info(TASK_DYLD_INFO)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

/// dyld_all_image_infos structure (64-bit version)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DyldAllImageInfos64 {
    version: u32,
    info_array_count: u32,
    info_array: u64,  // pointer to array of dyld_image_info
    // ... more fields we don't need
}

/// dyld_image_info structure (64-bit version)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DyldImageInfo64 {
    image_load_address: u64,  // Mach-O header address
    image_file_path: u64,     // pointer to path string
    image_file_mod_date: u64,
}

unsafe extern "C" {
    fn proc_name(pid: pid_t, buffer: *mut libc::c_char, buffersize: u32) -> c_int;
    fn task_for_pid(target_tport: mach_port_t, pid: c_int, t: *mut mach_port_t) -> libc::c_int;
    fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> libc::c_int;
    fn task_info(
        target_task: task_t,
        flavor: u32,
        task_info_out: *mut TaskDyldInfo,
        task_info_out_count: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
}

/// macOS process handle using Mach task ports
pub struct MacOSProcess {
    pid: Pid,
    task: task_t,
    name: String,
    path: Option<String>,
    target_arch: Architecture,
}

/// Mach-O header magic numbers
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_MAGIC: u32 = 0xfeedface;  // 32-bit

/// Mach-O CPU types
const CPU_TYPE_X86_64: i32 = 0x01000007;  // CPU_TYPE_X86 | CPU_ARCH_ABI64
const CPU_TYPE_ARM64: i32 = 0x0100000c;   // CPU_TYPE_ARM | CPU_ARCH_ABI64

/// Mach-O load command types
const LC_SEGMENT_64: u32 = 0x19;

/// Mach-O header (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MachHeader64 {
    magic: u32,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

/// Mach-O load command header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

/// Mach-O segment command (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: i32,
    initprot: i32,
    nsects: u32,
    flags: u32,
}

/// Detect the architecture of a target process by reading its Mach-O header
fn detect_target_arch(task: task_t) -> Architecture {
    // Read the first 8 bytes of the first region to find the Mach-O header
    // We need to find the main executable's base address first
    let mut address: mach_vm_address_t = 0;
    let mut size: mach_vm_size_t = 0;
    let mut info: vm_region_basic_info_64 = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object_name: mach_port_t = 0;

    // Find the first readable, executable region (likely the main executable)
    loop {
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                std::ptr::from_mut(&mut info).cast(),
                &mut info_count,
                &mut object_name,
            )
        };

        if kr != KERN_SUCCESS {
            break;
        }

        // Look for a region with read+execute (likely code section)
        if (info.protection & VM_PROT_READ) != 0 && (info.protection & VM_PROT_EXECUTE) != 0 {
            // Try to read Mach-O header
            let header_size = std::mem::size_of::<MachHeader64>();
            let mut header_buf = vec![0u8; header_size];
            let mut size_read: mach_vm_size_t = 0;

            let kr = unsafe {
                mach_vm_read_overwrite(
                    task,
                    address,
                    header_buf.len() as mach_vm_size_t,
                    header_buf.as_mut_ptr() as mach_vm_address_t,
                    &mut size_read,
                )
            };

            if kr == KERN_SUCCESS && size_read >= header_size as u64 {
                let mut header: MachHeader64 = unsafe { MaybeUninit::zeroed().assume_init() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        header_buf.as_ptr(),
                        std::ptr::from_mut(&mut header).cast(),
                        header_size,
                    );
                }

                // Check if it's a valid Mach-O header
                if header.magic == MH_MAGIC_64 || header.magic == MH_MAGIC {
                    return match header.cputype {
                        CPU_TYPE_ARM64 => Architecture::Arm64,
                        CPU_TYPE_X86_64 => Architecture::X86_64,
                        _ => default_host_arch(),
                    };
                }
            }
        }

        address += size;
    }

    // Fall back to host architecture if detection fails
    default_host_arch()
}

/// Get the default host architecture
fn default_host_arch() -> Architecture {
    #[cfg(target_arch = "aarch64")]
    return Architecture::Arm64;

    #[cfg(target_arch = "x86_64")]
    return Architecture::X86_64;

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    return Architecture::X86_64;
}

impl MacOSProcess {
    /// Attach to a process by PID
    pub fn attach(pid: Pid) -> Result<Self, PlatformError> {
        // Get process name
        let name = get_process_name(pid.0 as pid_t).unwrap_or_else(|| format!("pid_{}", pid.0));
        let path = get_process_path(pid.0 as pid_t);

        // Get task port
        let mut task: task_t = MACH_PORT_NULL;
        let kr: kern_return_t =
            unsafe { task_for_pid(mach_task_self(), pid.0 as pid_t, &mut task) };

        if kr != KERN_SUCCESS {
            return Err(PlatformError::permission_denied_with_guidance(
                &format!("task_for_pid failed with error {kr}"),
                "On macOS, attaching to processes requires: \
                 (1) Running as root, or \
                 (2) The target app having the 'get-task-allow' entitlement, or \
                 (3) Disabling SIP (not recommended). \
                 Some hardened system processes cannot be attached to at all.",
            ));
        }

        if task == MACH_PORT_NULL {
            return Err(PlatformError::PermissionDenied(
                "task_for_pid returned null port".into(),
            ));
        }

        // Detect target architecture
        let target_arch = detect_target_arch(task);

        tracing::info!(pid = pid.0, name = %name, arch = ?target_arch, "Attached to process");

        Ok(Self {
            pid,
            task,
            name,
            path,
            target_arch,
        })
    }

    /// Read a null-terminated C string from the target process
    fn read_cstring(&self, address: Address, max_len: usize) -> Option<String> {
        if address.0 == 0 {
            return None;
        }

        let mut buffer = vec![0u8; max_len];
        if self.read_memory_internal(address, &mut buffer).is_err() {
            return None;
        }

        // Find null terminator
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8(buffer[..end].to_vec()).ok()
    }

    /// Internal read that doesn't go through the trait (to avoid borrow issues)
    fn read_memory_internal(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut size_read: mach_vm_size_t = 0;
        let kr = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address.0 as mach_vm_address_t,
                buffer.len() as mach_vm_size_t,
                buffer.as_mut_ptr() as mach_vm_address_t,
                &mut size_read,
            )
        };

        if kr != KERN_SUCCESS {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: format!("mach_vm_read_overwrite failed with error {kr}"),
            });
        }

        Ok(size_read as usize)
    }

    /// Read Mach-O header to determine module size
    fn read_macho_size(&self, base: Address) -> Option<u64> {
        // Read the Mach-O header
        let header_size = std::mem::size_of::<MachHeader64>();
        let mut header_buf = vec![0u8; header_size];

        if self.read_memory_internal(base, &mut header_buf).is_err() {
            return None;
        }

        let mut header: MachHeader64 = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                header_buf.as_ptr(),
                std::ptr::from_mut(&mut header).cast(),
                header_size,
            );
        }

        // Verify magic
        if header.magic != MH_MAGIC_64 {
            return None;
        }

        // Walk load commands to find the highest segment end
        let mut max_end: u64 = 0;
        let mut offset = header_size;
        let lc_size = std::mem::size_of::<LoadCommand>();

        for _ in 0..header.ncmds.min(256) {
            let mut lc_buf = vec![0u8; lc_size];
            if self.read_memory_internal(Address(base.0 + offset as u64), &mut lc_buf).is_err() {
                break;
            }

            let mut lc: LoadCommand = unsafe { MaybeUninit::zeroed().assume_init() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    lc_buf.as_ptr(),
                    std::ptr::from_mut(&mut lc).cast(),
                    lc_size,
                );
            }

            if lc.cmd == LC_SEGMENT_64 {
                // Read the full segment command
                let seg_size = std::mem::size_of::<SegmentCommand64>();
                let mut seg_buf = vec![0u8; seg_size];
                if self.read_memory_internal(Address(base.0 + offset as u64), &mut seg_buf).is_ok() {
                    let mut seg: SegmentCommand64 = unsafe { MaybeUninit::zeroed().assume_init() };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            seg_buf.as_ptr(),
                            std::ptr::from_mut(&mut seg).cast(),
                            seg_size,
                        );
                    }

                    let seg_end = seg.vmaddr + seg.vmsize;
                    if seg_end > max_end {
                        max_end = seg_end;
                    }
                }
            }

            offset += lc.cmdsize as usize;
            if lc.cmdsize == 0 {
                break;
            }
        }

        if max_end > base.0 {
            Some(max_end - base.0)
        } else {
            None
        }
    }

    /// Compute SHA256 hash of the main executable file
    fn compute_executable_hash(&self) -> Option<String> {
        let path = self.path.as_ref()?;

        let mut file = File::open(path).ok()?;
        let mut hasher = Sha256::new();

        // Read in chunks to handle large files
        let mut buffer = [0u8; 65536];
        loop {
            let bytes_read = file.read(&mut buffer).ok()?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        // Return first 16 hex chars (64 bits) for a compact but unique identifier
        Some(format!("{:x}", result).chars().take(16).collect())
    }
}

impl ProcessHandle for MacOSProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn architecture(&self) -> Architecture {
        // Return the detected target architecture (may differ from host on Apple Silicon with Rosetta)
        self.target_arch
    }

    fn fingerprint(&self) -> TargetFingerprint {
        TargetFingerprint {
            process_name: self.name.clone(),
            arch: self.architecture(),
            module_hash: self.compute_executable_hash(),
        }
    }

    fn is_alive(&self) -> bool {
        // Check if process exists
        unsafe { libc::kill(self.pid.0 as pid_t, 0) == 0 }
    }

    fn read_memory(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut size_read: mach_vm_size_t = 0;
        let kr = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address.0 as mach_vm_address_t,
                buffer.len() as mach_vm_size_t,
                buffer.as_mut_ptr() as mach_vm_address_t,
                &mut size_read,
            )
        };

        if kr != KERN_SUCCESS {
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: format!("mach_vm_read_overwrite failed with error {kr}"),
            });
        }

        Ok(size_read as usize)
    }

    fn write_memory(&self, address: Address, data: &[u8]) -> Result<usize, PlatformError> {
        if data.is_empty() {
            return Ok(0);
        }

        let kr = unsafe {
            mach_vm_write(
                self.task,
                address.0 as mach_vm_address_t,
                data.as_ptr() as usize,
                data.len() as mach_msg_type_number_t,
            )
        };

        if kr != KERN_SUCCESS {
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: format!("mach_vm_write failed with error {kr}"),
            });
        }

        Ok(data.len())
    }

    fn regions(&self) -> Result<Vec<Region>, PlatformError> {
        // First, get modules so we can associate regions with them
        let modules = self.modules().unwrap_or_default();

        let mut regions = Vec::new();
        let mut address: mach_vm_address_t = 0;

        loop {
            let mut size: mach_vm_size_t = 0;
            let mut info: vm_region_basic_info_64 = unsafe { MaybeUninit::zeroed().assume_init() };
            let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: mach_port_t = 0;

            let kr = unsafe {
                mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    std::ptr::from_mut(&mut info).cast(),
                    &mut info_count,
                    &mut object_name,
                )
            };

            if kr != KERN_SUCCESS {
                break;
            }

            let permissions = Permissions {
                read: (info.protection & VM_PROT_READ) != 0,
                write: (info.protection & VM_PROT_WRITE) != 0,
                execute: (info.protection & VM_PROT_EXECUTE) != 0,
            };

            // Find which module this region belongs to (if any)
            let module_name = modules.iter().find(|m| {
                let module_end = m.base.0.saturating_add(m.size);
                address >= m.base.0 && address < module_end
            }).map(|m| m.name.clone());

            regions.push(Region {
                base: Address(address),
                size,
                permissions,
                module: module_name,
            });

            address += size;
        }

        Ok(regions)
    }

    fn modules(&self) -> Result<Vec<Module>, PlatformError> {
        let mut modules = Vec::new();

        // Get dyld info from the task
        let mut dyld_info: TaskDyldInfo = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut count = TASK_DYLD_INFO_COUNT;

        let kr = unsafe {
            task_info(
                self.task,
                TASK_DYLD_INFO,
                &mut dyld_info,
                &mut count,
            )
        };

        if kr != KERN_SUCCESS {
            tracing::warn!("task_info(TASK_DYLD_INFO) failed: {kr}");
            // Fall back to just the main executable
            if let Some(path) = &self.path {
                modules.push(Module {
                    name: self.name.clone(),
                    base: Address(0),
                    size: 0,
                    path: Some(path.clone()),
                });
            }
            return Ok(modules);
        }

        // Read dyld_all_image_infos from target process
        let mut all_image_infos: DyldAllImageInfos64 = unsafe { MaybeUninit::zeroed().assume_init() };
        let infos_size = std::mem::size_of::<DyldAllImageInfos64>();
        let mut infos_buf = vec![0u8; infos_size];

        if self.read_memory(Address(dyld_info.all_image_info_addr), &mut infos_buf).is_err() {
            tracing::warn!("Failed to read dyld_all_image_infos");
            return Ok(modules);
        }

        // SAFETY: We've verified the buffer is the right size
        unsafe {
            std::ptr::copy_nonoverlapping(
                infos_buf.as_ptr(),
                std::ptr::from_mut(&mut all_image_infos).cast(),
                infos_size,
            );
        }

        let image_count = all_image_infos.info_array_count as usize;
        if image_count == 0 || all_image_infos.info_array == 0 {
            return Ok(modules);
        }

        // Limit to prevent excessive reads
        let image_count = image_count.min(1000);

        // Read the image info array
        let info_entry_size = std::mem::size_of::<DyldImageInfo64>();
        let array_size = image_count * info_entry_size;
        let mut array_buf = vec![0u8; array_size];

        if self.read_memory(Address(all_image_infos.info_array), &mut array_buf).is_err() {
            tracing::warn!("Failed to read image info array");
            return Ok(modules);
        }

        // Parse each image info entry
        for i in 0..image_count {
            let offset = i * info_entry_size;
            let entry_bytes = &array_buf[offset..offset + info_entry_size];

            let mut entry: DyldImageInfo64 = unsafe { MaybeUninit::zeroed().assume_init() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    entry_bytes.as_ptr(),
                    std::ptr::from_mut(&mut entry).cast(),
                    info_entry_size,
                );
            }

            if entry.image_load_address == 0 {
                continue;
            }

            // Read the image path string
            let path = self.read_cstring(Address(entry.image_file_path), 1024);
            let name = path
                .as_ref()
                .and_then(|p| p.rsplit('/').next())
                .map(String::from)
                .unwrap_or_else(|| format!("module_{:x}", entry.image_load_address));

            // Get module size by reading Mach-O header
            let size = self.read_macho_size(Address(entry.image_load_address)).unwrap_or(0);

            modules.push(Module {
                name,
                base: Address(entry.image_load_address),
                size,
                path,
            });
        }

        // Sort by base address
        modules.sort_by_key(|m| m.base.0);

        Ok(modules)
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        if self.task != MACH_PORT_NULL {
            unsafe {
                mach_port_deallocate(mach_task_self(), self.task);
            }
            self.task = MACH_PORT_NULL;
            tracing::info!(pid = self.pid.0, "Detached from process");
        }
        Ok(())
    }
}

impl Drop for MacOSProcess {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

// Code signing operation flags
const CS_OPS_STATUS: u32 = 0;
const CS_RUNTIME: u32 = 0x00010000;  // Hardened runtime
const CS_GET_TASK_ALLOW: u32 = 0x00000004;  // Allows task_for_pid

unsafe extern "C" {
    fn csops(pid: pid_t, ops: u32, useraddr: *mut u32, usersize: usize) -> c_int;
}

/// Check if a process is likely attachable
///
/// Uses csops to check code signing status. Processes with hardened runtime
/// (without get-task-allow) cannot be attached even with debugger entitlement.
fn is_process_attachable(pid: pid_t, path: &Option<String>, name: &str) -> bool {
    // Filter out Apple system processes by name prefix
    // These have special protections beyond what csops reports
    const APPLE_NAME_PREFIXES: &[&str] = &[
        "com.apple.",
        "Apple",
    ];

    for prefix in APPLE_NAME_PREFIXES {
        if name.starts_with(prefix) {
            return false;
        }
    }

    // Filter out known Apple developer tool services
    const APPLE_SERVICE_NAMES: &[&str] = &[
        "CoreDeviceService",
        "CoreDeviceDDIUpdaterService",
        "DTServiceHub",
        "GPUToolsAgentService",
        "GPUToolsCompatService",
        "SKAgent",
        "CoreSimulator",
    ];

    for service in APPLE_SERVICE_NAMES {
        if name.contains(service) {
            return false;
        }
    }

    // Check path-based exclusions
    if let Some(path) = path {
        const PROTECTED_PATH_PREFIXES: &[&str] = &[
            "/System/",
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/libexec/",
            "/bin/",
            "/sbin/",
            "/Library/Apple/",
            "/Library/Developer/",  // Xcode tools
        ];

        for prefix in PROTECTED_PATH_PREFIXES {
            if path.starts_with(prefix) {
                return false;
            }
        }

        // Filter out Xcode internal executables
        if path.contains("/Xcode.app/") || path.contains("/Xcode-") {
            return false;
        }
    } else {
        // No path means we can't determine - assume not attachable
        return false;
    }

    // Check code signing status using csops
    let mut flags: u32 = 0;
    let result = unsafe {
        csops(
            pid,
            CS_OPS_STATUS,
            &mut flags,
            std::mem::size_of::<u32>(),
        )
    };

    if result != 0 {
        // csops failed - process might have exited or we don't have permission
        // Assume not attachable to be safe
        return false;
    }

    // Check if process has hardened runtime WITHOUT get-task-allow
    // Hardened runtime (CS_RUNTIME) blocks task_for_pid unless get-task-allow is set
    let has_hardened_runtime = (flags & CS_RUNTIME) != 0;
    let has_get_task_allow = (flags & CS_GET_TASK_ALLOW) != 0;

    // Attachable if: not hardened, OR hardened but has get-task-allow
    !has_hardened_runtime || has_get_task_allow
}

/// List all processes on the system
pub fn list_processes(check_attachable: bool, include_path: bool) -> Result<Vec<ProcessInfo>, PlatformError> {
    let mut processes = Vec::new();

    // First call to get count
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Err(PlatformError::SystemError(
            "proc_listallpids failed".into(),
        ));
    }

    // Allocate buffer with some extra space
    let mut pids: Vec<pid_t> = vec![0; (count as usize) + 100];
    let buffer_size = (pids.len() * std::mem::size_of::<pid_t>()) as i32;

    let actual_count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), buffer_size) };
    if actual_count <= 0 {
        return Err(PlatformError::SystemError(
            "proc_listallpids failed on second call".into(),
        ));
    }

    pids.truncate(actual_count as usize);

    for pid in pids {
        if pid <= 0 {
            continue;
        }

        if let Some(name) = get_process_name(pid) {
            let path = if include_path { get_process_path(pid) } else { None };
            let attachable = if check_attachable {
                is_process_attachable(pid, &path, &name)
            } else {
                true
            };
            processes.push(ProcessInfo {
                pid: Pid(pid as u32),
                name,
                path,
                attachable,
            });
        }
    }

    // Sort by name for easier browsing
    processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(processes)
}

fn get_process_name(pid: pid_t) -> Option<String> {
    let mut buffer = [0i8; 256];
    let len = unsafe { proc_name(pid, buffer.as_mut_ptr(), buffer.len() as u32) };

    if len > 0 {
        let cstr = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        cstr.to_str().ok().map(String::from)
    } else {
        None
    }
}

fn get_process_path(pid: pid_t) -> Option<String> {
    let mut buffer = [0i8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe {
        proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };

    if len > 0 {
        let cstr = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        cstr.to_str().ok().map(String::from)
    } else {
        None
    }
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
        // Note: This may fail on hardened macOS without entitlements
        let my_pid = Pid(std::process::id());
        match MacOSProcess::attach(my_pid) {
            Ok(process) => {
                assert!(process.is_alive());
                assert_eq!(process.pid(), my_pid);
            }
            Err(PlatformError::PermissionDenied(_)) => {
                // Expected on macOS without entitlements
                eprintln!("Attach to self failed (expected on hardened macOS)");
            }
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }
}
