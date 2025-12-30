//! Windows platform implementation using Win32 APIs
//!
//! Uses the following APIs:
//! - CreateToolhelp32Snapshot + Process32First/Next for process listing
//! - OpenProcess for process attachment
//! - ReadProcessMemory / WriteProcessMemory for memory operations
//! - VirtualQueryEx for memory region enumeration
//! - Module32First/Next for module listing
//! - AdjustTokenPrivileges for SeDebugPrivilege elevation
//!
//! Note: Requires appropriate access rights. Running as Administrator
//! may be needed for some protected processes. The attach function will
//! automatically attempt to enable SeDebugPrivilege if access is denied.

use std::ffi::OsString;
use std::mem::{self, MaybeUninit};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID, MAX_PATH};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::{GetModuleFileNameExW, GetProcessImageFileNameW};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, IsWow64Process, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Track whether we've already attempted to enable debug privilege
static DEBUG_PRIVILEGE_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static DEBUG_PRIVILEGE_ENABLED: AtomicBool = AtomicBool::new(false);

use messpit_protocol::{Address, Architecture, Module, Permissions, Pid, ProcessInfo, Region, TargetFingerprint};

use crate::{PlatformError, ProcessHandle};

/// Windows process handle using HANDLE
pub struct WindowsProcess {
    pid: Pid,
    handle: HANDLE,
    name: String,
    path: Option<String>,
    is_wow64: bool, // True if 32-bit process on 64-bit Windows
}

impl WindowsProcess {
    /// Attach to a process by PID
    ///
    /// This function will automatically attempt to enable SeDebugPrivilege
    /// if the initial attach fails with access denied.
    pub fn attach(pid: Pid) -> Result<Self, PlatformError> {
        Self::attach_internal(pid, true)
    }

    /// Internal attach implementation with retry logic
    fn attach_internal(pid: Pid, retry_with_privilege: bool) -> Result<Self, PlatformError> {
        // Open the process with required access rights
        let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

        let handle = match unsafe { OpenProcess(access, false, pid.0) } {
            Ok(h) => h,
            Err(e) => {
                let code = e.code().0 as u32;

                // Error code 5 = ERROR_ACCESS_DENIED
                if code == 5 && retry_with_privilege {
                    // Try to enable debug privilege and retry
                    if enable_debug_privilege() {
                        tracing::debug!(pid = pid.0, "Retrying attach with SeDebugPrivilege");
                        return Self::attach_internal(pid, false);
                    }
                }

                return Err(match code {
                    5 => PlatformError::PermissionDenied(
                        "Access denied. Try running as Administrator.".into(),
                    ),
                    87 => PlatformError::ProcessNotFound(pid.0),
                    _ => PlatformError::SystemError(format!("OpenProcess failed: {e}")),
                });
            }
        };

        // Get process name and path
        let (name, path) = get_process_name_and_path(handle, pid.0);

        // Check if it's a WoW64 process (32-bit on 64-bit Windows)
        let is_wow64 = is_wow64_process(handle);

        tracing::info!(
            pid = pid.0,
            name = %name,
            is_wow64 = is_wow64,
            debug_privilege = is_debug_privilege_enabled(),
            "Attached to process"
        );

        Ok(Self {
            pid,
            handle,
            name,
            path,
            is_wow64,
        })
    }
}

impl ProcessHandle for WindowsProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn architecture(&self) -> Architecture {
        if self.is_wow64 {
            // 32-bit process on 64-bit Windows
            Architecture::X86
        } else {
            // Native process - use host architecture
            #[cfg(target_arch = "x86_64")]
            return Architecture::X86_64;

            #[cfg(target_arch = "x86")]
            return Architecture::X86;

            #[cfg(target_arch = "aarch64")]
            return Architecture::Arm64;

            #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
            return Architecture::X86_64;
        }
    }

    fn fingerprint(&self) -> TargetFingerprint {
        TargetFingerprint {
            process_name: self.name.clone(),
            arch: self.architecture(),
            module_hash: None,
        }
    }

    fn is_alive(&self) -> bool {
        let mut exit_code: u32 = 0;
        let result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };
        // STILL_ACTIVE = 259
        result.is_ok() && exit_code == 259
    }

    fn read_memory(&self, address: Address, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut bytes_read: usize = 0;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address.0 as *const _,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut bytes_read),
            )
        };

        if result.is_err() {
            let err = std::io::Error::last_os_error();
            return Err(PlatformError::ReadFailed {
                address: address.0,
                reason: format!("ReadProcessMemory failed: {err}"),
            });
        }

        Ok(bytes_read)
    }

    fn write_memory(&self, address: Address, data: &[u8]) -> Result<usize, PlatformError> {
        if data.is_empty() {
            return Ok(0);
        }

        let mut bytes_written: usize = 0;
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                address.0 as *const _,
                data.as_ptr().cast(),
                data.len(),
                Some(&mut bytes_written),
            )
        };

        if result.is_err() {
            let err = std::io::Error::last_os_error();
            return Err(PlatformError::WriteFailed {
                address: address.0,
                reason: format!("WriteProcessMemory failed: {err}"),
            });
        }

        Ok(bytes_written)
    }

    fn regions(&self) -> Result<Vec<Region>, PlatformError> {
        let mut regions = Vec::new();
        let mut address: usize = 0;

        // Get modules first for region->module association
        let modules = self.modules().unwrap_or_default();

        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { MaybeUninit::zeroed().assume_init() };
            let info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

            let result = unsafe {
                VirtualQueryEx(
                    self.handle,
                    Some(address as *const _),
                    &mut info,
                    info_size,
                )
            };

            if result == 0 {
                break;
            }

            // Only include committed memory
            if info.State == MEM_COMMIT {
                let permissions = protection_to_permissions(info.Protect.0);

                // Find which module this region belongs to
                let region_addr = info.BaseAddress as u64;
                let module_name = modules.iter().find(|m| {
                    let module_end = m.base.0.saturating_add(m.size);
                    region_addr >= m.base.0 && region_addr < module_end
                }).map(|m| m.name.clone());

                regions.push(Region {
                    base: Address(info.BaseAddress as u64),
                    size: info.RegionSize as u64,
                    permissions,
                    module: module_name,
                });
            }

            // Move to next region
            address = (info.BaseAddress as usize) + info.RegionSize;

            // Check for overflow (end of address space)
            if address < info.BaseAddress as usize {
                break;
            }
        }

        Ok(regions)
    }

    fn modules(&self) -> Result<Vec<Module>, PlatformError> {
        let mut modules = Vec::new();

        // Create snapshot of modules
        // Use TH32CS_SNAPMODULE32 as well to capture 32-bit modules on WoW64
        let flags = if self.is_wow64 {
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        } else {
            TH32CS_SNAPMODULE
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(flags, self.pid.0) }.map_err(|e| {
            PlatformError::SystemError(format!("CreateToolhelp32Snapshot failed: {e}"))
        })?;

        // Ensure snapshot is closed when we're done
        let _guard = HandleGuard(snapshot);

        let mut entry: MODULEENTRY32W = unsafe { MaybeUninit::zeroed().assume_init() };
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        // Get first module
        if unsafe { Module32FirstW(snapshot, &mut entry) }.is_err() {
            // No modules found - might be access denied for protected process
            return Ok(modules);
        }

        loop {
            let name = wchar_to_string(&entry.szModule);
            let path = wchar_to_string(&entry.szExePath);

            modules.push(Module {
                name,
                base: Address(entry.modBaseAddr as u64),
                size: entry.modBaseSize as u64,
                path: if path.is_empty() { None } else { Some(path) },
            });

            // Get next module
            if unsafe { Module32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }

        // Sort by base address
        modules.sort_by_key(|m| m.base.0);

        Ok(modules)
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = HANDLE::default();
            tracing::info!(pid = self.pid.0, "Detached from process");
        }
        Ok(())
    }
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

/// RAII guard to close a HANDLE
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Convert wide-char buffer to String
fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

/// Convert Windows memory protection flags to our Permissions struct
fn protection_to_permissions(protect: u32) -> Permissions {
    let read = matches!(
        protect,
        x if x == PAGE_READONLY.0
            || x == PAGE_READWRITE.0
            || x == PAGE_WRITECOPY.0
            || x == PAGE_EXECUTE_READ.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
    );

    let write = matches!(
        protect,
        x if x == PAGE_READWRITE.0
            || x == PAGE_WRITECOPY.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
    );

    let execute = matches!(
        protect,
        x if x == PAGE_EXECUTE.0
            || x == PAGE_EXECUTE_READ.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
    );

    Permissions { read, write, execute }
}

/// Check if a process is running under WoW64 (32-bit on 64-bit Windows)
fn is_wow64_process(handle: HANDLE) -> bool {
    let mut is_wow64 = false;
    let _ = unsafe { IsWow64Process(handle, &mut is_wow64) };
    is_wow64.into()
}

/// Get process name and path from handle
fn get_process_name_and_path(handle: HANDLE, pid: u32) -> (String, Option<String>) {
    // Try to get the full image name
    let mut buffer = [0u16; MAX_PATH as usize];
    let mut size = buffer.len() as u32;

    let path = if unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buffer.as_mut_ptr()), &mut size)
    }
    .is_ok()
    {
        let path_str = wchar_to_string(&buffer[..size as usize]);
        Some(path_str)
    } else {
        None
    };

    // Extract name from path
    let name = path
        .as_ref()
        .and_then(|p| Path::new(p).file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("pid_{pid}"));

    (name, path)
}

/// List all processes on the system
pub fn list_processes() -> Result<Vec<ProcessInfo>, PlatformError> {
    let mut processes = Vec::new();

    // Create a snapshot of all processes
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
        PlatformError::SystemError(format!("CreateToolhelp32Snapshot failed: {e}"))
    })?;

    // Ensure snapshot is closed when we're done
    let _guard = HandleGuard(snapshot);

    let mut entry: PROCESSENTRY32W = unsafe { MaybeUninit::zeroed().assume_init() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

    // Get first process
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_err() {
        return Err(PlatformError::SystemError(
            "Process32FirstW failed".into(),
        ));
    }

    loop {
        let pid = entry.th32ProcessID;

        // Skip system processes (PID 0 and 4 are System Idle Process and System)
        if pid > 4 {
            let name = wchar_to_string(&entry.szExeFile);

            // Try to get the full path by briefly opening the process
            let path = get_process_path(pid);

            // Check if we can attach (try to open with minimal rights)
            let attachable = is_process_attachable(pid);

            processes.push(ProcessInfo {
                pid: Pid(pid),
                name,
                path,
                attachable,
            });
        }

        // Get next process
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            break;
        }
    }

    // Sort by name for easier browsing
    processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(processes)
}

/// Get the full path of a process
fn get_process_path(pid: u32) -> Option<String> {
    // Open with minimal rights just to query the name
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }.ok()?;
    let _guard = HandleGuard(handle);

    let mut buffer = [0u16; MAX_PATH as usize];
    let mut size = buffer.len() as u32;

    if unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buffer.as_mut_ptr()), &mut size)
    }
    .is_ok()
    {
        Some(wchar_to_string(&buffer[..size as usize]))
    } else {
        None
    }
}

/// Check if a process is likely attachable
fn is_process_attachable(pid: u32) -> bool {
    // Try to open with the access rights we need
    let access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    match unsafe { OpenProcess(access, false, pid) } {
        Ok(handle) => {
            unsafe {
                let _ = CloseHandle(handle);
            }
            true
        }
        Err(_) => false,
    }
}

// ============================================================================
// Debug Privilege Management
// ============================================================================

/// Enable SeDebugPrivilege for the current process.
///
/// This privilege allows attaching to processes running as other users,
/// including system processes. Requires the process to be running as
/// Administrator to succeed.
///
/// Returns `true` if the privilege was successfully enabled, `false` otherwise.
/// This function is safe to call multiple times; subsequent calls will return
/// the cached result.
pub fn enable_debug_privilege() -> bool {
    // Return cached result if we've already tried
    if DEBUG_PRIVILEGE_ATTEMPTED.load(Ordering::SeqCst) {
        return DEBUG_PRIVILEGE_ENABLED.load(Ordering::SeqCst);
    }

    DEBUG_PRIVILEGE_ATTEMPTED.store(true, Ordering::SeqCst);

    let result = unsafe { try_enable_debug_privilege() };
    DEBUG_PRIVILEGE_ENABLED.store(result, Ordering::SeqCst);

    if result {
        tracing::info!("SeDebugPrivilege enabled successfully");
    } else {
        tracing::debug!("Failed to enable SeDebugPrivilege (not running as Administrator?)");
    }

    result
}

/// Check if debug privilege has been enabled
pub fn is_debug_privilege_enabled() -> bool {
    DEBUG_PRIVILEGE_ENABLED.load(Ordering::SeqCst)
}

/// Internal function to enable SeDebugPrivilege
unsafe fn try_enable_debug_privilege() -> bool {
    // Get the current process token
    let mut token_handle = HANDLE::default();
    let current_process = GetCurrentProcess();

    if OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token_handle).is_err() {
        return false;
    }

    let _token_guard = HandleGuard(token_handle);

    // Look up the LUID for SeDebugPrivilege
    let mut luid = LUID::default();
    if LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).is_err() {
        return false;
    }

    // Set up the privilege structure
    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // Enable the privilege
    let result = AdjustTokenPrivileges(
        token_handle,
        false,
        Some(&mut tp),
        0,
        None,
        None,
    );

    if result.is_err() {
        return false;
    }

    // Check if the privilege was actually enabled
    // AdjustTokenPrivileges succeeds even if no privileges were changed,
    // so we need to check GetLastError for ERROR_NOT_ALL_ASSIGNED
    let last_error = windows::core::Error::from_win32();
    if last_error.code().0 != 0 {
        // ERROR_NOT_ALL_ASSIGNED = 1300
        return false;
    }

    true
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
        let result = WindowsProcess::attach(my_pid);

        match result {
            Ok(proc) => {
                assert_eq!(proc.pid(), my_pid);
                assert!(proc.is_alive());

                // Try to read our own memory
                let test_value: u32 = 0xDEADBEEF;
                let addr = &test_value as *const u32 as u64;
                let mut buffer = [0u8; 4];

                match proc.read_memory(Address(addr), &mut buffer) {
                    Ok(n) => {
                        assert_eq!(n, 4);
                        assert_eq!(u32::from_ne_bytes(buffer), 0xDEADBEEF);
                    }
                    Err(e) => {
                        println!("Read failed: {e:?}");
                    }
                }
            }
            Err(PlatformError::PermissionDenied(_)) => {
                println!("Permission denied (may need to run as Administrator)");
            }
            Err(e) => {
                panic!("Unexpected error: {e:?}");
            }
        }
    }

    #[test]
    fn can_enumerate_own_modules() {
        let my_pid = Pid(std::process::id());

        if let Ok(proc) = WindowsProcess::attach(my_pid) {
            let modules = proc.modules().expect("Should enumerate modules");
            assert!(!modules.is_empty(), "Should find at least one module");

            // The first module should be our executable
            let first = &modules[0];
            assert!(first.base.0 > 0, "Module should have valid base address");
            println!("First module: {} at 0x{:X}", first.name, first.base.0);
        }
    }

    #[test]
    fn can_enumerate_own_regions() {
        let my_pid = Pid(std::process::id());

        if let Ok(proc) = WindowsProcess::attach(my_pid) {
            let regions = proc.regions().expect("Should enumerate regions");
            assert!(!regions.is_empty(), "Should find at least one region");

            // Should have some readable regions
            let readable = regions.iter().filter(|r| r.permissions.read).count();
            assert!(readable > 0, "Should have readable regions");
        }
    }
}
