//! Messpit - Modern Memory Trainer Studio
//!
//! Tauri application with Svelte frontend.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Maximum size for a single memory region read (256 MB)
const MAX_REGION_READ_SIZE: usize = 256 * 1024 * 1024;

/// Minimum valid user-space address (skip null page and low addresses)
const MIN_VALID_ADDRESS: u64 = 0x10000;

/// Maximum length for label strings
const MAX_LABEL_LENGTH: usize = 256;

/// Maximum length for pattern strings
const MAX_PATTERN_INPUT_LENGTH: usize = 1024;

/// Maximum length for script source
const MAX_SCRIPT_LENGTH: usize = 256 * 1024; // 256 KB

/// Maximum length for project name
const MAX_PROJECT_NAME_LENGTH: usize = 128;

/// Maximum length for notes
const MAX_NOTES_LENGTH: usize = 64 * 1024; // 64 KB

/// Maximum number of watch entries
const MAX_WATCH_ENTRIES: usize = 1000;

/// Maximum number of concurrent scripts
const MAX_CONCURRENT_SCRIPTS: usize = 10;

/// Maximum number of script output entries to keep
const MAX_SCRIPT_OUTPUT_ENTRIES: usize = 50;

/// Maximum scan results to store
const MAX_SCAN_RESULTS: usize = 100_000;

// ============================================================================
// User-Friendly Error Messages
// ============================================================================

/// Format a user-friendly error for process operations
fn error_process(action: &str, details: &str) -> String {
    format!("Failed to {}: {}", action, details)
}

/// Format a user-friendly error for validation failures
fn error_validation(field: &str, issue: &str) -> String {
    format!("Invalid {}: {}", field, issue)
}

/// Format a user-friendly error for limit exceeded
fn error_limit(resource: &str, max: usize) -> String {
    format!("{} limit reached (maximum: {})", resource, max)
}

/// Format a user-friendly error for missing requirements
fn error_requires(requirement: &str) -> String {
    format!("This operation requires {}", requirement)
}

/// Helper trait for handling mutex lock errors gracefully
trait MutexExt<T> {
    /// Lock the mutex, recovering from poison errors by taking the data
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;

    /// Lock the mutex, returning an error string if poisoned
    fn lock_checked(&self) -> Result<MutexGuard<'_, T>, String>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("Recovered from poisoned mutex");
            poisoned.into_inner()
        })
    }

    fn lock_checked(&self) -> Result<MutexGuard<'_, T>, String> {
        self.lock().map_err(|_| "Internal error: mutex was poisoned".to_string())
    }
}

/// Helper trait for handling RwLock errors gracefully
trait RwLockExt<T> {
    /// Write lock, recovering from poison errors
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T>;

    /// Read lock with error propagation
    fn read_checked(&self) -> Result<RwLockReadGuard<'_, T>, String>;

    /// Write lock with error propagation
    fn write_checked(&self) -> Result<RwLockWriteGuard<'_, T>, String>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|poisoned| {
            tracing::warn!("Recovered from poisoned RwLock (write)");
            poisoned.into_inner()
        })
    }

    fn read_checked(&self) -> Result<RwLockReadGuard<'_, T>, String> {
        self.read().map_err(|_| "Internal error: RwLock was poisoned".to_string())
    }

    fn write_checked(&self) -> Result<RwLockWriteGuard<'_, T>, String> {
        self.write().map_err(|_| "Internal error: RwLock was poisoned".to_string())
    }
}

use messpit_engine::session::{FreezeEntry, WatchEntry};
use messpit_engine::{decode_at, encode_value, new_shared_session, AuditLog, Pattern, PatternScanner, Project, ProjectSignature, ProjectWatchEntry, ScanEngine, SharedSession};
use messpit_platform::{attach, list_processes, PlatformError, ProcessHandle};
use messpit_protocol::{Address, Architecture, EntryId, Pid, Refinement, RunId, ScanComparison, ScanParams, Value, ValueType};
use messpit_script_host::{CancellationToken, HostRequest, HostResponse, ScriptConfig, ScriptHost, TYPESCRIPT_DEFINITIONS};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::mpsc;

/// Memory operation request from script
#[derive(Debug)]
enum MemoryOp {
    Read {
        address: Address,
        value_type: ValueType,
        response: std::sync::mpsc::Sender<Option<Value>>,
    },
    Write {
        address: Address,
        value: Value,
        response: std::sync::mpsc::Sender<bool>,
    },
}

/// Global application state
struct AppState {
    session: SharedSession,
    attached: Mutex<Option<AttachedProcess>>,
    /// Store last scan results for refinement
    last_scan_results: Mutex<Vec<(Address, Value)>>,
    /// Store scan value type for refinement
    last_scan_type: Mutex<Option<ValueType>>,
    /// Current project
    project: Mutex<Project>,
    /// Current project file path (None if unsaved)
    project_path: Mutex<Option<String>>,
    /// Running scripts (run_id -> cancellation token)
    running_scripts: Mutex<HashMap<String, CancellationToken>>,
    /// Script output buffer (run_id -> output lines)
    script_output: Mutex<HashMap<String, Vec<String>>>,
    /// Tracks if project has unsaved changes
    has_unsaved_changes: std::sync::atomic::AtomicBool,
    /// Audit log for tracking operations
    audit_log: Mutex<AuditLog>,
}

struct AttachedProcess {
    pid: Pid,
    name: String,
    handle: Box<dyn ProcessHandle>,
}

/// Process info returned to frontend
#[derive(Serialize)]
struct ProcessInfo {
    pid: u32,
    name: String,
    path: Option<String>,
    attachable: bool,
}

/// Attach result returned to frontend
#[derive(Serialize)]
struct AttachResult {
    pid: u32,
    name: String,
    arch: String,
}

/// Region info returned to frontend
#[derive(Serialize)]
struct RegionInfo {
    start: String,
    size: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

/// Scan result returned to frontend
#[derive(Serialize)]
struct ScanResult {
    address: String,
    value: String,
}

/// Scan parameters from frontend
#[derive(Deserialize)]
struct ScanRequest {
    value_type: String,
    comparison: String,
    value: String,
}

/// Refinement parameters from frontend
#[derive(Deserialize)]
struct RefineRequest {
    mode: String,
    value: Option<String>,
}

/// Watch entry returned to frontend
#[derive(Serialize)]
struct WatchInfo {
    id: String,
    address: String,
    value_type: String,
    label: String,
    value: Option<String>,
    frozen: bool,
}

/// Add watch request from frontend
#[derive(Deserialize)]
struct AddWatchRequest {
    address: String,
    value_type: String,
    label: String,
}

/// Freeze request from frontend
#[derive(Deserialize)]
struct FreezeRequest {
    entry_id: String,
    value: String,
}

/// List all running processes
#[tauri::command]
fn list_processes_cmd() -> Result<Vec<ProcessInfo>, String> {
    let processes = list_processes().map_err(|e| e.to_string())?;
    Ok(processes
        .into_iter()
        .map(|p| ProcessInfo {
            pid: p.pid.0,
            name: p.name,
            path: p.path,
            attachable: p.attachable,
        })
        .collect())
}

/// Attach to a process
#[tauri::command]
fn attach_process(pid: u32, state: State<'_, AppState>) -> Result<AttachResult, String> {
    let pid = Pid(pid);

    // Get process info first
    let processes = list_processes().map_err(|e| {
        error_process("list processes", &e.to_string())
    })?;
    let process_info = processes
        .iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| error_validation("process", &format!(
            "PID {} not found. The process may have exited.", pid.0
        )))?;

    // Attach via platform API
    let handle = attach(pid).map_err(|e: PlatformError| {
        error_process("attach to process", &e.to_string())
    })?;

    let result = AttachResult {
        pid: pid.0,
        name: process_info.name.clone(),
        arch: "x86_64".into(),
    };

    // Store attached process with handle
    let attached = AttachedProcess {
        pid,
        name: process_info.name.clone(),
        handle,
    };

    let mut guard = state.attached.lock_checked()?;
    *guard = Some(attached);
    drop(guard);

    record_audit(&state, "attach", Some(pid.0), None, Some(&format!("process: {}", result.name)));

    Ok(result)
}

/// Detach from the current process
#[tauri::command]
fn detach_process(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.attached.lock_checked()?;
    let pid = guard.as_ref().map(|a| a.pid.0);
    let name = guard.as_ref().map(|a| a.name.clone());
    if let Some(mut attached) = guard.take() {
        let _ = attached.handle.detach();
    }
    drop(guard);

    // Clear scan results to free memory
    state.last_scan_results.lock_or_recover().clear();
    *state.last_scan_type.lock_or_recover() = None;

    if let Some(pid) = pid {
        record_audit(&state, "detach", Some(pid), None, name.as_deref());
    }

    Ok(())
}

/// Get the current attached process info
#[tauri::command]
fn get_attached(state: State<'_, AppState>) -> Option<AttachResult> {
    let guard = state.attached.lock_or_recover();
    guard.as_ref().map(|p| AttachResult {
        pid: p.pid.0,
        name: p.name.clone(),
        arch: "x86_64".into(),
    })
}

/// Get memory regions of the attached process
#[tauri::command]
fn get_regions(state: State<'_, AppState>) -> Result<Vec<RegionInfo>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let regions = attached.handle.regions().map_err(|e| e.to_string())?;

    Ok(regions
        .into_iter()
        .map(|r| RegionInfo {
            start: format!("0x{:016X}", r.base.0),
            size: r.size,
            readable: r.permissions.read,
            writable: r.permissions.write,
            executable: r.permissions.execute,
        })
        .collect())
}

/// Perform a memory scan
#[tauri::command]
fn start_scan(request: ScanRequest, state: State<'_, AppState>) -> Result<Vec<ScanResult>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    // Parse value type
    let value_type = parse_value_type(&request.value_type)?;

    // Parse comparison and value
    let comparison = match request.comparison.as_str() {
        "exact" => {
            let value = parse_value(&request.value, &value_type)?;
            ScanComparison::Exact { value }
        }
        _ => return Err(format!("Unsupported comparison: {}", request.comparison)),
    };

    let alignment = value_type.size().unwrap_or(4) as u8;
    let params = ScanParams {
        value_type,
        comparison,
        alignment,
        writable_only: true,
        region_filter: vec![],
    };

    // Get writable regions and scan them
    let regions = attached.handle.regions().map_err(|e| e.to_string())?;
    let mut all_raw_results: Vec<(Address, Value)> = Vec::new();

    for region in regions.iter().filter(|r| r.permissions.write && r.permissions.read) {
        // Skip regions that are too large (safety limit)
        let region_size = region.size as usize;
        if region_size > MAX_REGION_READ_SIZE {
            tracing::warn!(
                "Skipping oversized region at 0x{:X} (size: {} bytes)",
                region.base.0,
                region_size
            );
            continue;
        }

        // Read region memory
        let mut buffer = vec![0u8; region_size];
        if attached
            .handle
            .read_memory(region.base, &mut buffer)
            .is_ok()
        {
            let result = ScanEngine::initial_scan(&buffer, region.base, &params);
            all_raw_results.extend(result.addresses);
        }

        // Cap total results to prevent memory exhaustion
        if all_raw_results.len() >= MAX_SCAN_RESULTS {
            tracing::info!("Scan result limit reached ({}), stopping early", MAX_SCAN_RESULTS);
            break;
        }
    }

    // Truncate if over limit
    if all_raw_results.len() > MAX_SCAN_RESULTS {
        all_raw_results.truncate(MAX_SCAN_RESULTS);
    }

    // Store results for refinement
    *state.last_scan_results.lock_or_recover() = all_raw_results.clone();
    *state.last_scan_type.lock_or_recover() = Some(value_type);

    // Convert to frontend format (limit displayed results)
    let results: Vec<ScanResult> = all_raw_results
        .iter()
        .take(1000)
        .map(|(addr, val)| ScanResult {
            address: format!("0x{:016X}", addr.0),
            value: format_val(val),
        })
        .collect();

    Ok(results)
}

/// Get the number of scan results
#[tauri::command]
fn get_scan_count(state: State<'_, AppState>) -> usize {
    state.last_scan_results.lock_or_recover().len()
}

/// Refine the existing scan results
#[tauri::command]
fn refine_scan(request: RefineRequest, state: State<'_, AppState>) -> Result<Vec<ScanResult>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let previous = state.last_scan_results.lock_or_recover().clone();
    let value_type = state.last_scan_type.lock_or_recover()
        .ok_or("No previous scan to refine")?;

    if previous.is_empty() {
        return Err("No previous scan results to refine".into());
    }

    // Parse refinement mode
    let refinement = match request.mode.as_str() {
        "changed" => Refinement::Changed,
        "unchanged" => Refinement::Unchanged,
        "increased" => Refinement::Increased,
        "decreased" => Refinement::Decreased,
        "exact" => {
            let value_str = request.value.ok_or("Value required for exact refinement")?;
            let value = parse_value(&value_str, &value_type)?;
            Refinement::Exact { value }
        }
        _ => return Err(format!("Unsupported refinement mode: {}", request.mode)),
    };

    // Perform refinement
    let refined = ScanEngine::refine_scan(
        &previous,
        |addr, sz| {
            let mut buf = vec![0u8; sz];
            attached.handle.read_memory(addr, &mut buf).ok()?;
            Some(buf)
        },
        &value_type,
        &refinement,
    );

    // Store refined results
    *state.last_scan_results.lock_or_recover() = refined.clone();

    // Convert to frontend format
    let results: Vec<ScanResult> = refined
        .iter()
        .take(1000)
        .map(|(addr, val)| ScanResult {
            address: format!("0x{:016X}", addr.0),
            value: format_val(val),
        })
        .collect();

    Ok(results)
}

/// Clear scan results and start fresh
#[tauri::command]
fn clear_scan(state: State<'_, AppState>) {
    state.last_scan_results.lock_or_recover().clear();
    *state.last_scan_type.lock_or_recover() = None;
}

/// Add an address to the watch list
#[tauri::command]
fn add_watch(request: AddWatchRequest, state: State<'_, AppState>) -> Result<String, String> {
    // Validate label length
    if request.label.len() > MAX_LABEL_LENGTH {
        return Err(error_validation("label", &format!("too long (max {} characters)", MAX_LABEL_LENGTH)));
    }

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;

    let mut session = state.session.write_checked()?;

    // Check watch limit
    if session.watches.len() >= MAX_WATCH_ENTRIES {
        return Err(error_limit("Watch entries", MAX_WATCH_ENTRIES));
    }

    let entry_id = EntryId::new();
    let label = request.label.clone();
    let entry = WatchEntry {
        id: entry_id,
        address,
        value_type,
        label: request.label,
        last_value: None,
    };

    session.add_watch(entry);
    drop(session);
    mark_project_changed(&state);
    record_audit(&state, "add_watch", None, Some(address), Some(&format!("label: {}", label)));

    Ok(entry_id.0.to_string())
}

/// Remove an address from the watch list
#[tauri::command]
fn remove_watch(entry_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = EntryId(entry_id.parse().map_err(|_| "Invalid entry ID")?);
    let mut session = state.session.write_checked()?;
    let address = session.watches.get(&id).map(|w| w.address);
    session.remove_watch(&id);
    drop(session);
    mark_project_changed(&state);
    record_audit(&state, "remove_watch", None, address, Some(&entry_id));
    Ok(())
}

/// Get all watch entries with current values
#[tauri::command]
fn get_watches(state: State<'_, AppState>) -> Result<Vec<WatchInfo>, String> {
    let attached_guard = state.attached.lock_checked()?;
    let session = state.session.read_checked()?;

    let watches: Vec<WatchInfo> = session.watches().map(|w| {
        // Try to read current value
        let current_value = if let Some(attached) = attached_guard.as_ref() {
            let size = w.value_type.size().unwrap_or(8);
            let mut buf = vec![0u8; size];
            if attached.handle.read_memory(w.address, &mut buf).is_ok() {
                decode_at(&buf, &w.value_type)
            } else {
                None
            }
        } else {
            None
        };

        WatchInfo {
            id: w.id.0.to_string(),
            address: format!("0x{:016X}", w.address.0),
            value_type: format_value_type(&w.value_type),
            label: w.label.clone(),
            value: current_value.map(|v| format_val(&v)),
            frozen: session.freezes.contains_key(&w.id),
        }
    }).collect();

    Ok(watches)
}

/// Toggle freeze for a watch entry
#[tauri::command]
fn toggle_freeze(request: FreezeRequest, state: State<'_, AppState>) -> Result<bool, String> {
    let id = EntryId(request.entry_id.parse().map_err(|_| "Invalid entry ID")?);
    let mut session = state.session.write_checked()?;

    let (result, address) = if session.freezes.contains_key(&id) {
        let addr = session.freezes.get(&id).map(|f| f.address);
        session.remove_freeze(&id);
        (false, addr)
    } else {
        // Get watch entry to create freeze
        let watch = session.watches.get(&id)
            .ok_or("Watch entry not found")?;

        let value = parse_value(&request.value, &watch.value_type)?;
        let addr = watch.address;
        let freeze = FreezeEntry::new(
            id,
            watch.address,
            watch.value_type,
            value,
            10, // 10ms interval
        );
        session.set_freeze(id, freeze);
        (true, Some(addr))
    };

    drop(session);
    mark_project_changed(&state);
    record_audit(
        &state,
        if result { "freeze_enabled" } else { "freeze_disabled" },
        None,
        address,
        Some(&format!("value: {}", request.value)),
    );
    Ok(result)
}

/// Write a value directly to memory
#[derive(Deserialize)]
struct WriteValueRequest {
    address: String,
    value_type: String,
    value: String,
}

#[tauri::command]
fn write_value(request: WriteValueRequest, state: State<'_, AppState>) -> Result<(), String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;
    let value = parse_value(&request.value, &value_type)?;
    let bytes = encode_value(&value);
    let pid = attached.pid.0;

    attached.handle.write_memory(address, &bytes)
        .map_err(|e| e.to_string())?;

    drop(guard);
    record_audit(
        &state,
        "write_value",
        Some(pid),
        Some(address),
        Some(&format!("type: {}, value: {}", request.value_type, request.value)),
    );

    Ok(())
}

/// Read a value directly from memory
#[derive(Deserialize)]
struct ReadValueRequest {
    address: String,
    value_type: String,
}

#[tauri::command]
fn read_value(request: ReadValueRequest, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;
    let size = value_type.size().unwrap_or(8);

    let mut buf = vec![0u8; size];
    if attached.handle.read_memory(address, &mut buf).is_ok()
        && let Some(value) = decode_at(&buf, &value_type) {
            return Ok(Some(format_val(&value)));
        }

    Ok(None)
}

fn parse_value_type(s: &str) -> Result<ValueType, String> {
    match s {
        "i32" => Ok(ValueType::I32),
        "i64" => Ok(ValueType::I64),
        "f32" => Ok(ValueType::F32),
        "f64" => Ok(ValueType::F64),
        "u32" => Ok(ValueType::U32),
        "u64" => Ok(ValueType::U64),
        "i8" => Ok(ValueType::I8),
        "i16" => Ok(ValueType::I16),
        "u8" => Ok(ValueType::U8),
        "u16" => Ok(ValueType::U16),
        _ => Err(error_validation("value type", &format!(
            "'{}' is not supported. Use: i8, i16, i32, i64, u8, u16, u32, u64, f32, or f64", s
        ))),
    }
}

fn format_value_type(vt: &ValueType) -> String {
    match vt {
        ValueType::I8 => "i8",
        ValueType::I16 => "i16",
        ValueType::I32 => "i32",
        ValueType::I64 => "i64",
        ValueType::U8 => "u8",
        ValueType::U16 => "u16",
        ValueType::U32 => "u32",
        ValueType::U64 => "u64",
        ValueType::F32 => "f32",
        ValueType::F64 => "f64",
        _ => "unknown",
    }.to_string()
}

fn parse_address(s: &str) -> Result<Address, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");

    if s.is_empty() {
        return Err(error_validation("address", "cannot be empty"));
    }

    let addr = u64::from_str_radix(s, 16)
        .map_err(|_| error_validation("address", "must be a valid hexadecimal number (e.g., 0x12345678)"))?;

    // Validate address range - reject addresses in null page / low memory
    if addr < MIN_VALID_ADDRESS {
        return Err(error_validation("address", &format!(
            "0x{:X} is in protected memory. Use addresses above 0x{:X}",
            addr, MIN_VALID_ADDRESS
        )));
    }

    Ok(Address(addr))
}

fn parse_value(s: &str, value_type: &ValueType) -> Result<Value, String> {
    if s.is_empty() {
        return Err(error_validation("value", "cannot be empty"));
    }

    match value_type {
        ValueType::I32 => s
            .parse::<i32>()
            .map(Value::I32)
            .map_err(|_| error_validation("value", "must be a valid 32-bit signed integer (e.g., 100, -50)")),
        ValueType::I64 => s
            .parse::<i64>()
            .map(Value::I64)
            .map_err(|_| error_validation("value", "must be a valid 64-bit signed integer")),
        ValueType::U32 => s
            .parse::<u32>()
            .map(Value::U32)
            .map_err(|_| error_validation("value", "must be a valid 32-bit unsigned integer (0 to 4294967295)")),
        ValueType::U64 => s
            .parse::<u64>()
            .map(Value::U64)
            .map_err(|_| error_validation("value", "must be a valid 64-bit unsigned integer")),
        ValueType::F32 => s
            .parse::<f32>()
            .map(Value::F32)
            .map_err(|_| error_validation("value", "must be a valid decimal number (e.g., 3.14)")),
        ValueType::F64 => s
            .parse::<f64>()
            .map(Value::F64)
            .map_err(|_| error_validation("value", "must be a valid decimal number")),
        _ => Err(error_validation("value type", "only integer and float types are supported for parsing")),
    }
}

fn format_val(val: &Value) -> String {
    match val {
        Value::I8(v) => format!("{v}"),
        Value::I16(v) => format!("{v}"),
        Value::I32(v) => format!("{v}"),
        Value::I64(v) => format!("{v}"),
        Value::U8(v) => format!("{v}"),
        Value::U16(v) => format!("{v}"),
        Value::U32(v) => format!("{v}"),
        Value::U64(v) => format!("{v}"),
        Value::F32(v) => format!("{v:.4}"),
        Value::F64(v) => format!("{v:.4}"),
        Value::Bytes(b) => format!("{} bytes", b.len()),
        Value::String(s) => s.clone(),
    }
}

// ============================================================================
// Project Management Commands
// ============================================================================

/// Project info returned to frontend
#[derive(Serialize)]
struct ProjectInfo {
    name: String,
    path: Option<String>,
    watch_count: usize,
    has_unsaved_changes: bool,
}

/// Get current project info
#[tauri::command]
fn get_project_info(state: State<'_, AppState>) -> ProjectInfo {
    let project = state.project.lock_or_recover();
    let path = state.project_path.lock_or_recover();
    ProjectInfo {
        name: project.name.clone(),
        path: path.clone(),
        watch_count: project.watch_entries.len(),
        has_unsaved_changes: state.has_unsaved_changes.load(std::sync::atomic::Ordering::SeqCst),
    }
}

/// Mark the project as having unsaved changes
fn mark_project_changed(state: &AppState) {
    state.has_unsaved_changes.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Mark the project as saved (no unsaved changes)
fn mark_project_saved(state: &AppState) {
    state.has_unsaved_changes.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Record an audit log entry
fn record_audit(state: &AppState, operation: &str, pid: Option<u32>, address: Option<Address>, details: Option<&str>) {
    if let Ok(mut log) = state.audit_log.lock() {
        log.record(operation, pid, address, details);
    }
}

/// Audit log entry for frontend
#[derive(Serialize)]
struct AuditEntryInfo {
    timestamp: String,
    operation: String,
    pid: Option<u32>,
    address: Option<String>,
    details: Option<String>,
}

/// Get all audit log entries
#[tauri::command]
fn get_audit_log(state: State<'_, AppState>) -> Vec<AuditEntryInfo> {
    let log = state.audit_log.lock_or_recover();
    log.entries()
        .iter()
        .map(|e| AuditEntryInfo {
            timestamp: e.timestamp.clone(),
            operation: e.operation.clone(),
            pid: e.target_pid,
            address: e.address.map(|a| format!("0x{:X}", a.0)),
            details: e.details.clone(),
        })
        .collect()
}

/// Clear the audit log
#[tauri::command]
fn clear_audit_log(state: State<'_, AppState>) {
    let mut log = state.audit_log.lock_or_recover();
    log.clear();
}

/// Create a new project
#[tauri::command]
fn new_project(name: String, state: State<'_, AppState>) -> Result<ProjectInfo, String> {
    // Validate project name length
    if name.len() > MAX_PROJECT_NAME_LENGTH {
        return Err(format!("Project name too long (max {} characters)", MAX_PROJECT_NAME_LENGTH));
    }

    let mut project = state.project.lock_or_recover();
    let mut path = state.project_path.lock_or_recover();

    *project = Project::new(&name);
    *path = None;

    // Clear session watches to sync
    let mut session = state.session.write_or_recover();
    session.watches.clear();
    session.freezes.clear();

    Ok(ProjectInfo {
        name: project.name.clone(),
        path: None,
        watch_count: 0,
        has_unsaved_changes: false,
    })
}

/// Save project to a file path
#[tauri::command]
fn save_project(file_path: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut project = state.project.lock_checked()?;
    let mut saved_path = state.project_path.lock_checked()?;
    let session = state.session.read_checked()?;
    let attached = state.attached.lock_checked()?;

    // Sync watches from session to project
    project.watch_entries.clear();
    for watch in session.watches() {
        let frozen = session.freezes.contains_key(&watch.id);
        let freeze_value = session.freezes.get(&watch.id).map(|f| f.value.clone());

        project.watch_entries.push(ProjectWatchEntry {
            id: watch.id.0.to_string(),
            label: watch.label.clone(),
            address: watch.address.0,
            value_type: watch.value_type,
            frozen,
            freeze_value,
            signature_id: None,
        });
    }

    // Set target info if attached
    if let Some(ref att) = *attached {
        project.target = Some(messpit_engine::ProjectTarget {
            process_name: att.name.clone(),
            fingerprint: None,
            arch: Architecture::X86_64,
        });
    }

    project.save(&file_path).map_err(|e| e.to_string())?;
    *saved_path = Some(file_path);

    // Release locks before marking saved
    drop(project);
    drop(saved_path);
    drop(session);
    drop(attached);

    mark_project_saved(&state);
    Ok(())
}

/// Load project from a file path
#[tauri::command]
fn load_project(file_path: String, state: State<'_, AppState>) -> Result<ProjectInfo, String> {
    let loaded = Project::load(&file_path).map_err(|e| e.to_string())?;

    let mut project = state.project.lock_checked()?;
    let mut saved_path = state.project_path.lock_checked()?;
    let mut session = state.session.write_checked()?;

    // Clear existing watches
    session.watches.clear();
    session.freezes.clear();

    // Import watches from project
    for entry in &loaded.watch_entries {
        let id = entry.id.parse().unwrap_or_else(|_| uuid::Uuid::new_v4());
        let watch = WatchEntry {
            id: EntryId(id),
            address: Address(entry.address),
            value_type: entry.value_type,
            label: entry.label.clone(),
            last_value: None,
        };
        session.add_watch(watch);

        // Restore freeze if applicable
        if entry.frozen
            && let Some(ref freeze_val) = entry.freeze_value {
                let freeze = FreezeEntry::new(
                    EntryId(id),
                    Address(entry.address),
                    entry.value_type,
                    freeze_val.clone(),
                    10,
                );
                session.set_freeze(EntryId(id), freeze);
            }
    }

    let watch_count = loaded.watch_entries.len();
    let name = loaded.name.clone();

    *project = loaded;
    *saved_path = Some(file_path.clone());

    // Release locks before marking saved
    drop(project);
    drop(saved_path);
    drop(session);

    mark_project_saved(&state);

    Ok(ProjectInfo {
        name,
        path: Some(file_path),
        watch_count,
        has_unsaved_changes: false,
    })
}

/// Export project as JSON (for sharing)
#[tauri::command]
fn export_project(file_path: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut project = state.project.lock_checked()?;
    let session = state.session.read_checked()?;
    let attached = state.attached.lock_checked()?;

    // Sync watches from session
    project.watch_entries.clear();
    for watch in session.watches() {
        let frozen = session.freezes.contains_key(&watch.id);
        let freeze_value = session.freezes.get(&watch.id).map(|f| f.value.clone());

        project.watch_entries.push(ProjectWatchEntry {
            id: watch.id.0.to_string(),
            label: watch.label.clone(),
            address: watch.address.0,
            value_type: watch.value_type,
            frozen,
            freeze_value,
            signature_id: None,
        });
    }

    if let Some(ref att) = *attached {
        project.target = Some(messpit_engine::ProjectTarget {
            process_name: att.name.clone(),
            fingerprint: None,
            arch: Architecture::X86_64,
        });
    }

    // Export with pretty formatting
    let json = serde_json::to_string_pretty(&*project)
        .map_err(|e| format!("Serialization error: {}", e))?;

    std::fs::write(&file_path, json)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

/// Import project from JSON
#[tauri::command]
fn import_project(file_path: String, state: State<'_, AppState>) -> Result<ProjectInfo, String> {
    // Just delegate to load_project since format is the same
    load_project(file_path, state)
}

/// Update project name
#[tauri::command]
fn set_project_name(name: String, state: State<'_, AppState>) -> Result<(), String> {
    // Validate name length
    if name.len() > MAX_PROJECT_NAME_LENGTH {
        return Err(format!("Project name too long (max {} characters)", MAX_PROJECT_NAME_LENGTH));
    }

    let mut project = state.project.lock_or_recover();
    project.name = name;
    Ok(())
}

/// Get project notes
#[tauri::command]
fn get_project_notes(state: State<'_, AppState>) -> String {
    let project = state.project.lock_or_recover();
    project.notes.clone()
}

/// Set project notes
#[tauri::command]
fn set_project_notes(notes: String, state: State<'_, AppState>) -> Result<(), String> {
    // Validate notes length
    if notes.len() > MAX_NOTES_LENGTH {
        return Err(format!("Notes too long (max {} bytes)", MAX_NOTES_LENGTH));
    }

    let mut project = state.project.lock_or_recover();
    project.notes = notes;
    Ok(())
}

// ============================================================================
// Script Commands
// ============================================================================

/// Script run result
#[derive(Serialize)]
struct ScriptRunResult {
    run_id: String,
}

/// Script output returned to frontend
#[derive(Serialize)]
struct ScriptOutputResult {
    lines: Vec<String>,
    finished: bool,
    error: Option<String>,
}

/// Run a script
#[tauri::command]
async fn run_script(source: String, state: State<'_, AppState>) -> Result<ScriptRunResult, String> {
    // Validate script length
    if source.len() > MAX_SCRIPT_LENGTH {
        return Err(error_validation("script", &format!("too long (max {} bytes)", MAX_SCRIPT_LENGTH)));
    }

    // Check concurrent script limit
    {
        let scripts = state.running_scripts.lock_or_recover();
        if scripts.len() >= MAX_CONCURRENT_SCRIPTS {
            return Err(error_limit("Concurrent scripts", MAX_CONCURRENT_SCRIPTS));
        }
    }

    let run_id = RunId::new();
    let run_id_str = run_id.0.to_string();

    // Create script host with config
    let config = ScriptConfig::default();
    let host = ScriptHost::new(config);

    // Store cancellation token
    let token = host.cancellation_token();
    state.running_scripts.lock_or_recover().insert(run_id_str.clone(), token);

    // Cleanup old script output entries if too many
    {
        let mut output = state.script_output.lock_or_recover();
        if output.len() >= MAX_SCRIPT_OUTPUT_ENTRIES {
            // Remove oldest entries (keep the most recent ones)
            let to_remove: Vec<String> = output.keys()
                .take(output.len() - MAX_SCRIPT_OUTPUT_ENTRIES + 1)
                .cloned()
                .collect();
            for key in to_remove {
                output.remove(&key);
            }
        }
        output.insert(run_id_str.clone(), Vec::new());
    }

    // Create event channel (unused in sync execution for now)
    let (tx, _rx) = mpsc::channel(100);

    // Create channel for memory operations
    let (mem_tx, mut mem_rx) = tokio::sync::mpsc::channel::<MemoryOp>(32);

    // Clone references needed by handler
    let session_clone = state.session.clone();
    let handler = {
        // Capture what we need for the closure
        let output_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let output_for_handler = output_lines.clone();
        let mem_tx = mem_tx.clone();

        move |request: HostRequest| -> HostResponse {
            match request {
                HostRequest::Print { message } => {
                    output_for_handler.lock_or_recover().push(message.clone());
                    tracing::info!("Script: {}", message);
                    HostResponse::Ok
                }
                HostRequest::Notify { message } => {
                    tracing::info!("Script notification: {}", message);
                    HostResponse::Ok
                }
                HostRequest::Sleep { duration_ms } => {
                    std::thread::sleep(std::time::Duration::from_millis(duration_ms.min(10000)));
                    HostResponse::Ok
                }
                HostRequest::AddWatch { address, value_type, label } => {
                    let entry_id = EntryId::new();
                    let entry = WatchEntry {
                        id: entry_id,
                        address,
                        value_type,
                        label,
                        last_value: None,
                    };
                    let mut session = session_clone.write_or_recover();
                    session.add_watch(entry);
                    tracing::info!("Script added watch at {:?}", address);
                    HostResponse::Ok
                }
                HostRequest::SetFreeze { address, value, interval_ms } => {
                    // Find watch entry by address and set freeze
                    let mut session = session_clone.write_or_recover();
                    let watch_id = session.watches.iter()
                        .find(|(_, w)| w.address == address)
                        .map(|(id, _)| *id);

                    if let Some(id) = watch_id {
                        if let Some(watch) = session.watches.get(&id) {
                            let freeze = FreezeEntry::new(
                                id,
                                address,
                                watch.value_type,
                                value,
                                interval_ms,
                            );
                            session.set_freeze(id, freeze);
                            tracing::info!("Script set freeze at {:?}", address);
                            HostResponse::Ok
                        } else {
                            HostResponse::Error("Watch entry not found".into())
                        }
                    } else {
                        HostResponse::Error("No watch entry at this address".into())
                    }
                }
                HostRequest::ClearFreeze { address } => {
                    let mut session = session_clone.write_or_recover();
                    let watch_id = session.watches.iter()
                        .find(|(_, w)| w.address == address)
                        .map(|(id, _)| *id);

                    if let Some(id) = watch_id {
                        session.remove_freeze(&id);
                        tracing::info!("Script cleared freeze at {:?}", address);
                        HostResponse::Ok
                    } else {
                        HostResponse::Error("No watch entry at this address".into())
                    }
                }
                HostRequest::ReadMemory { address, value_type } => {
                    // Send request through channel and wait for response
                    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                    if mem_tx.blocking_send(MemoryOp::Read {
                        address,
                        value_type,
                        response: resp_tx,
                    }).is_ok() {
                        match resp_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                            Ok(value) => HostResponse::Value(value),
                            Err(_) => {
                                tracing::warn!("Memory read timeout for {:?}", address);
                                HostResponse::Value(None)
                            }
                        }
                    } else {
                        HostResponse::Value(None)
                    }
                }
                HostRequest::WriteMemory { address, value } => {
                    // Send request through channel and wait for response
                    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                    if mem_tx.blocking_send(MemoryOp::Write {
                        address,
                        value,
                        response: resp_tx,
                    }).is_ok() {
                        match resp_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                            Ok(true) => HostResponse::Ok,
                            Ok(false) => HostResponse::Error("Write failed".into()),
                            Err(_) => HostResponse::Error("Memory write timeout".into()),
                        }
                    } else {
                        HostResponse::Error("No process attached".into())
                    }
                }
            }
        }
    };

    // Spawn the script execution
    let script_future = host.execute(run_id, &source, handler, tx);

    // Handle memory operations while script runs
    let result = tokio::select! {
        result = script_future => result,
        _ = async {
            while let Some(op) = mem_rx.recv().await {
                let attached = state.attached.lock_or_recover();
                match op {
                    MemoryOp::Read { address, value_type, response } => {
                        let value = if let Some(ref proc) = *attached {
                            // Read bytes from memory
                            let size = value_type.size().unwrap_or(8);
                            let mut buf = vec![0u8; size];
                            if proc.handle.read_memory(address, &mut buf).is_ok() {
                                decode_at(&buf, &value_type)
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        let _ = response.send(value);
                    }
                    MemoryOp::Write { address, value, response } => {
                        let success = if let Some(ref proc) = *attached {
                            let bytes = encode_value(&value);
                            proc.handle.write_memory(address, &bytes).is_ok()
                        } else {
                            false
                        };
                        let _ = response.send(success);
                    }
                }
            }
        } => unreachable!(),
    };

    // Remove from running scripts
    state.running_scripts.lock_or_recover().remove(&run_id_str);

    match result {
        Ok(script_result) => {
            // Store output
            let mut output = state.script_output.lock_or_recover();
            if let Some(lines) = output.get_mut(&run_id_str) {
                if !script_result.output.is_empty() {
                    lines.push(script_result.output);
                }
                if let Some(ret) = script_result.return_value {
                    lines.push(format!("=> {}", ret));
                }
            }
            Ok(ScriptRunResult { run_id: run_id_str })
        }
        Err(e) => {
            let mut output = state.script_output.lock_or_recover();
            if let Some(lines) = output.get_mut(&run_id_str) {
                lines.push(format!("Error: {}", e));
            }
            Ok(ScriptRunResult { run_id: run_id_str })
        }
    }
}

/// Cancel a running script
#[tauri::command]
fn cancel_script(run_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let scripts = state.running_scripts.lock_checked()?;
    if let Some(token) = scripts.get(&run_id) {
        token.cancel();
        Ok(())
    } else {
        Err("Script not found or already finished".into())
    }
}

/// Get script output
#[tauri::command]
fn get_script_output(run_id: String, state: State<'_, AppState>) -> ScriptOutputResult {
    let output = state.script_output.lock_or_recover();
    let running = state.running_scripts.lock_or_recover();

    let lines = output.get(&run_id).cloned().unwrap_or_default();
    let finished = !running.contains_key(&run_id);

    ScriptOutputResult {
        lines,
        finished,
        error: None,
    }
}

/// Clear script output buffer
#[tauri::command]
fn clear_script_output(run_id: String, state: State<'_, AppState>) {
    let mut output = state.script_output.lock_or_recover();
    output.remove(&run_id);
}

/// Get TypeScript definitions for the host API
#[tauri::command]
fn get_script_api_types() -> String {
    TYPESCRIPT_DEFINITIONS.to_string()
}

// ============================================================================
// Script Management Commands
// ============================================================================

/// Script info for frontend
#[derive(Serialize, Clone)]
struct ScriptInfo {
    id: String,
    name: String,
    source: String,
    enabled: bool,
}

/// Save a script to the project
#[tauri::command]
fn save_script(id: String, name: String, source: String, state: State<'_, AppState>) -> Result<(), String> {
    // Validate input lengths
    if name.len() > MAX_LABEL_LENGTH {
        return Err(format!("Script name too long (max {} characters)", MAX_LABEL_LENGTH));
    }
    if source.len() > 100_000 {
        return Err("Script source too long (max 100KB)".to_string());
    }

    let mut project = state.project.lock_checked()?;

    let script = messpit_engine::ProjectScript {
        id,
        name,
        source,
        enabled: false,
    };

    project.add_script(script);

    drop(project);
    mark_project_changed(&state);

    Ok(())
}

/// Delete a script from the project
#[tauri::command]
fn delete_script(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut project = state.project.lock_checked()?;

    let before_len = project.scripts.len();
    project.scripts.retain(|s| s.id != id);

    if project.scripts.len() == before_len {
        return Err("Script not found".to_string());
    }

    drop(project);
    mark_project_changed(&state);

    Ok(())
}

/// Get all scripts from the project
#[tauri::command]
fn get_scripts(state: State<'_, AppState>) -> Result<Vec<ScriptInfo>, String> {
    let project = state.project.lock_checked()?;

    let scripts = project.scripts.iter().map(|s| ScriptInfo {
        id: s.id.clone(),
        name: s.name.clone(),
        source: s.source.clone(),
        enabled: s.enabled,
    }).collect();

    Ok(scripts)
}

/// Get a single script by ID
#[tauri::command]
fn get_script(id: String, state: State<'_, AppState>) -> Result<ScriptInfo, String> {
    let project = state.project.lock_checked()?;

    project.scripts.iter()
        .find(|s| s.id == id)
        .map(|s| ScriptInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            source: s.source.clone(),
            enabled: s.enabled,
        })
        .ok_or_else(|| "Script not found".to_string())
}

/// Update script enabled state
#[tauri::command]
fn set_script_enabled(id: String, enabled: bool, state: State<'_, AppState>) -> Result<(), String> {
    let mut project = state.project.lock_checked()?;

    if let Some(script) = project.scripts.iter_mut().find(|s| s.id == id) {
        script.enabled = enabled;
        drop(project);
        mark_project_changed(&state);
        Ok(())
    } else {
        Err("Script not found".to_string())
    }
}

// ============================================================================
// Pattern Scanning Commands
// ============================================================================

/// Pattern scan request from frontend
#[derive(Deserialize)]
struct PatternScanRequest {
    /// IDA-style pattern (e.g., "48 8B ?? 00")
    pattern: String,
    /// Optional module name to scope the search
    module: Option<String>,
    /// Whether to use SIMD acceleration
    use_simd: bool,
}

/// Pattern scan result for frontend
#[derive(Serialize)]
struct PatternScanResult {
    address: String,
    module: Option<String>,
    module_offset: Option<String>,
}

/// Signature info for frontend
#[derive(Serialize)]
struct SignatureInfo {
    id: String,
    label: String,
    pattern: String,
    module: String,
    offset: i64,
    value_type: String,
    resolved_address: Option<String>,
}

/// Perform a pattern scan
#[tauri::command]
fn pattern_scan(request: PatternScanRequest, state: State<'_, AppState>) -> Result<Vec<PatternScanResult>, String> {
    // Validate pattern length
    if request.pattern.len() > MAX_PATTERN_INPUT_LENGTH {
        return Err(format!("Pattern string too long (max {} characters)", MAX_PATTERN_INPUT_LENGTH));
    }

    // Validate module name if provided
    if let Some(ref module) = request.module
        && module.len() > MAX_LABEL_LENGTH {
            return Err(format!("Module name too long (max {} characters)", MAX_LABEL_LENGTH));
        }

    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    // Parse the pattern
    let pattern = Pattern::parse(&request.pattern)
        .map_err(|e| format!("Invalid pattern: {}", e))?;

    // Get regions and modules
    let regions = attached.handle.regions().map_err(|e| e.to_string())?;
    let modules = attached.handle.modules().unwrap_or_default();

    // Filter regions if module specified
    let scan_regions: Vec<_> = if let Some(ref module_name) = request.module {
        let module_lower = module_name.to_lowercase();
        regions.into_iter()
            .filter(|r| {
                r.module.as_ref()
                    .is_some_and(|m| m.to_lowercase().contains(&module_lower))
            })
            .collect()
    } else {
        // Scan only executable regions by default for signature scanning
        regions.into_iter()
            .filter(|r| r.permissions.read && r.permissions.execute)
            .collect()
    };

    // Perform the scan
    let scanner = PatternScanner::new(pattern);
    let results = scanner.scan_regions(
        attached.handle.as_ref(),
        &scan_regions,
        &modules,
        request.use_simd,
    );

    // Convert to frontend format (limit to 1000 results)
    let result_list: Vec<PatternScanResult> = results
        .into_iter()
        .take(1000)
        .map(|r| PatternScanResult {
            address: format!("0x{:016X}", r.address.0),
            module: r.module,
            module_offset: r.module_offset.map(|o| format!("0x{:X}", o)),
        })
        .collect();

    Ok(result_list)
}

/// Add a signature to the project
#[derive(Deserialize)]
struct AddSignatureRequest {
    label: String,
    pattern: String,
    module: String,
    offset: i64,
    value_type: String,
}

#[tauri::command]
fn add_signature(request: AddSignatureRequest, state: State<'_, AppState>) -> Result<String, String> {
    // Validate label length
    if request.label.len() > MAX_LABEL_LENGTH {
        return Err(format!("Label too long (max {} characters)", MAX_LABEL_LENGTH));
    }

    // Validate pattern length
    if request.pattern.len() > MAX_PATTERN_INPUT_LENGTH {
        return Err(format!("Pattern too long (max {} characters)", MAX_PATTERN_INPUT_LENGTH));
    }

    // Validate module name length
    if request.module.len() > MAX_LABEL_LENGTH {
        return Err(format!("Module name too long (max {} characters)", MAX_LABEL_LENGTH));
    }

    let value_type = parse_value_type(&request.value_type)?;

    // Validate pattern syntax
    Pattern::parse(&request.pattern)
        .map_err(|e| format!("Invalid pattern: {}", e))?;

    let sig = ProjectSignature {
        id: uuid::Uuid::new_v4().to_string(),
        label: request.label,
        pattern: request.pattern,
        module: request.module,
        offset: request.offset,
        value_type,
    };

    let sig_id = sig.id.clone();
    let mut project = state.project.lock_checked()?;
    project.add_signature(sig);

    Ok(sig_id)
}

/// Remove a signature from the project
#[tauri::command]
fn remove_signature(sig_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut project = state.project.lock_checked()?;
    project.remove_signature(&sig_id);
    Ok(())
}

/// Get all signatures from the project
#[tauri::command]
fn get_signatures(state: State<'_, AppState>) -> Result<Vec<SignatureInfo>, String> {
    let project = state.project.lock_checked()?;
    let attached = state.attached.lock_checked()?;

    let sigs: Vec<SignatureInfo> = project.signatures.iter().map(|sig| {
        // Try to resolve the signature if attached
        let resolved_address = if let Some(ref proc) = *attached {
            resolve_signature_internal(proc, sig).map(|a| format!("0x{:016X}", a.0))
        } else {
            None
        };

        SignatureInfo {
            id: sig.id.clone(),
            label: sig.label.clone(),
            pattern: sig.pattern.clone(),
            module: sig.module.clone(),
            offset: sig.offset,
            value_type: format_value_type(&sig.value_type),
            resolved_address,
        }
    }).collect();

    Ok(sigs)
}

/// Resolve a signature to a runtime address
#[tauri::command]
fn resolve_signature(sig_id: String, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let project = state.project.lock_checked()?;
    let attached = state.attached.lock_checked()?;

    let sig = project.get_signature(&sig_id)
        .ok_or("Signature not found")?;

    let attached_proc = attached.as_ref()
        .ok_or("No process attached")?;

    let address = resolve_signature_internal(attached_proc, sig);

    Ok(address.map(|a| format!("0x{:016X}", a.0)))
}

/// Internal helper to resolve a signature
fn resolve_signature_internal(proc: &AttachedProcess, sig: &ProjectSignature) -> Option<Address> {
    // Parse pattern
    let pattern = Pattern::parse(&sig.pattern).ok()?;

    // Get regions and modules
    let regions = proc.handle.regions().ok()?;
    let modules = proc.handle.modules().unwrap_or_default();

    // Filter to target module
    let module_lower = sig.module.to_lowercase();
    let scan_regions: Vec<_> = regions.into_iter()
        .filter(|r| {
            r.module.as_ref()
                .is_some_and(|m| m.to_lowercase().contains(&module_lower))
        })
        .collect();

    // Scan
    let scanner = PatternScanner::new(pattern);
    let results = scanner.scan_regions(
        proc.handle.as_ref(),
        &scan_regions,
        &modules,
        true, // use SIMD
    );

    // Return first match with offset applied
    results.first().map(|r| {
        Address((r.address.0 as i64 + sig.offset) as u64)
    })
}

/// Create a watch entry from a resolved signature
#[tauri::command]
fn watch_from_signature(sig_id: String, state: State<'_, AppState>) -> Result<String, String> {
    let project = state.project.lock_checked()?;
    let attached = state.attached.lock_checked()?;

    let sig = project.get_signature(&sig_id)
        .ok_or("Signature not found")?
        .clone();

    let attached_proc = attached.as_ref()
        .ok_or("No process attached")?;

    let address = resolve_signature_internal(attached_proc, &sig)
        .ok_or("Failed to resolve signature")?;

    // Create watch entry
    let entry_id = EntryId::new();
    let entry = WatchEntry {
        id: entry_id,
        address,
        value_type: sig.value_type,
        label: sig.label.clone(),
        last_value: None,
    };

    drop(project);
    drop(attached);

    let mut session = state.session.write_checked()?;
    session.add_watch(entry);

    // Also update the project watch entry with signature reference
    drop(session);
    let mut project = state.project.lock_checked()?;
    project.add_watch(ProjectWatchEntry {
        id: entry_id.0.to_string(),
        label: sig.label,
        address: address.0,
        value_type: sig.value_type,
        frozen: false,
        freeze_value: None,
        signature_id: Some(sig_id),
    });

    Ok(entry_id.0.to_string())
}

/// Perform cleanup on application exit
fn cleanup_on_exit(state: &AppState) {
    tracing::info!("Performing cleanup on exit...");

    // Cancel all running scripts
    {
        let scripts = state.running_scripts.lock_or_recover();
        for (id, token) in scripts.iter() {
            tracing::info!(script_id = %id, "Cancelling running script");
            token.cancel();
        }
    }

    // Detach from any attached process
    {
        let mut attached = state.attached.lock_or_recover();
        if let Some(mut proc) = attached.take() {
            tracing::info!(pid = proc.pid.0, "Detaching from process on exit");
            let _ = proc.handle.detach();
        }
    }

    // Clear freeze state
    {
        let mut session = state.session.write_or_recover();
        session.set_freeze_enabled(false);
        session.freezes.clear();
    }

    tracing::info!("Cleanup complete");
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("messpit=info".parse().unwrap()),
        )
        .init();

    let session = new_shared_session();

    // Set up audit log with file persistence
    let audit_log = {
        // Use system log directory or fall back to current directory
        let log_path = dirs::data_local_dir()
            .map(|p| p.join("messpit").join("audit.log"))
            .unwrap_or_else(|| std::path::PathBuf::from("messpit_audit.log"));

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        tracing::info!("Audit log file: {}", log_path.display());
        AuditLog::with_file(1000, log_path)
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState {
            session,
            attached: Mutex::new(None),
            last_scan_results: Mutex::new(Vec::new()),
            last_scan_type: Mutex::new(None),
            project: Mutex::new(Project::new("Untitled")),
            project_path: Mutex::new(None),
            running_scripts: Mutex::new(HashMap::new()),
            script_output: Mutex::new(HashMap::new()),
            has_unsaved_changes: std::sync::atomic::AtomicBool::new(false),
            audit_log: Mutex::new(audit_log),
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event
                && let Some(state) = window.try_state::<AppState>() {
                    cleanup_on_exit(&state);
                }
        })
        .invoke_handler(tauri::generate_handler![
            list_processes_cmd,
            attach_process,
            detach_process,
            get_attached,
            get_regions,
            start_scan,
            get_scan_count,
            refine_scan,
            clear_scan,
            add_watch,
            remove_watch,
            get_watches,
            toggle_freeze,
            write_value,
            read_value,
            // Project commands
            get_project_info,
            new_project,
            save_project,
            load_project,
            export_project,
            import_project,
            set_project_name,
            get_project_notes,
            set_project_notes,
            // Script commands
            run_script,
            cancel_script,
            get_script_output,
            clear_script_output,
            get_script_api_types,
            // Script management commands
            save_script,
            delete_script,
            get_scripts,
            get_script,
            set_script_enabled,
            // Pattern scanning commands
            pattern_scan,
            add_signature,
            remove_signature,
            get_signatures,
            resolve_signature,
            watch_from_signature,
            // Audit log commands
            get_audit_log,
            clear_audit_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
