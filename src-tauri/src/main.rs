//! Messpit - Modern Memory Trainer Studio
//!
//! Tauri application with Svelte frontend.
//!
//! ## Module Structure
//! - `helpers` - Constants, error formatting, and value parsing utilities
//! - `state` - Application state and lock extension traits
//! - `types` - Request/response types for frontend communication

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod helpers;
mod state;
mod types;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

// Re-export from helpers module
use helpers::{
    error_limit, error_process, error_requires, error_validation,
    parse_address, parse_value, parse_value_type, format_value_type,
    MAX_CONCURRENT_SCRIPTS, MAX_LABEL_LENGTH, MAX_NOTES_LENGTH, MAX_PATTERN_INPUT_LENGTH,
    MAX_PROJECT_NAME_LENGTH, MAX_REGION_READ_SIZE, MAX_SCAN_RESULTS, MAX_SCRIPT_LENGTH,
    MAX_SCRIPT_OUTPUT_ENTRIES, MAX_WATCH_ENTRIES, MIN_VALID_ADDRESS,
};

// Re-export lock traits from state module
use state::{MutexExt, RwLockExt};

// Re-export types from types module
use types::{
    AddSignatureRequest, AddWatchRequest, CheatTableEntryInfo, CheatTableInfo,
    ExportCheatTableRequest, FreezeRequest, ImportCheatTableRequest, PatternScanRequest,
    PatternScanResult, PointerScanRequest, PointerScanResultItem, ProcessInfo,
    ProcessListRequest, ProcessListResponse, AttachResult, RefineRequest, RegionInfo,
    ResolveChainRequest, ScanRequest, ScanResult, ScriptInfo, ScriptOutputResult,
    ScriptRunResult, SignatureInfo, WatchInfo, WriteValueRequest, ReadValueRequest,
    ProjectInfo,
};

use messpit_engine::session::{FreezeEntry, WatchEntry};
use messpit_engine::{decode_at, encode_value, new_shared_session, Pattern, PatternScanner, Project, ProjectSignature, ProjectWatchEntry, ScanEngine, SharedSession};
use messpit_platform::{attach, list_processes, list_processes_with_options, PlatformError, ProcessHandle};
use messpit_protocol::{Address, Architecture, EntryId, Pid, Refinement, RunId, ScanComparison, ScanParams, Value, ValueType};
use messpit_script_host::{CancellationToken, HostRequest, HostResponse, ScriptConfig, ScriptHost, TYPESCRIPT_DEFINITIONS};
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
}

struct AttachedProcess {
    pid: Pid,
    name: String,
    handle: Box<dyn ProcessHandle>,
}

// Types are imported from the types module

/// List all running processes - ORIGINAL SIMPLE VERSION
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

/// List processes with server-side filtering and ordering
#[tauri::command(async)]
fn list_processes_filtered(_request: ProcessListRequest) -> Result<ProcessListResponse, String> {
    // DEBUG: Return empty immediately to test if the issue is in list_processes_with_options
    return Ok(ProcessListResponse {
        processes: vec![],
        total: 0,
    });

    #[allow(unreachable_code)]
    let processes = list_processes_with_options(
        _request.show_only_attachable,
        _request.include_paths,
    )
        .map_err(|e| e.to_string())?;
    let filter = _request.filter.unwrap_or_default();
    let filter_lower = filter.to_lowercase();
    let pinned: HashSet<u32> = _request.pinned_pids.into_iter().collect();
    let limit = _request.limit.unwrap_or(usize::MAX);

    let mut pinned_list = Vec::new();
    let mut other_list = Vec::new();

    for proc in processes {
        if _request.show_only_attachable && !proc.attachable {
            continue;
        }

        if !filter.is_empty() {
            let matches_text = proc.name.to_lowercase().contains(&filter_lower)
                || proc.pid.0.to_string().contains(&filter);
            if !matches_text {
                continue;
            }
        }

        let info = ProcessInfo {
            pid: proc.pid.0,
            name: proc.name,
            path: proc.path,
            attachable: proc.attachable,
        };

        if pinned.contains(&info.pid) {
            pinned_list.push(info);
        } else {
            other_list.push(info);
        }
    }

    let total = pinned_list.len() + other_list.len();
    let mut combined = pinned_list;
    combined.extend(other_list);
    if combined.len() > limit {
        combined.truncate(limit);
    }

    Ok(ProcessListResponse {
        processes: combined,
        total,
    })
}

/// Attach to a process
#[tauri::command]
async fn attach_process(pid: u32, state: State<'_, AppState>) -> Result<AttachResult, String> {
    let pid_val = Pid(pid);

    // Clear previous session state (watches, freezes, scan results)
    // These are quick mutex operations, don't need spawn_blocking
    {
        let mut session = state.session.write_or_recover();
        session.watches.clear();
        session.freezes.clear();
    }
    *state.last_scan_results.lock_or_recover() = Vec::new();
    *state.last_scan_type.lock_or_recover() = None;

    // Attach via platform API - this is the blocking I/O operation
    let handle = tauri::async_runtime::spawn_blocking(move || {
        attach(pid_val).map_err(|e: PlatformError| {
            error_process("attach to process", &e.to_string())
        })
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    // Get process name from the handle (already fetched during attach)
    let name = handle.fingerprint().process_name;

    let result = AttachResult {
        pid: pid_val.0,
        name: name.clone(),
        arch: "x86_64".into(),
    };

    // Store attached process with handle
    let attached = AttachedProcess {
        pid: pid_val,
        name,
        handle,
    };

    let mut guard = state.attached.lock_checked()?;
    *guard = Some(attached);
    drop(guard);

    Ok(result)
}

/// Detach from the current process
#[tauri::command]
fn detach_process(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.attached.lock_checked()?;
    let _pid = guard.as_ref().map(|a| a.pid.0);
    let _name = guard.as_ref().map(|a| a.name.clone());
    if let Some(mut attached) = guard.take() {
        let _ = attached.handle.detach();
    }
    drop(guard);

    // Clear scan results to free memory
    state.last_scan_results.lock_or_recover().clear();
    *state.last_scan_type.lock_or_recover() = None;

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

/// Paginated region response
#[derive(serde::Serialize)]
struct RegionsResponse {
    regions: Vec<RegionInfo>,
    total: usize,
    page: usize,
    per_page: usize,
}

/// Get memory regions of the attached process (paginated)
#[tauri::command]
async fn get_regions(
    page: Option<usize>,
    per_page: Option<usize>,
    state: State<'_, AppState>,
) -> Result<RegionsResponse, String> {
    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    let per_page_val = per_page.unwrap_or(500);
    let page_val = page.unwrap_or(0);

    // Read /proc/pid/maps in a blocking task
    let result = tauri::async_runtime::spawn_blocking(move || {
        // Read and parse /proc/pid/maps
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid))
            .map_err(|e| format!("Failed to read maps: {}", e))?;

        let mut regions = Vec::new();
        for line in maps_content.lines() {
            if let Some(region) = parse_maps_line(line) {
                regions.push(region);
            }
        }

        let total = regions.len();
        let skip = page_val * per_page_val;

        let page_regions: Vec<RegionInfo> = regions
            .into_iter()
            .skip(skip)
            .take(per_page_val)
            .collect();

        Ok::<_, String>(RegionsResponse {
            regions: page_regions,
            total,
            page: page_val,
            per_page: per_page_val,
        })
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    Ok(result)
}

/// Parse a single line from /proc/pid/maps into a RegionInfo
fn parse_maps_line(line: &str) -> Option<RegionInfo> {
    let mut parts = line.split_whitespace();

    // Address range: "start-end"
    let addr_range = parts.next()?;
    let mut addr_parts = addr_range.split('-');
    let start = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(addr_parts.next()?, 16).ok()?;

    // Permissions: "rwxp" or similar
    let perms = parts.next()?;
    let readable = perms.contains('r');
    let writable = perms.contains('w');
    let executable = perms.contains('x');

    // Skip offset, dev, inode
    parts.next(); // offset
    parts.next(); // dev
    parts.next(); // inode

    // Module path (optional, rest of line)
    let module = parts.next().map(|s| s.to_string());

    Some(RegionInfo {
        start: format!("0x{:016X}", start),
        end: format!("0x{:016X}", end),
        size: end - start,
        readable,
        writable,
        executable,
        module,
    })
}

/// Perform a memory scan
#[tauri::command]
async fn start_scan(request: ScanRequest, state: State<'_, AppState>) -> Result<Vec<ScanResult>, String> {
    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    // Parse value type and comparison (quick operations)
    let value_type = parse_value_type(&request.value_type)?;
    let comparison = match request.comparison.as_str() {
        "exact" => {
            let value = parse_value(&request.value, &value_type)?;
            ScanComparison::Exact { value }
        }
        _ => return Err(format!("Unsupported comparison: {}", request.comparison)),
    };

    let alignment = value_type.size().unwrap_or(4) as u8;
    let params = ScanParams {
        value_type: value_type.clone(),
        comparison,
        alignment,
        writable_only: true,
        region_filter: vec![],
    };

    // Run the heavy scan operation in a blocking task
    let all_raw_results = tauri::async_runtime::spawn_blocking(move || {
        // Read /proc/pid/maps to get regions
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid))
            .map_err(|e| format!("Failed to read maps: {}", e))?;

        // Parse regions
        let mut regions: Vec<(u64, usize, bool, bool)> = Vec::new(); // (start, size, readable, writable)
        for line in maps_content.lines() {
            if let Some((start, end, readable, writable)) = parse_maps_line_for_scan(line) {
                if readable && writable {
                    regions.push((start, (end - start) as usize, readable, writable));
                }
            }
        }

        // Open memory file for reading
        let mut mem_file = File::open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;

        let mut all_results: Vec<(Address, Value)> = Vec::new();

        for (region_start, region_size, _, _) in regions {
            // Skip regions that are too large (safety limit)
            if region_size > MAX_REGION_READ_SIZE {
                continue;
            }

            // Read region memory
            let mut buffer = vec![0u8; region_size];
            if mem_file.seek(SeekFrom::Start(region_start)).is_ok()
                && mem_file.read_exact(&mut buffer).is_ok()
            {
                let result = ScanEngine::initial_scan(&buffer, Address(region_start), &params);
                all_results.extend(result.addresses);
            }

            // Cap total results to prevent memory exhaustion
            if all_results.len() >= MAX_SCAN_RESULTS {
                break;
            }
        }

        // Truncate if over limit
        if all_results.len() > MAX_SCAN_RESULTS {
            all_results.truncate(MAX_SCAN_RESULTS);
        }

        Ok::<_, String>(all_results)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    // Store results for refinement (back on main thread, but quick)
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

/// Parse a maps line for scanning (returns start, end, readable, writable)
fn parse_maps_line_for_scan(line: &str) -> Option<(u64, u64, bool, bool)> {
    let mut parts = line.split_whitespace();
    let addr_range = parts.next()?;
    let mut addr_parts = addr_range.split('-');
    let start = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let perms = parts.next()?;
    Some((start, end, perms.contains('r'), perms.contains('w')))
}

/// Get the number of scan results
#[tauri::command]
fn get_scan_count(state: State<'_, AppState>) -> usize {
    state.last_scan_results.lock_or_recover().len()
}

/// Refine the existing scan results
#[tauri::command]
async fn refine_scan(request: RefineRequest, state: State<'_, AppState>) -> Result<Vec<ScanResult>, String> {
    // Get pid and previous results while holding locks briefly
    let (pid, previous, value_type) = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        let previous = state.last_scan_results.lock_or_recover().clone();
        let value_type = state.last_scan_type.lock_or_recover()
            .ok_or("No previous scan to refine")?;
        (attached.pid.0, previous, value_type)
    };

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

    // Run the heavy refinement in a blocking task
    let refined = tauri::async_runtime::spawn_blocking(move || {
        // Open memory file - use Mutex for Sync requirement
        let mem_file = File::open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;
        let mem_file = Mutex::new(mem_file);

        // Perform refinement
        let refined = ScanEngine::refine_scan(
            &previous,
            |addr, sz| {
                let mut file = mem_file.lock().ok()?;
                let mut buf = vec![0u8; sz];
                if file.seek(SeekFrom::Start(addr.0)).is_ok()
                    && file.read_exact(&mut buf).is_ok()
                {
                    Some(buf)
                } else {
                    None
                }
            },
            &value_type,
            &refinement,
        );

        Ok::<_, String>(refined)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

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
    let _label = request.label.clone();
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

    Ok(entry_id.0.to_string())
}

/// Remove an address from the watch list
#[tauri::command]
fn remove_watch(entry_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = EntryId(entry_id.parse().map_err(|_| "Invalid entry ID")?);
    let mut session = state.session.write_checked()?;
    let _address = session.watches.get(&id).map(|w| w.address);
    session.remove_watch(&id);
    drop(session);
    mark_project_changed(&state);
    Ok(())
}

/// Get all watch entries with current values
#[tauri::command]
async fn get_watches(state: State<'_, AppState>) -> Result<Vec<WatchInfo>, String> {
    // Collect watch data and pid while holding locks briefly
    let (watch_data, pid_opt): (Vec<_>, Option<u32>) = {
        let attached_guard = state.attached.lock_checked()?;
        let session = state.session.read_checked()?;

        let pid = attached_guard.as_ref().map(|a| a.pid.0);
        let data: Vec<_> = session.watches().map(|w| {
            let frozen = session.freezes.contains_key(&w.id);
            let freeze_value = session.freezes.get(&w.id).map(|f| format_val(&f.value));
            (w.id.0, w.address.0, w.value_type.clone(), w.label.clone(), frozen, freeze_value)
        }).collect();

        (data, pid)
    };

    // If no watches, return early (common case)
    if watch_data.is_empty() {
        return Ok(Vec::new());
    }

    // Read memory values in a blocking task to avoid blocking main thread
    let watches = tauri::async_runtime::spawn_blocking(move || {
        // Open /proc/pid/mem if we have a pid
        let mut mem_file = pid_opt.and_then(|pid| {
            File::open(format!("/proc/{}/mem", pid)).ok()
        });

        watch_data.into_iter().map(|(id, addr, value_type, label, frozen, freeze_value)| {
            let current_value = if let Some(ref mut file) = mem_file {
                let size = value_type.size().unwrap_or(8);
                let mut buf = vec![0u8; size];
                if file.seek(SeekFrom::Start(addr as u64)).is_ok()
                    && file.read_exact(&mut buf).is_ok()
                {
                    decode_at(&buf, &value_type)
                } else {
                    None
                }
            } else {
                None
            };

            WatchInfo {
                id: id.to_string(),
                address: format!("0x{:016X}", addr),
                value_type: format_value_type(&value_type),
                label,
                value: current_value.map(|v| format_val(&v)),
                frozen,
                freeze_value,
            }
        }).collect::<Vec<_>>()
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?;

    Ok(watches)
}

/// Toggle freeze for a watch entry
#[tauri::command]
fn toggle_freeze(request: FreezeRequest, state: State<'_, AppState>) -> Result<bool, String> {
    let id = EntryId(request.entry_id.parse().map_err(|_| "Invalid entry ID")?);
    let mut session = state.session.write_checked()?;

    let (result, _address) = if session.freezes.contains_key(&id) {
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
    Ok(result)
}

/// Write a value directly to memory
#[tauri::command]
async fn write_value(request: WriteValueRequest, state: State<'_, AppState>) -> Result<(), String> {
    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;
    let value = parse_value(&request.value, &value_type)?;
    let bytes = encode_value(&value);
    let addr_val = address.0;

    // Write in blocking task
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;
        file.seek(SeekFrom::Start(addr_val))
            .map_err(|e| format!("Failed to seek: {}", e))?;
        file.write_all(&bytes)
            .map_err(|e| format!("Failed to write: {}", e))?;
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    Ok(())
}

/// Read a value directly from memory
#[tauri::command]
async fn read_value(request: ReadValueRequest, state: State<'_, AppState>) -> Result<Option<String>, String> {
    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;
    let size = value_type.size().unwrap_or(8);
    let addr_val = address.0;

    // Read in blocking task
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut file = File::open(format!("/proc/{}/mem", pid)).ok()?;
        let mut buf = vec![0u8; size];
        file.seek(SeekFrom::Start(addr_val)).ok()?;
        file.read_exact(&mut buf).ok()?;
        decode_at(&buf, &value_type).map(|v| format_val(&v))
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?;

    Ok(result)
}

/// Read raw memory bytes for hex viewer
#[tauri::command]
async fn read_memory_bytes(
    address: String,
    size: usize,
    state: State<'_, AppState>,
) -> Result<Vec<u8>, String> {
    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    let addr = parse_address(&address)?;

    // Limit read size to prevent excessive memory usage (max 64KB per read)
    let size = size.min(65536);

    // Read in blocking task
    let buf = tauri::async_runtime::spawn_blocking(move || {
        let mut file = File::open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;
        let mut buf = vec![0u8; size];
        file.seek(SeekFrom::Start(addr.0))
            .map_err(|e| format!("Failed to seek: {}", e))?;
        file.read_exact(&mut buf)
            .map_err(|e| format!("Failed to read memory: {}", e))?;
        Ok::<_, String>(buf)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    Ok(buf)
}

/// Format a value for compact display (4 decimal places for floats)
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
        let id = entry.id.parse().unwrap_or_else(|e| {
            tracing::warn!(
                entry_id = %entry.id,
                error = %e,
                "Invalid UUID in project file, generating new ID"
            );
            uuid::Uuid::new_v4()
        });
        let watch = WatchEntry {
            id: EntryId(id),
            address: Address(entry.address),
            value_type: entry.value_type,
            label: entry.label.clone(),
            last_value: None,
        };
        session.add_watch(watch);

        // Restore freeze if applicable
        if entry.frozen {
            if let Some(ref freeze_val) = entry.freeze_value {
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

/// Perform a pattern scan
#[tauri::command]
async fn pattern_scan(request: PatternScanRequest, state: State<'_, AppState>) -> Result<Vec<PatternScanResult>, String> {
    // Validate pattern length
    if request.pattern.len() > MAX_PATTERN_INPUT_LENGTH {
        return Err(format!("Pattern string too long (max {} characters)", MAX_PATTERN_INPUT_LENGTH));
    }

    // Validate module name if provided
    if let Some(ref module) = request.module {
        if module.len() > MAX_LABEL_LENGTH {
            return Err(format!("Module name too long (max {} characters)", MAX_LABEL_LENGTH));
        }
    }

    // Get pid while holding lock briefly
    let pid = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        attached.pid.0
    };

    // Parse the pattern (quick operation)
    let pattern = Pattern::parse(&request.pattern)
        .map_err(|e| format!("Invalid pattern: {}", e))?;

    let module_filter = request.module.clone();
    let use_simd = request.use_simd;

    let _use_simd = use_simd; // SIMD handled internally by pattern

    // Run the heavy scan operation in a blocking task
    let result_list = tauri::async_runtime::spawn_blocking(move || {
        // Read /proc/pid/maps to get regions
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid))
            .map_err(|e| format!("Failed to read maps: {}", e))?;

        // Parse regions for pattern scanning (executable regions or module-filtered)
        let mut scan_regions: Vec<(u64, u64, bool, bool, Option<String>)> = Vec::new();
        for line in maps_content.lines() {
            if let Some(region) = parse_maps_line_for_pattern_scan(line) {
                scan_regions.push(region);
            }
        }

        // Filter regions
        let scan_regions: Vec<_> = if let Some(ref module_name) = module_filter {
            let module_lower = module_name.to_lowercase();
            scan_regions.into_iter()
                .filter(|(_, _, readable, _, module)| {
                    *readable && module.as_ref()
                        .is_some_and(|m| m.to_lowercase().contains(&module_lower))
                })
                .collect()
        } else {
            // Scan only executable regions by default
            scan_regions.into_iter()
                .filter(|(_, _, readable, executable, _)| *readable && *executable)
                .collect()
        };

        // Open memory file for reading
        let mut mem_file = File::open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;

        let mut all_results: Vec<PatternScanResult> = Vec::new();
        let pattern_len = pattern.len();

        for (start, end, _, _, module) in scan_regions {
            let region_size = (end - start) as usize;
            // Skip regions that are too large
            if region_size > MAX_REGION_READ_SIZE {
                continue;
            }

            // Read region memory
            let mut buffer = vec![0u8; region_size];
            if mem_file.seek(SeekFrom::Start(start)).is_ok()
                && mem_file.read_exact(&mut buffer).is_ok()
            {
                // Scan for pattern matches using matches_at
                let scan_end = buffer.len().saturating_sub(pattern_len);
                for offset in 0..=scan_end {
                    if pattern.matches_at(&buffer, offset) {
                        let address = start + offset as u64;
                        let module_offset = module.as_ref().map(|_| offset as u64);
                        all_results.push(PatternScanResult {
                            address: format!("0x{:016X}", address),
                            module: module.clone(),
                            module_offset: module_offset.map(|o| format!("0x{:X}", o)),
                        });

                        if all_results.len() >= 1000 {
                            break;
                        }
                    }
                }
            }

            if all_results.len() >= 1000 {
                break;
            }
        }

        Ok::<_, String>(all_results)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    Ok(result_list)
}

/// Parse a maps line for pattern scanning (returns start, end, readable, executable, module)
fn parse_maps_line_for_pattern_scan(line: &str) -> Option<(u64, u64, bool, bool, Option<String>)> {
    let mut parts = line.split_whitespace();
    let addr_range = parts.next()?;
    let mut addr_parts = addr_range.split('-');
    let start = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let perms = parts.next()?;
    parts.next(); // offset
    parts.next(); // dev
    parts.next(); // inode
    let module = parts.next().map(|s| s.to_string());
    Some((start, end, perms.contains('r'), perms.contains('x'), module))
}

// ============================================================================
// Pointer Scanning Commands
// ============================================================================

/// Perform a pointer scan to find pointer chains to a target address
#[tauri::command]
fn pointer_scan(request: PointerScanRequest, state: State<'_, AppState>) -> Result<Vec<PointerScanResultItem>, String> {
    use messpit_engine::pointer::{PointerScanner, PointerScanConfig};

    // Parse target address
    let target_str = request.target_address.trim_start_matches("0x").trim_start_matches("0X");
    let target = u64::from_str_radix(target_str, 16)
        .map_err(|_| error_validation("target address", "must be a valid hexadecimal address"))?;

    if target < MIN_VALID_ADDRESS {
        return Err(error_validation("target address", "address is too low to be valid user-space memory"));
    }

    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    // Determine pointer size based on architecture
    let pointer_size = match attached.handle.architecture() {
        Architecture::X86 => 4,
        _ => 8,
    };

    // Build config with validated parameters
    let config = PointerScanConfig {
        max_depth: request.max_depth.unwrap_or(5).clamp(1, 7),
        max_offset: request.max_offset.unwrap_or(0x1000).min(0x10000),
        max_results: request.max_results.unwrap_or(100).min(1000),
        aligned_only: true,
        pointer_size,
        static_base_only: true,
    };

    // Get regions and modules
    let regions = attached.handle.regions().map_err(|e| error_process("get memory regions", &e.to_string()))?;
    let modules = attached.handle.modules().unwrap_or_default();

    // Perform the scan
    let scanner = PointerScanner::new(config);
    let result = scanner.scan(
        attached.handle.as_ref(),
        Address(target),
        &regions,
        &modules,
    );

    if result.cancelled {
        return Err("Pointer scan was cancelled".to_string());
    }

    // Convert to frontend format
    let items: Vec<PointerScanResultItem> = result.chains
        .into_iter()
        .map(|chain| PointerScanResultItem {
            chain: chain.format(),
            module: chain.module.clone(),
            module_offset: format!("0x{:X}", chain.module_offset),
            offsets: chain.offsets.iter().map(|o| {
                if *o >= 0 {
                    format!("0x{:X}", o)
                } else {
                    format!("-0x{:X}", o.unsigned_abs())
                }
            }).collect(),
        })
        .collect();

    tracing::info!(
        target = target,
        results = items.len(),
        pointers_scanned = result.pointers_scanned,
        "Pointer scan completed"
    );

    Ok(items)
}

/// Parse a maps line fully (returns start, end, readable, writable, executable, module)
fn parse_maps_line_full(line: &str) -> Option<(u64, u64, bool, bool, bool, Option<String>)> {
    let mut parts = line.split_whitespace();
    let addr_range = parts.next()?;
    let mut addr_parts = addr_range.split('-');
    let start = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(addr_parts.next()?, 16).ok()?;
    let perms = parts.next()?;
    parts.next(); // offset
    parts.next(); // dev
    parts.next(); // inode
    let module = parts.next().map(|s| s.to_string());
    Some((start, end, perms.contains('r'), perms.contains('w'), perms.contains('x'), module))
}

/// Resolve a pointer chain to get the current address
#[tauri::command]
async fn resolve_pointer_chain(request: ResolveChainRequest, state: State<'_, AppState>) -> Result<String, String> {
    use messpit_engine::pointer::PointerChain;

    // Get pid and pointer size while holding lock briefly
    let (pid, pointer_size) = {
        let guard = state.attached.lock_checked()?;
        let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;
        let ptr_size = match attached.handle.architecture() {
            Architecture::X86 => 4,
            _ => 8,
        };
        (attached.pid.0, ptr_size)
    };

    // Parse module offset
    let module_offset_str = request.module_offset.trim_start_matches("0x").trim_start_matches("0X");
    let module_offset = u64::from_str_radix(module_offset_str, 16)
        .map_err(|_| error_validation("module offset", "must be a valid hexadecimal value"))?;

    // Parse offsets
    let offsets: Result<Vec<i64>, String> = request.offsets.iter().map(|o| {
        let s = o.trim();
        let (negative, num_str) = if s.starts_with('-') {
            (true, s.trim_start_matches('-').trim_start_matches("0x").trim_start_matches("0X"))
        } else {
            (false, s.trim_start_matches('+').trim_start_matches("0x").trim_start_matches("0X"))
        };
        let val = i64::from_str_radix(num_str, 16)
            .map_err(|_| error_validation("offset", &format!("'{}' is not a valid hexadecimal value", o)))?;
        Ok(if negative { -val } else { val })
    }).collect();
    let offsets = offsets?;

    let chain = PointerChain {
        module: request.module.clone(),
        module_offset,
        offsets,
        resolved: Address(0), // Will be calculated
    };

    let module_name = request.module;

    // Run resolution in blocking task
    let resolved = tauri::async_runtime::spawn_blocking(move || {
        // Read /proc/pid/maps to find module base
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid))
            .map_err(|e| format!("Failed to read maps: {}", e))?;

        // Find module base address
        let module_base = if let Some(ref module) = module_name {
            let module_lower = module.to_lowercase();
            maps_content.lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let path = parts.get(5)?;
                        if path.to_lowercase().contains(&module_lower) {
                            let addr_range = parts[0];
                            let start_str = addr_range.split('-').next()?;
                            return u64::from_str_radix(start_str, 16).ok();
                        }
                    }
                    None
                })
                .next()
                .ok_or_else(|| format!("Module '{}' not found", module))?
        } else {
            return Err("Module name required for pointer chain resolution".to_string());
        };

        // Open memory file
        let mut mem_file = File::open(format!("/proc/{}/mem", pid))
            .map_err(|e| format!("Failed to open mem: {}", e))?;

        // Start from module base + offset
        let mut current_addr = module_base + chain.module_offset;

        // Follow the pointer chain
        for (i, offset) in chain.offsets.iter().enumerate() {
            // Read pointer at current address
            let mut ptr_buf = vec![0u8; pointer_size];
            mem_file.seek(SeekFrom::Start(current_addr))
                .map_err(|e| format!("Failed to seek to 0x{:X}: {}", current_addr, e))?;
            mem_file.read_exact(&mut ptr_buf)
                .map_err(|e| format!("Failed to read pointer at 0x{:X}: {}", current_addr, e))?;

            // Decode pointer value
            let ptr_value = if pointer_size == 4 {
                u32::from_le_bytes(ptr_buf[..4].try_into().unwrap()) as u64
            } else {
                u64::from_le_bytes(ptr_buf[..8].try_into().unwrap())
            };

            // Apply offset (except for the last one which is applied to the final address)
            if i < chain.offsets.len() - 1 {
                current_addr = (ptr_value as i64 + offset) as u64;
            } else {
                // Last offset is applied to the pointer value to get final address
                current_addr = (ptr_value as i64 + offset) as u64;
            }
        }

        Ok::<_, String>(current_addr)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))??;

    Ok(format!("0x{:016X}", resolved))
}

// ============================================================================
// Cheat Table Export/Import Commands
// ============================================================================

use messpit_engine::cheattable::{CheatTable, CheatEntry, AddressLocator};

/// Export current watches to a cheat table
#[tauri::command]
fn export_cheat_table(request: ExportCheatTableRequest, state: State<'_, AppState>) -> Result<String, String> {
    // Validate name
    if request.name.is_empty() || request.name.len() > MAX_LABEL_LENGTH {
        return Err(error_validation("name", "must be 1-256 characters"));
    }

    let session = state.session.read_checked()?;
    let attached = state.attached.lock_checked()?;

    // Get process name
    let process_name = attached.as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let mut table = CheatTable::new(&request.name, &process_name);
    table.author = request.author;
    table.description = request.description;

    // Get module hash if attached
    if let Some(ref proc) = *attached {
        table.target.module_hash = proc.handle.fingerprint().module_hash;
    }

    // Collect entries to export
    let entry_filter: Option<std::collections::HashSet<String>> = request.entry_ids
        .map(|ids| ids.into_iter().collect());

    for watch in session.watches() {
        // Filter if specific entries requested
        if let Some(ref filter) = entry_filter {
            if !filter.contains(&watch.id.0.to_string()) {
                continue;
            }
        }

        let frozen = session.freezes.contains_key(&watch.id);
        let freeze_value = session.freezes.get(&watch.id).map(|f| f.value.clone());

        let entry = CheatEntry {
            id: watch.id.0.to_string(),
            label: watch.label.clone(),
            group: None,
            value_type: watch.value_type,
            locator: AddressLocator::Direct { address: watch.address.0 },
            frozen,
            freeze_value,
            hotkey: None,
            description: None,
        };

        table.add_entry(entry);
    }

    // Convert to JSON
    table.to_json().map_err(|e| format!("Failed to export: {}", e))
}

/// Parse a cheat table JSON and return info
#[tauri::command]
fn parse_cheat_table(json: String) -> Result<CheatTableInfo, String> {
    let table = CheatTable::from_json(&json)
        .map_err(|e| format!("Invalid cheat table: {}", e))?;

    let entries: Vec<CheatTableEntryInfo> = table.entries.iter().map(|e| {
        let locator_kind = match &e.locator {
            AddressLocator::Direct { .. } => "direct",
            AddressLocator::PointerChain { .. } => "pointer_chain",
            AddressLocator::Signature { .. } => "signature",
        };

        CheatTableEntryInfo {
            id: e.id.clone(),
            label: e.label.clone(),
            group: e.group.clone(),
            value_type: format_value_type(&e.value_type),
            locator: e.locator.format(),
            locator_kind: locator_kind.to_string(),
            frozen: e.frozen,
            description: e.description.clone(),
        }
    }).collect();

    Ok(CheatTableInfo {
        name: table.name,
        author: table.author,
        description: table.description,
        process_name: table.target.process_name,
        entry_count: entries.len(),
        created: table.created,
        modified: table.modified,
        entries,
    })
}

/// Import entries from a cheat table
#[tauri::command]
fn import_cheat_table(request: ImportCheatTableRequest, state: State<'_, AppState>) -> Result<usize, String> {
    use messpit_engine::pointer::{resolve_chain, PointerChain};

    let table = CheatTable::from_json(&request.json)
        .map_err(|e| format!("Invalid cheat table: {}", e))?;

    let mut session = state.session.write_checked()?;
    let attached = state.attached.lock_checked()?;

    // Check if attached process matches (warn but continue)
    if let Some(ref proc) = *attached {
        if !proc.name.to_lowercase().contains(&table.target.process_name.to_lowercase()) {
            tracing::warn!(
                "Importing cheat table for '{}' but attached to '{}'",
                table.target.process_name,
                proc.name
            );
        }
    }

    let entry_filter: Option<std::collections::HashSet<String>> = request.entry_ids
        .map(|ids| ids.into_iter().collect());

    let mut imported = 0;

    for entry in &table.entries {
        // Filter if specific entries requested
        if let Some(ref filter) = entry_filter {
            if !filter.contains(&entry.id) {
                continue;
            }
        }

        // Resolve address based on locator type
        let address = if request.resolve && attached.is_some() {
            let proc = attached.as_ref().unwrap();
            match &entry.locator {
                AddressLocator::Direct { address } => Some(Address(*address)),
                AddressLocator::PointerChain { module, module_offset, offsets } => {
                    let chain = PointerChain {
                        module: Some(module.clone()),
                        module_offset: *module_offset,
                        offsets: offsets.clone(),
                        resolved: Address(0),
                    };
                    let pointer_size = match proc.handle.architecture() {
                        Architecture::X86 => 4,
                        _ => 8,
                    };
                    let modules = proc.handle.modules().unwrap_or_default();
                    resolve_chain(proc.handle.as_ref(), &chain, &modules, pointer_size)
                }
                AddressLocator::Signature { module, pattern, offset } => {
                    // Try to resolve via pattern scan
                    if let Ok(parsed) = Pattern::parse(pattern) {
                        let regions = proc.handle.regions().unwrap_or_default();
                        let modules = proc.handle.modules().unwrap_or_default();
                        let module_lower = module.to_lowercase();
                        let scan_regions: Vec<_> = regions.into_iter()
                            .filter(|r| r.module.as_ref().is_some_and(|m| m.to_lowercase().contains(&module_lower)))
                            .collect();

                        let scanner = PatternScanner::new(parsed);
                        let results = scanner.scan_regions(proc.handle.as_ref(), &scan_regions, &modules, true);

                        results.first().map(|r| Address((r.address.0 as i64 + offset) as u64))
                    } else {
                        None
                    }
                }
            }
        } else {
            // Not resolving, just use direct address if available
            match &entry.locator {
                AddressLocator::Direct { address } => Some(Address(*address)),
                _ => None,
            }
        };

        // Only add if we have an address
        if let Some(addr) = address {
            let entry_id = EntryId(uuid::Uuid::new_v4());

            session.add_watch(WatchEntry {
                id: entry_id,
                address: addr,
                value_type: entry.value_type,
                label: entry.label.clone(),
                last_value: None,
            });

            // Apply freeze if specified
            if entry.frozen {
                if let Some(ref value) = entry.freeze_value {
                    let freeze = FreezeEntry::new(
                        entry_id,
                        addr,
                        entry.value_type,
                        value.clone(),
                        100, // Default interval
                    );
                    session.set_freeze(entry_id, freeze);
                }
            }

            imported += 1;
        }
    }

    tracing::info!(
        table_name = %table.name,
        imported = imported,
        total = table.entries.len(),
        "Imported cheat table entries"
    );

    Ok(imported)
}

/// Save cheat table to file
#[tauri::command]
fn save_cheat_table_file(path: String, json: String) -> Result<(), String> {
    std::fs::write(&path, &json)
        .map_err(|e| format!("Failed to save file: {}", e))
}

/// Load cheat table from file
#[tauri::command]
fn load_cheat_table_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to load file: {}", e))
}

/// Add a signature to the project
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
async fn get_signatures(state: State<'_, AppState>) -> Result<Vec<SignatureInfo>, String> {
    // Collect signature data while holding locks briefly
    let (sigs_data, pid_opt): (Vec<_>, Option<u32>) = {
        let project = state.project.lock_checked()?;
        let attached = state.attached.lock_checked()?;
        let pid = attached.as_ref().map(|a| a.pid.0);
        let data: Vec<_> = project.signatures.iter().map(|sig| {
            (sig.id.clone(), sig.label.clone(), sig.pattern.clone(),
             sig.module.clone(), sig.offset, sig.value_type.clone())
        }).collect();
        (data, pid)
    };

    // If no signatures, return early
    if sigs_data.is_empty() {
        return Ok(Vec::new());
    }

    // Resolve signatures in blocking task if we have a pid
    let sigs = if let Some(pid) = pid_opt {
        tauri::async_runtime::spawn_blocking(move || {
            // Open memory file for pattern scanning
            let mem_file = File::open(format!("/proc/{}/mem", pid)).ok();
            let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok();

            sigs_data.into_iter().map(|(id, label, pattern, module, offset, value_type)| {
                // Try to resolve the signature
                let resolved_address = if mem_file.is_some() && maps_content.is_some() {
                    // Pattern resolution would go here, but skip for now to avoid complexity
                    // The signature will be resolved on-demand when needed
                    None
                } else {
                    None
                };

                SignatureInfo {
                    id,
                    label,
                    pattern,
                    module,
                    offset,
                    value_type: format_value_type(&value_type),
                    resolved_address,
                }
            }).collect::<Vec<_>>()
        })
        .await
        .map_err(|e| format!("Task failed: {}", e))?
    } else {
        // No process attached, just return signature info without resolution
        sigs_data.into_iter().map(|(id, label, pattern, module, offset, value_type)| {
            SignatureInfo {
                id,
                label,
                pattern,
                module,
                offset,
                value_type: format_value_type(&value_type),
                resolved_address: None,
            }
        }).collect()
    };

    Ok(sigs)
}

/// Resolve a signature to a runtime address
#[tauri::command]
async fn resolve_signature(sig_id: String, state: State<'_, AppState>) -> Result<Option<String>, String> {
    // Get pid and signature data while holding locks briefly
    let (pid, pattern_str, module, offset) = {
        let project = state.project.lock_checked()?;
        let attached = state.attached.lock_checked()?;

        let sig = project.get_signature(&sig_id)
            .ok_or("Signature not found")?;

        let attached_proc = attached.as_ref()
            .ok_or("No process attached")?;

        (attached_proc.pid.0, sig.pattern.clone(), sig.module.clone(), sig.offset)
    };

    // Parse pattern
    let pattern = Pattern::parse(&pattern_str)
        .map_err(|e| format!("Invalid pattern: {}", e))?;

    // Run resolution in blocking task
    let address = tauri::async_runtime::spawn_blocking(move || {
        // Read /proc/pid/maps
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

        // Filter to target module
        let module_lower = module.to_lowercase();
        let scan_regions: Vec<(u64, u64, Option<String>)> = maps_content.lines()
            .filter_map(|line| {
                let (start, end, readable, _, executable, module_path) = parse_maps_line_full(line)?;
                if readable && executable {
                    if module_path.as_ref().is_some_and(|m| m.to_lowercase().contains(&module_lower)) {
                        return Some((start, end, module_path));
                    }
                }
                None
            })
            .collect();

        // Open memory file
        let mut mem_file = File::open(format!("/proc/{}/mem", pid)).ok()?;
        let pattern_len = pattern.len();

        // Scan regions for pattern
        for (start, end, _) in scan_regions {
            let region_size = (end - start) as usize;
            if region_size > MAX_REGION_READ_SIZE {
                continue;
            }

            let mut buffer = vec![0u8; region_size];
            if mem_file.seek(SeekFrom::Start(start)).is_ok()
                && mem_file.read_exact(&mut buffer).is_ok()
            {
                // Scan for pattern using matches_at
                let scan_end = buffer.len().saturating_sub(pattern_len);
                for match_offset in 0..=scan_end {
                    if pattern.matches_at(&buffer, match_offset) {
                        let address = start + match_offset as u64;
                        return Some(Address((address as i64 + offset) as u64));
                    }
                }
            }
        }

        None
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?;

    Ok(address.map(|a| format!("0x{:016X}", a.0)))
}

/// Create a watch entry from a resolved signature
#[tauri::command]
async fn watch_from_signature(sig_id: String, state: State<'_, AppState>) -> Result<String, String> {
    // Get pid and signature data while holding locks briefly
    let (pid, sig_label, sig_pattern, sig_module, sig_offset, sig_value_type) = {
        let project = state.project.lock_checked()?;
        let attached = state.attached.lock_checked()?;

        let sig = project.get_signature(&sig_id)
            .ok_or("Signature not found")?;

        let attached_proc = attached.as_ref()
            .ok_or("No process attached")?;

        (
            attached_proc.pid.0,
            sig.label.clone(),
            sig.pattern.clone(),
            sig.module.clone(),
            sig.offset,
            sig.value_type.clone(),
        )
    };

    // Parse pattern
    let pattern = Pattern::parse(&sig_pattern)
        .map_err(|e| format!("Invalid pattern: {}", e))?;

    // Run resolution in blocking task
    let address = tauri::async_runtime::spawn_blocking(move || {
        // Read /proc/pid/maps
        let maps_content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

        // Filter to target module
        let module_lower = sig_module.to_lowercase();
        let scan_regions: Vec<(u64, u64)> = maps_content.lines()
            .filter_map(|line| {
                let (start, end, readable, _, executable, module_path) = parse_maps_line_full(line)?;
                if readable && executable {
                    if module_path.as_ref().is_some_and(|m| m.to_lowercase().contains(&module_lower)) {
                        return Some((start, end));
                    }
                }
                None
            })
            .collect();

        // Open memory file
        let mut mem_file = File::open(format!("/proc/{}/mem", pid)).ok()?;
        let pattern_len = pattern.len();

        // Scan regions for pattern
        for (start, end) in scan_regions {
            let region_size = (end - start) as usize;
            if region_size > MAX_REGION_READ_SIZE {
                continue;
            }

            let mut buffer = vec![0u8; region_size];
            if mem_file.seek(SeekFrom::Start(start)).is_ok()
                && mem_file.read_exact(&mut buffer).is_ok()
            {
                // Scan for pattern using matches_at
                let scan_end = buffer.len().saturating_sub(pattern_len);
                for match_offset in 0..=scan_end {
                    if pattern.matches_at(&buffer, match_offset) {
                        let addr = start + match_offset as u64;
                        return Some(Address((addr as i64 + sig_offset) as u64));
                    }
                }
            }
        }

        None
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
    .ok_or("Failed to resolve signature")?;

    // Create watch entry
    let entry_id = EntryId::new();
    let entry = WatchEntry {
        id: entry_id,
        address,
        value_type: sig_value_type.clone(),
        label: sig_label.clone(),
        last_value: None,
    };

    let mut session = state.session.write_checked()?;
    session.add_watch(entry);
    drop(session);

    // Also update the project watch entry with signature reference
    let mut project = state.project.lock_checked()?;
    project.add_watch(ProjectWatchEntry {
        id: entry_id.0.to_string(),
        label: sig_label,
        address: address.0,
        value_type: sig_value_type,
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
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<AppState>() {
                    cleanup_on_exit(&state);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_processes_cmd,
            list_processes_filtered,
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
            read_memory_bytes,
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
            // Pointer scanning commands
            pointer_scan,
            resolve_pointer_chain,
            // Cheat table commands
            export_cheat_table,
            parse_cheat_table,
            import_cheat_table,
            save_cheat_table_file,
            load_cheat_table_file,
            add_signature,
            remove_signature,
            get_signatures,
            resolve_signature,
            watch_from_signature,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
