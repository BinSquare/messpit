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

use std::collections::HashMap;
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
    AttachResult, RefineRequest, RegionInfo, ResolveChainRequest, ScanRequest,
    ScanResult, ScriptInfo, ScriptOutputResult, ScriptRunResult, SignatureInfo,
    WatchInfo, WriteValueRequest, ReadValueRequest, ProjectInfo, AuditEntryInfo,
};

use messpit_engine::session::{FreezeEntry, WatchEntry};
use messpit_engine::{decode_at, encode_value, new_shared_session, AuditLog, Pattern, PatternScanner, Project, ProjectSignature, ProjectWatchEntry, ScanEngine, SharedSession};
use messpit_platform::{attach, list_processes, PlatformError, ProcessHandle};
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
    /// Audit log for tracking operations
    audit_log: Mutex<AuditLog>,
}

struct AttachedProcess {
    pid: Pid,
    name: String,
    handle: Box<dyn ProcessHandle>,
}

// Types are imported from the types module

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
        .map(|r| {
            // Try to read first 16 bytes for preview if readable
            let preview = if r.permissions.read {
                let mut buf = [0u8; 16];
                attached.handle.read_memory(r.base, &mut buf).ok().map(|_| {
                    buf.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                })
            } else {
                None
            };

            RegionInfo {
                start: format!("0x{:016X}", r.base.0),
                end: format!("0x{:016X}", r.base.0.saturating_add(r.size)),
                size: r.size,
                readable: r.permissions.read,
                writable: r.permissions.write,
                executable: r.permissions.execute,
                module: r.module,
                preview,
            }
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

        let frozen = session.freezes.contains_key(&w.id);
        let freeze_value = session.freezes.get(&w.id).map(|f| format_val(&f.value));
        WatchInfo {
            id: w.id.0.to_string(),
            address: format!("0x{:016X}", w.address.0),
            value_type: format_value_type(&w.value_type),
            label: w.label.clone(),
            value: current_value.map(|v| format_val(&v)),
            frozen,
            freeze_value,
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
#[tauri::command]
fn read_value(request: ReadValueRequest, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let address = parse_address(&request.address)?;
    let value_type = parse_value_type(&request.value_type)?;
    let size = value_type.size().unwrap_or(8);

    let mut buf = vec![0u8; size];
    if attached.handle.read_memory(address, &mut buf).is_ok() {
        if let Some(value) = decode_at(&buf, &value_type) {
            return Ok(Some(format_val(&value)));
        }
    }

    Ok(None)
}

/// Read raw memory bytes for hex viewer
#[tauri::command]
fn read_memory_bytes(
    address: String,
    size: usize,
    state: State<'_, AppState>,
) -> Result<Vec<u8>, String> {
    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

    let address = parse_address(&address)?;

    // Limit read size to prevent excessive memory usage (max 64KB per read)
    let size = size.min(65536);

    let mut buf = vec![0u8; size];
    attached.handle.read_memory(address, &mut buf)
        .map_err(|e| format!("Failed to read memory: {}", e))?;

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

/// Record an audit log entry
fn record_audit(state: &AppState, operation: &str, pid: Option<u32>, address: Option<Address>, details: Option<&str>) {
    if let Ok(mut log) = state.audit_log.lock() {
        log.record(operation, pid, address, details);
    }
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
fn pattern_scan(request: PatternScanRequest, state: State<'_, AppState>) -> Result<Vec<PatternScanResult>, String> {
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

/// Resolve a pointer chain to get the current address
#[tauri::command]
fn resolve_pointer_chain(request: ResolveChainRequest, state: State<'_, AppState>) -> Result<String, String> {
    use messpit_engine::pointer::{resolve_chain, PointerChain};

    let guard = state.attached.lock_checked()?;
    let attached = guard.as_ref().ok_or_else(|| error_requires("an attached process"))?;

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
        module: request.module,
        module_offset,
        offsets,
        resolved: Address(0), // Will be calculated
    };

    // Determine pointer size
    let pointer_size = match attached.handle.architecture() {
        Architecture::X86 => 4,
        _ => 8,
    };

    let modules = attached.handle.modules().unwrap_or_default();
    let resolved = resolve_chain(attached.handle.as_ref(), &chain, &modules, pointer_size)
        .ok_or_else(|| "Failed to resolve pointer chain - one or more pointers are invalid".to_string())?;

    Ok(format!("0x{:016X}", resolved.0))
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
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<AppState>() {
                    cleanup_on_exit(&state);
                }
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
            // Audit log commands
            get_audit_log,
            clear_audit_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
