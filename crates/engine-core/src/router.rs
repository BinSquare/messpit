//! Command router - dispatches commands to appropriate handlers

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use messpit_policy::{Policy, PolicyDecision};
use messpit_protocol::{
    Address, CommandEnvelope, CommandId, DetachReason, EngineCommand, EngineError, EngineEvent,
    ErrorCode, EventEnvelope, JobId, PatternMatch, RunId, ScriptStatus,
};

use crate::{
    pattern::{Pattern, PatternScanner},
    scan::{decode_at, encode_value},
    EngineTransport, EventSender, Project, SharedSession, WatchEntry,
};

/// Helper trait for RwLock error handling
trait RwLockExt<T> {
    fn read_or_error(&self) -> Result<RwLockReadGuard<'_, T>, EngineError>;
    fn write_or_error(&self) -> Result<RwLockWriteGuard<'_, T>, EngineError>;
}

impl<T> RwLockExt<T> for std::sync::RwLock<T> {
    fn read_or_error(&self) -> Result<RwLockReadGuard<'_, T>, EngineError> {
        self.read().map_err(|_| {
            EngineError::new(ErrorCode::InternalError, "Session lock poisoned")
        })
    }

    fn write_or_error(&self) -> Result<RwLockWriteGuard<'_, T>, EngineError> {
        self.write().map_err(|_| {
            EngineError::new(ErrorCode::InternalError, "Session lock poisoned")
        })
    }
}

/// Active job state for tracking pattern scans and scripts
pub struct ActiveJob {
    pub job_id: JobId,
    pub job_type: JobType,
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug, Clone)]
pub enum JobType {
    PatternScan,
    Script { run_id: RunId },
}

/// Engine router that processes commands and emits events
pub struct Router {
    session: SharedSession,
    transport: EngineTransport,
    policy: Policy,
    /// Active jobs (pattern scans, scripts)
    jobs: Arc<RwLock<HashMap<JobId, ActiveJob>>>,
    /// Current project state
    project: Arc<RwLock<Project>>,
    /// Tracks if project has unsaved changes
    has_unsaved_changes: Arc<std::sync::atomic::AtomicBool>,
}

impl Router {
    /// Create a new router with default (restrictive) policy
    pub fn new(session: SharedSession, transport: EngineTransport) -> Self {
        Self {
            session,
            transport,
            policy: Policy::default(),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            project: Arc::new(RwLock::new(Project::default())),
            has_unsaved_changes: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Create a new router with permissive policy (allows writes)
    pub fn new_permissive(session: SharedSession, transport: EngineTransport) -> Self {
        Self {
            session,
            transport,
            policy: Policy::permissive(),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            project: Arc::new(RwLock::new(Project::default())),
            has_unsaved_changes: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Check if project has unsaved changes
    pub fn has_unsaved_changes(&self) -> bool {
        self.has_unsaved_changes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Mark project as having unsaved changes
    fn mark_changed(&self) {
        self.has_unsaved_changes.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Mark project as saved (no unsaved changes)
    fn mark_saved(&self) {
        self.has_unsaved_changes.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get the current project
    pub fn project(&self) -> Arc<RwLock<Project>> {
        self.project.clone()
    }

    /// Process a single command and emit response events
    pub fn handle_command(&self, envelope: CommandEnvelope) {
        let cmd_id = envelope.id;

        match self.dispatch(envelope) {
            Ok(events) => {
                for event in events {
                    let _ = self.transport.send(EventEnvelope::response(event, cmd_id));
                }
            }
            Err(err) => {
                let _ = self.transport.send(EventEnvelope::response(
                    EngineEvent::Error(err),
                    cmd_id,
                ));
            }
        }
    }

    fn dispatch(&self, envelope: CommandEnvelope) -> Result<Vec<EngineEvent>, EngineError> {
        match envelope.command {
            EngineCommand::ListProcesses => self.list_processes(),
            EngineCommand::Attach { pid } => self.attach(pid, envelope.id),
            EngineCommand::Detach => self.detach(),
            EngineCommand::ListModules => self.list_modules(),
            EngineCommand::ListRegions { filter } => self.list_regions(filter),
            EngineCommand::ReadValues { addresses, ty } => self.read_values(addresses, ty),
            EngineCommand::WriteValue { address, value, reason } => {
                self.write_value(address, value, reason, envelope.id)
            }
            EngineCommand::StartScan { scan_id, params } => {
                self.start_scan(scan_id, params)
            }
            EngineCommand::RefineScan { scan_id, refinement } => {
                self.refine_scan(scan_id, refinement)
            }
            EngineCommand::GetScanResults { scan_id, offset, limit } => {
                self.get_scan_results(scan_id, offset, limit)
            }
            EngineCommand::CancelScan { scan_id } => self.cancel_scan(scan_id),
            EngineCommand::AddWatch { entry_id, address, ty, label } => {
                self.add_watch(entry_id, address, ty, label)
            }
            EngineCommand::RemoveWatch { entry_id } => self.remove_watch(entry_id),
            EngineCommand::SetFreeze { entry_id, enabled, value, interval_ms } => {
                self.set_freeze(entry_id, enabled, value, interval_ms)
            }
            EngineCommand::DisableAllFreezes => self.disable_all_freezes(),
            EngineCommand::StartPatternScan { job_id, module, pattern, region_filter } => {
                self.start_pattern_scan(job_id, module, pattern, region_filter)
            }
            EngineCommand::ResolveSymbol { module, offset } => {
                self.resolve_symbol(module, offset)
            }
            EngineCommand::RunScript { run_id, script_id, source, args } => {
                self.run_script(run_id, script_id, source, args)
            }
            EngineCommand::CancelJob { job_id } => self.cancel_job(job_id),
            EngineCommand::SaveProject { path } => self.save_project(path),
            EngineCommand::LoadProject { path } => self.load_project(path),
        }
    }

    fn list_processes(&self) -> Result<Vec<EngineEvent>, EngineError> {
        let processes = messpit_platform::list_processes().map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        Ok(vec![EngineEvent::ProcessList { processes }])
    }

    fn attach(
        &self,
        pid: messpit_protocol::Pid,
        cmd_id: CommandId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Check policy
        match self.policy.check_attach(pid) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                return Ok(vec![EngineEvent::PolicyDenied {
                    command_id: cmd_id,
                    reason,
                }]);
            }
        }

        let mut session = self.session.write_or_error()?;

        if session.is_attached() {
            return Err(EngineError::new(
                ErrorCode::AlreadyAttached,
                "Already attached to a process. Detach first.",
            ));
        }

        let process = messpit_platform::attach(pid).map_err(|e| {
            EngineError::new(ErrorCode::PermissionDenied, e.to_string())
        })?;

        let fingerprint = process.fingerprint();
        session.attach(process);

        Ok(vec![EngineEvent::Attached { fingerprint }])
    }

    fn detach(&self) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;

        if !session.is_attached() {
            return Err(EngineError::new(ErrorCode::NotAttached, "Not attached to any process"));
        }

        session.detach();

        Ok(vec![EngineEvent::Detached {
            reason: DetachReason::Requested,
        }])
    }

    fn list_modules(&self) -> Result<Vec<EngineEvent>, EngineError> {
        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        let modules = process.modules().map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        Ok(vec![EngineEvent::ModuleList { modules }])
    }

    fn list_regions(
        &self,
        filter: Option<messpit_protocol::RegionFilter>,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        let mut regions = process.regions().map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        // Apply filters if provided
        if let Some(f) = filter {
            regions.retain(|r| {
                f.readable.is_none_or(|v| r.permissions.read == v)
                    && f.writable.is_none_or(|v| r.permissions.write == v)
                    && f.executable.is_none_or(|v| r.permissions.execute == v)
                    && f.module_name.as_ref().is_none_or(|name| {
                        r.module.as_ref().is_some_and(|m| m.contains(name))
                    })
            });
        }

        Ok(vec![EngineEvent::RegionList { regions }])
    }

    fn read_values(
        &self,
        addresses: Vec<messpit_protocol::Address>,
        ty: messpit_protocol::ValueType,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        let size = ty.size().unwrap_or(256); // Default max for variable types
        let mut results = Vec::with_capacity(addresses.len());

        for addr in addresses {
            let mut buffer = vec![0u8; size];
            match process.read_memory(addr, &mut buffer) {
                Ok(read) if read >= size => {
                    let value = decode_at(&buffer, &ty);
                    results.push((addr, value));
                }
                _ => {
                    results.push((addr, None));
                }
            }
        }

        Ok(vec![EngineEvent::ValuesRead { values: results }])
    }

    fn write_value(
        &self,
        address: messpit_protocol::Address,
        value: messpit_protocol::Value,
        reason: String,
        cmd_id: CommandId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Check policy
        match self.policy.check_write(address, &reason) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                return Ok(vec![EngineEvent::PolicyDenied {
                    command_id: cmd_id,
                    reason,
                }]);
            }
        }

        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        let bytes = encode_value(&value);
        process.write_memory(address, &bytes).map_err(|e| {
            EngineError::new(ErrorCode::InvalidAddress, e.to_string())
        })?;

        drop(session);
        self.mark_changed();

        Ok(vec![EngineEvent::ValueWritten { address }])
    }

    fn add_watch(
        &self,
        entry_id: messpit_protocol::EntryId,
        address: messpit_protocol::Address,
        ty: messpit_protocol::ValueType,
        label: String,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;

        session.add_watch(WatchEntry {
            id: entry_id,
            address,
            value_type: ty,
            label: label.clone(),
            last_value: None,
        });

        drop(session);
        self.mark_changed();

        Ok(vec![])
    }

    fn remove_watch(
        &self,
        entry_id: messpit_protocol::EntryId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;
        session.remove_watch(&entry_id);
        drop(session);
        self.mark_changed();
        Ok(vec![])
    }

    fn set_freeze(
        &self,
        entry_id: messpit_protocol::EntryId,
        enabled: bool,
        value: Option<messpit_protocol::Value>,
        interval_ms: u32,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;

        let mut freeze_addr = None;
        if enabled {
            // Get the watch entry to get address and type
            let watch = session.watches().find(|w| w.id == entry_id).cloned();

            if let Some(watch) = watch {
                freeze_addr = Some(watch.address);
                let freeze_value = value.clone().unwrap_or_else(|| {
                    watch.last_value.clone().unwrap_or(messpit_protocol::Value::I32(0))
                });

                let freeze = crate::FreezeEntry::new(
                    entry_id,
                    watch.address,
                    watch.value_type,
                    freeze_value,
                    interval_ms,
                );
                session.set_freeze(entry_id, freeze);
            }
        } else {
            session.remove_freeze(&entry_id);
        }

        drop(session);
        self.mark_changed();

        Ok(vec![])
    }

    fn disable_all_freezes(&self) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;
        session.set_freeze_enabled(false);
        drop(session);
        Ok(vec![])
    }

    // === Scan commands (stub implementations - full scan logic is in scan.rs) ===

    fn start_scan(
        &self,
        _scan_id: messpit_protocol::ScanId,
        _params: messpit_protocol::ScanParams,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Scan functionality is primarily handled by the Tauri commands
        // This is a placeholder for the engine router
        Ok(vec![])
    }

    fn refine_scan(
        &self,
        _scan_id: messpit_protocol::ScanId,
        _refinement: messpit_protocol::Refinement,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Ok(vec![])
    }

    fn get_scan_results(
        &self,
        scan_id: messpit_protocol::ScanId,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Note: Scan results are managed by Tauri commands, not the engine router.
        // This stub exists for protocol completeness. The Tauri layer handles
        // scan state and pagination directly for better integration with the UI.
        let _ = limit; // Acknowledge parameter
        Ok(vec![EngineEvent::ScanResultsPage {
            scan_id,
            offset,
            entries: vec![],
        }])
    }

    fn cancel_scan(
        &self,
        scan_id: messpit_protocol::ScanId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        Ok(vec![EngineEvent::ScanCancelled { scan_id }])
    }

    // === Pattern scanning ===

    fn start_pattern_scan(
        &self,
        job_id: JobId,
        module: Option<String>,
        pattern: Vec<Option<u8>>,
        region_filter: Option<messpit_protocol::RegionFilter>,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        // Get regions and modules
        let mut regions = process.regions().map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        // Apply region filter if provided
        if let Some(ref f) = region_filter {
            regions.retain(|r| {
                f.readable.is_none_or(|v| r.permissions.read == v)
                    && f.writable.is_none_or(|v| r.permissions.write == v)
                    && f.executable.is_none_or(|v| r.permissions.execute == v)
            });
        }

        // Filter to specific module if requested
        if let Some(ref mod_name) = module {
            regions.retain(|r| {
                r.module.as_ref().is_some_and(|m| m.contains(mod_name))
            });
        }

        let modules = process.modules().unwrap_or_default();

        // Create pattern and scanner
        let compiled_pattern = Pattern::new(pattern);
        let scanner = PatternScanner::new(compiled_pattern);

        // Register the job
        let cancelled = scanner.cancellation_handle();
        if let Ok(mut jobs) = self.jobs.write() {
            jobs.insert(job_id, ActiveJob {
                job_id,
                job_type: JobType::PatternScan,
                cancelled: cancelled.clone(),
            });
        }

        // Perform the scan
        let results = scanner.scan_regions(process, &regions, &modules, true);

        // Remove the job
        if let Ok(mut jobs) = self.jobs.write() {
            jobs.remove(&job_id);
        }

        // Convert results
        let matches: Vec<PatternMatch> = results
            .into_iter()
            .map(|r| PatternMatch {
                address: r.address,
                module: r.module,
                module_offset: r.module_offset,
            })
            .collect();

        drop(session);

        Ok(vec![EngineEvent::PatternScanResults { job_id, matches }])
    }

    fn resolve_symbol(
        &self,
        module_name: String,
        offset: u64,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let session = self.session.read_or_error()?;

        let process = session.process().ok_or_else(|| {
            EngineError::new(ErrorCode::NotAttached, "Not attached to any process")
        })?;

        let modules = process.modules().map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        // Find the module
        let module = modules.iter().find(|m| m.name.contains(&module_name));

        match module {
            Some(m) => {
                let address = Address(m.base.0 + offset);
                Ok(vec![EngineEvent::SymbolResolved {
                    module: module_name,
                    offset,
                    address,
                }])
            }
            None => Err(EngineError::new(
                ErrorCode::InvalidAddress,
                format!("Module '{}' not found", module_name),
            )),
        }
    }

    // === Scripting ===

    fn run_script(
        &self,
        run_id: RunId,
        _script_id: messpit_protocol::ScriptId,
        _source: String,
        _args: Vec<String>,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Script execution is handled by the script-host crate and Tauri commands
        // This router method returns a placeholder event.

        // In a full implementation, we would:
        // 1. Register the job
        // 2. Spawn the script execution
        // 3. Stream output via events
        // For now, return finished immediately (actual execution is in Tauri commands)
        Ok(vec![EngineEvent::ScriptFinished {
            run_id,
            status: ScriptStatus::Success,
        }])
    }

    fn cancel_job(
        &self,
        job_id: JobId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        if let Ok(jobs) = self.jobs.read() {
            if let Some(job) = jobs.get(&job_id) {
                job.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(vec![]);
            }
        }

        Err(EngineError::new(
            ErrorCode::InternalError,
            format!("Job {:?} not found", job_id),
        ))
    }

    // === Project management ===

    fn save_project(
        &self,
        path: String,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Get current session state and save to project
        let session = self.session.read_or_error()?;

        let mut project = self.project.write().map_err(|_| {
            EngineError::new(ErrorCode::InternalError, "Failed to lock project")
        })?;

        // Update project with current watch entries
        project.watch_entries.clear();
        for watch in session.watches() {
            project.watch_entries.push(crate::ProjectWatchEntry {
                id: watch.id.0.to_string(),
                label: watch.label.clone(),
                address: watch.address.0,
                value_type: watch.value_type,
                frozen: session.freezes.contains_key(&watch.id),
                freeze_value: session.freezes.get(&watch.id).map(|f| f.value.clone()),
                signature_id: None,
            });
        }

        // Save to file
        project.save(&path).map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        drop(session);
        drop(project);

        self.mark_saved();

        Ok(vec![EngineEvent::ProjectSaved { path }])
    }

    fn load_project(
        &self,
        path: String,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        // Load project from file
        let loaded_project = Project::load(&path).map_err(|e| {
            EngineError::new(ErrorCode::InternalError, e.to_string())
        })?;

        // Update internal project state
        {
            let mut project = self.project.write().map_err(|_| {
                EngineError::new(ErrorCode::InternalError, "Failed to lock project")
            })?;
            *project = loaded_project.clone();
        }

        // Restore watch entries to session
        let mut session = self.session.write_or_error()?;
        session.watches.clear();
        session.freezes.clear();

        for entry in &loaded_project.watch_entries {
            let entry_id = messpit_protocol::EntryId(
                uuid::Uuid::parse_str(&entry.id).unwrap_or_else(|_| uuid::Uuid::new_v4())
            );
            session.add_watch(WatchEntry {
                id: entry_id,
                address: Address(entry.address),
                value_type: entry.value_type,
                label: entry.label.clone(),
                last_value: None,
            });

            // Restore freeze if applicable
            if entry.frozen {
                if let Some(ref value) = entry.freeze_value {
                    let freeze = crate::FreezeEntry::new(
                        entry_id,
                        Address(entry.address),
                        entry.value_type,
                        value.clone(),
                        100, // Default interval
                    );
                    session.set_freeze(entry_id, freeze);
                }
            }
        }

        drop(session);
        self.mark_saved(); // Just loaded, so no unsaved changes

        Ok(vec![EngineEvent::ProjectLoaded { path }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messpit_protocol::{Value, ValueType};

    #[test]
    fn test_decode_encode_roundtrip_i32() {
        use crate::scan::{decode_at, encode_value};

        let original = Value::I32(-12345);
        let encoded = encode_value(&original);
        let decoded = decode_at(&encoded, &ValueType::I32);

        assert_eq!(decoded, Some(original));
    }

    #[test]
    fn test_decode_encode_roundtrip_u64() {
        use crate::scan::{decode_at, encode_value};

        let original = Value::U64(0xDEADBEEFCAFEBABE);
        let encoded = encode_value(&original);
        let decoded = decode_at(&encoded, &ValueType::U64);

        assert_eq!(decoded, Some(original));
    }

    #[test]
    fn test_decode_encode_roundtrip_f64() {
        use crate::scan::{decode_at, encode_value};

        let original = Value::F64(3.141592653589793);
        let encoded = encode_value(&original);
        let decoded = decode_at(&encoded, &ValueType::F64);

        assert_eq!(decoded, Some(original));
    }

    #[test]
    fn test_decode_encode_roundtrip_string() {
        use crate::scan::{decode_at, encode_value};

        let original = Value::String("Hello, World!".to_string());
        let encoded = encode_value(&original);
        let decoded = decode_at(&encoded, &ValueType::String { max_len: 100 });

        assert_eq!(decoded, Some(original));
    }

    #[test]
    fn test_decode_insufficient_bytes() {
        use crate::scan::decode_at;

        let bytes = [0x12, 0x34]; // Only 2 bytes
        assert!(decode_at(&bytes, &ValueType::I32).is_none());
        assert!(decode_at(&bytes, &ValueType::I64).is_none());
        assert!(decode_at(&bytes, &ValueType::F64).is_none());
    }
}
