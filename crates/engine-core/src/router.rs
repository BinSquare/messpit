//! Command router - dispatches commands to appropriate handlers

use std::sync::{RwLockReadGuard, RwLockWriteGuard};

use messpit_platform;
use messpit_policy::{Policy, PolicyDecision};
use messpit_protocol::{
    CommandEnvelope, CommandId, DetachReason, EngineCommand, EngineError, EngineEvent,
    ErrorCode, EventEnvelope,
};

use crate::{
    EngineTransport, EventSender, SharedSession, WatchEntry,
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

/// Engine router that processes commands and emits events
pub struct Router {
    session: SharedSession,
    transport: EngineTransport,
    policy: Policy,
}

impl Router {
    /// Create a new router with default (restrictive) policy
    pub fn new(session: SharedSession, transport: EngineTransport) -> Self {
        Self {
            session,
            transport,
            policy: Policy::default(),
        }
    }

    /// Create a new router with permissive policy (allows writes)
    pub fn new_permissive(session: SharedSession, transport: EngineTransport) -> Self {
        Self {
            session,
            transport,
            policy: Policy::permissive(),
        }
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
            EngineCommand::AddWatch { entry_id, address, ty, label } => {
                self.add_watch(entry_id, address, ty, label)
            }
            EngineCommand::RemoveWatch { entry_id } => self.remove_watch(entry_id),
            EngineCommand::SetFreeze { entry_id, enabled, value, interval_ms } => {
                self.set_freeze(entry_id, enabled, value, interval_ms)
            }
            EngineCommand::DisableAllFreezes => self.disable_all_freezes(),
            // TODO: Implement remaining commands
            _ => Err(EngineError::new(
                ErrorCode::InternalError,
                "Command not yet implemented",
            )),
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
                    let value = decode_value(&buffer, &ty);
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

        // TODO: Add audit record

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
            label,
            last_value: None,
        });

        Ok(vec![])
    }

    fn remove_watch(
        &self,
        entry_id: messpit_protocol::EntryId,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;
        session.remove_watch(&entry_id);
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

        if enabled {
            // Get the watch entry to get address and type
            let watch = session.watches().find(|w| w.id == entry_id).cloned();

            if let Some(watch) = watch {
                let freeze_value = value.unwrap_or_else(|| {
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

        Ok(vec![])
    }

    fn disable_all_freezes(&self) -> Result<Vec<EngineEvent>, EngineError> {
        let mut session = self.session.write_or_error()?;
        session.set_freeze_enabled(false);
        Ok(vec![])
    }
}

/// Decode bytes into a typed value
fn decode_value(bytes: &[u8], ty: &messpit_protocol::ValueType) -> Option<messpit_protocol::Value> {
    use messpit_protocol::{Value, ValueType};

    match ty {
        ValueType::I8 if bytes.len() >= 1 => Some(Value::I8(i8::from_le_bytes([bytes[0]]))),
        ValueType::I16 if bytes.len() >= 2 => {
            Some(Value::I16(i16::from_le_bytes([bytes[0], bytes[1]])))
        }
        ValueType::I32 if bytes.len() >= 4 => Some(Value::I32(i32::from_le_bytes(
            bytes[..4].try_into().unwrap(),
        ))),
        ValueType::I64 if bytes.len() >= 8 => Some(Value::I64(i64::from_le_bytes(
            bytes[..8].try_into().unwrap(),
        ))),
        ValueType::U8 if bytes.len() >= 1 => Some(Value::U8(bytes[0])),
        ValueType::U16 if bytes.len() >= 2 => {
            Some(Value::U16(u16::from_le_bytes([bytes[0], bytes[1]])))
        }
        ValueType::U32 if bytes.len() >= 4 => Some(Value::U32(u32::from_le_bytes(
            bytes[..4].try_into().unwrap(),
        ))),
        ValueType::U64 if bytes.len() >= 8 => Some(Value::U64(u64::from_le_bytes(
            bytes[..8].try_into().unwrap(),
        ))),
        ValueType::F32 if bytes.len() >= 4 => Some(Value::F32(f32::from_le_bytes(
            bytes[..4].try_into().unwrap(),
        ))),
        ValueType::F64 if bytes.len() >= 8 => Some(Value::F64(f64::from_le_bytes(
            bytes[..8].try_into().unwrap(),
        ))),
        ValueType::Bytes { len } if bytes.len() >= *len => {
            Some(Value::Bytes(bytes[..*len].to_vec()))
        }
        ValueType::String { max_len } => {
            let end = bytes.iter().take(*max_len).position(|&b| b == 0).unwrap_or(*max_len);
            String::from_utf8(bytes[..end].to_vec()).ok().map(Value::String)
        }
        _ => None,
    }
}

/// Encode a typed value into bytes
fn encode_value(value: &messpit_protocol::Value) -> Vec<u8> {
    use messpit_protocol::Value;

    match value {
        Value::I8(v) => v.to_le_bytes().to_vec(),
        Value::I16(v) => v.to_le_bytes().to_vec(),
        Value::I32(v) => v.to_le_bytes().to_vec(),
        Value::I64(v) => v.to_le_bytes().to_vec(),
        Value::U8(v) => vec![*v],
        Value::U16(v) => v.to_le_bytes().to_vec(),
        Value::U32(v) => v.to_le_bytes().to_vec(),
        Value::U64(v) => v.to_le_bytes().to_vec(),
        Value::F32(v) => v.to_le_bytes().to_vec(),
        Value::F64(v) => v.to_le_bytes().to_vec(),
        Value::Bytes(v) => v.clone(),
        Value::String(v) => {
            let mut bytes = v.as_bytes().to_vec();
            bytes.push(0); // Null terminate
            bytes
        }
    }
}
