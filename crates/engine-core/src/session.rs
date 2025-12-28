//! Session state management

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use messpit_platform::ProcessHandle;
use messpit_protocol::{EntryId, ScanId, Address, ValueType, Value};

/// Trait alias for ProcessHandle (re-exported for convenience)
pub use messpit_platform::ProcessHandle as ProcessHandleDyn;

/// Active session state
pub struct Session {
    /// Currently attached process, if any
    process: Option<Box<dyn ProcessHandle>>,
    /// Active scans
    scans: HashMap<ScanId, ScanState>,
    /// Watch entries
    pub watches: HashMap<EntryId, WatchEntry>,
    /// Freeze entries (subset of watches)
    pub freezes: HashMap<EntryId, FreezeEntry>,
    /// Global freeze enabled
    freeze_enabled: bool,
}

impl Session {
    pub fn new() -> Self {
        Self {
            process: None,
            scans: HashMap::new(),
            watches: HashMap::new(),
            freezes: HashMap::new(),
            freeze_enabled: true,
        }
    }

    pub fn is_attached(&self) -> bool {
        self.process.is_some()
    }

    pub fn process(&self) -> Option<&dyn ProcessHandle> {
        self.process.as_deref()
    }

    pub fn process_mut(&mut self) -> Option<&mut Box<dyn ProcessHandle>> {
        self.process.as_mut()
    }

    pub fn attach(&mut self, process: Box<dyn ProcessHandle>) {
        self.process = Some(process);
    }

    pub fn detach(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.detach();
        }
        // Clear scans but preserve watches for re-resolve on next attach
        self.scans.clear();
    }

    pub fn add_watch(&mut self, entry: WatchEntry) {
        self.watches.insert(entry.id, entry);
    }

    pub fn remove_watch(&mut self, id: &EntryId) {
        self.watches.remove(id);
        self.freezes.remove(id);
    }

    pub fn watches(&self) -> impl Iterator<Item = &WatchEntry> {
        self.watches.values()
    }

    pub fn set_freeze(&mut self, id: EntryId, freeze: FreezeEntry) {
        self.freezes.insert(id, freeze);
    }

    pub fn remove_freeze(&mut self, id: &EntryId) {
        self.freezes.remove(id);
    }

    pub fn freezes(&self) -> impl Iterator<Item = &FreezeEntry> {
        self.freezes.values()
    }

    pub fn is_freeze_enabled(&self) -> bool {
        self.freeze_enabled
    }

    pub fn set_freeze_enabled(&mut self, enabled: bool) {
        self.freeze_enabled = enabled;
    }

    pub fn add_scan(&mut self, id: ScanId, state: ScanState) {
        self.scans.insert(id, state);
    }

    pub fn get_scan(&self, id: &ScanId) -> Option<&ScanState> {
        self.scans.get(id)
    }

    pub fn get_scan_mut(&mut self, id: &ScanId) -> Option<&mut ScanState> {
        self.scans.get_mut(id)
    }

    pub fn remove_scan(&mut self, id: &ScanId) {
        self.scans.remove(id);
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// State of an active scan
pub struct ScanState {
    pub id: ScanId,
    pub value_type: ValueType,
    /// Current mode (dense or sparse)
    pub mode: ScanMode,
    /// Number of results
    pub result_count: usize,
}

/// Scan storage mode
pub enum ScanMode {
    /// Dense mode: bitset + snapshot for "unknown initial" scans
    Dense {
        /// Baseline snapshot of memory
        snapshot: Vec<u8>,
        /// Bitset of valid addresses (1 bit per aligned position)
        valid: Vec<u8>,
        /// Base address of the snapshot
        base: Address,
    },
    /// Sparse mode: list of addresses after narrowing
    Sparse {
        /// Matched addresses with their last known values
        addresses: Vec<(Address, Value)>,
    },
}

/// A watched memory location
#[derive(Debug, Clone)]
pub struct WatchEntry {
    pub id: EntryId,
    pub address: Address,
    pub value_type: ValueType,
    pub label: String,
    pub last_value: Option<Value>,
}

/// A frozen memory location
#[derive(Debug, Clone)]
pub struct FreezeEntry {
    pub id: EntryId,
    pub address: Address,
    pub value_type: ValueType,
    pub value: Value,
    pub interval_ms: u32,
    pub failure_count: u32,
    pub max_failures: u32,
}

impl FreezeEntry {
    pub const DEFAULT_MAX_FAILURES: u32 = 5;

    pub fn new(id: EntryId, address: Address, value_type: ValueType, value: Value, interval_ms: u32) -> Self {
        Self {
            id,
            address,
            value_type,
            value,
            interval_ms,
            failure_count: 0,
            max_failures: Self::DEFAULT_MAX_FAILURES,
        }
    }

    pub fn record_failure(&mut self) -> bool {
        self.failure_count += 1;
        self.failure_count >= self.max_failures
    }

    pub fn reset_failures(&mut self) {
        self.failure_count = 0;
    }
}

/// Thread-safe session wrapper
pub type SharedSession = Arc<RwLock<Session>>;

pub fn new_shared_session() -> SharedSession {
    Arc::new(RwLock::new(Session::new()))
}
