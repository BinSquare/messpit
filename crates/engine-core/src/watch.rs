//! Watch and freeze subsystem
//!
//! - Watch: Periodic polling of memory addresses with batched reads
//! - Freeze: Write-on-interval to maintain values

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use messpit_protocol::{Address, EntryId, Value};

use crate::scan::{decode_at, encode_value};
use crate::session::SharedSession;

/// Helper trait for RwLock error recovery
trait RwLockExt<T> {
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T>;
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|poisoned| {
            tracing::warn!("Recovered from poisoned RwLock (read)");
            poisoned.into_inner()
        })
    }

    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|poisoned| {
            tracing::warn!("Recovered from poisoned RwLock (write)");
            poisoned.into_inner()
        })
    }
}

/// Configuration for the watch/freeze subsystem
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Interval between watch polls (ms)
    pub watch_interval_ms: u64,
    /// Default freeze interval (ms)
    pub default_freeze_interval_ms: u32,
    /// Maximum consecutive failures before auto-disable
    pub max_freeze_failures: u32,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            watch_interval_ms: 100,
            default_freeze_interval_ms: 10,
            max_freeze_failures: 5,
        }
    }
}

/// Watch/freeze subsystem manager
pub struct WatchManager {
    config: WatchConfig,
    session: SharedSession,
    running: Arc<AtomicBool>,
    /// Last update times for freeze entries
    freeze_timers: Arc<RwLock<std::collections::HashMap<EntryId, Instant>>>,
}

impl WatchManager {
    pub fn new(session: SharedSession, config: WatchConfig) -> Self {
        Self {
            config,
            session,
            running: Arc::new(AtomicBool::new(false)),
            freeze_timers: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Start the watch/freeze loop in a background thread
    pub fn start(&self) -> WatchHandle {
        let running = self.running.clone();
        let session = self.session.clone();
        let config = self.config.clone();
        let freeze_timers = self.freeze_timers.clone();

        running.store(true, Ordering::SeqCst);

        let handle = std::thread::spawn(move || {
            Self::run_loop(running, session, config, freeze_timers);
        });

        WatchHandle {
            running: self.running.clone(),
            thread: Some(handle),
        }
    }

    fn run_loop(
        running: Arc<AtomicBool>,
        session: SharedSession,
        config: WatchConfig,
        freeze_timers: Arc<RwLock<std::collections::HashMap<EntryId, Instant>>>,
    ) {
        let watch_interval = Duration::from_millis(config.watch_interval_ms);

        while running.load(Ordering::SeqCst) {
            let start = Instant::now();

            // Process watches and freezes
            if let Ok(mut sess) = session.write() {
                // First, collect all watch info we need
                let watch_info: Vec<_> = sess
                    .watches()
                    .map(|w| (w.id, w.address, w.value_type))
                    .collect();

                // Collect freeze info
                let freeze_info: Vec<_> = if sess.is_freeze_enabled() {
                    sess.freezes()
                        .map(|f| (f.id, f.address, f.value.clone(), f.interval_ms))
                        .collect()
                } else {
                    vec![]
                };

                // Now read from process (immutable borrow)
                if let Some(process) = sess.process() {
                    // Read watch values
                    let mut updates = Vec::new();
                    for (id, address, value_type) in &watch_info {
                        let size = value_type.size().unwrap_or(256);
                        let mut buffer = vec![0u8; size];
                        if process.read_memory(*address, &mut buffer).is_ok() {
                            if let Some(value) = decode_at(&buffer, value_type) {
                                updates.push((*id, value));
                            }
                        }
                    }

                    // Process freezes
                    let now = Instant::now();
                    let mut timers = freeze_timers.write_or_recover();
                    let mut to_disable = Vec::new();

                    for (id, address, value, interval_ms) in &freeze_info {
                        let interval = Duration::from_millis(*interval_ms as u64);
                        let last = timers.get(id).copied().unwrap_or(now - interval);

                        if now.duration_since(last) >= interval {
                            let bytes = encode_value(value);
                            if process.write_memory(*address, &bytes).is_err() {
                                to_disable.push(*id);
                            }
                            timers.insert(*id, now);
                        }
                    }

                    // Process borrow ends here, now we can mutate session
                    let _ = process;

                    // Apply watch updates
                    for (id, value) in updates {
                        if let Some(watch) = sess.watches.get_mut(&id) {
                            watch.last_value = Some(value);
                        }
                    }

                    // Handle freeze failures
                    for id in to_disable {
                        if let Some(freeze) = sess.freezes.get_mut(&id) {
                            if freeze.record_failure() {
                                tracing::warn!(entry_id = ?id, "Freeze auto-disabled after too many failures");
                            }
                        }
                    }
                }
            }

            // Sleep for remaining interval
            let elapsed = start.elapsed();
            if elapsed < watch_interval {
                std::thread::sleep(watch_interval - elapsed);
            }
        }
    }

    /// Get current watch values
    pub fn get_watch_updates(&self) -> Vec<WatchUpdate> {
        let session = self.session.read_or_recover();
        session
            .watches()
            .map(|w| WatchUpdate {
                entry_id: w.id,
                address: w.address,
                value: w.last_value.clone(),
                frozen: session.freezes.contains_key(&w.id),
            })
            .collect()
    }
}

/// Handle for stopping the watch loop
pub struct WatchHandle {
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WatchHandle {
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Watch update for UI
#[derive(Debug, Clone)]
pub struct WatchUpdate {
    pub entry_id: EntryId,
    pub address: Address,
    pub value: Option<Value>,
    pub frozen: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn test_watch_config_default() {
        let config = WatchConfig::default();
        assert_eq!(config.watch_interval_ms, 100);
        assert_eq!(config.default_freeze_interval_ms, 10);
        assert_eq!(config.max_freeze_failures, 5);
    }
}
