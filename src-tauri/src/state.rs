//! Lock extension traits for graceful error handling.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Helper trait for handling mutex lock errors gracefully
pub trait MutexExt<T> {
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
        self.lock()
            .map_err(|_| "Internal error: mutex was poisoned".to_string())
    }
}

/// Helper trait for handling RwLock errors gracefully
pub trait RwLockExt<T> {
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
        self.read()
            .map_err(|_| "Internal error: RwLock was poisoned".to_string())
    }

    fn write_checked(&self) -> Result<RwLockWriteGuard<'_, T>, String> {
        self.write()
            .map_err(|_| "Internal error: RwLock was poisoned".to_string())
    }
}
