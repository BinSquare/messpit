//! Messpit Engine Core
//!
//! This crate provides:
//! - Command routing and dispatch
//! - Memory scanning engine
//! - Watch and freeze management
//! - Session state management
//! - Project persistence
//! - Pattern/signature scanning

mod project;
pub mod pattern;
mod router;
pub mod scan;
pub mod session;
mod transport;
mod watch;

pub use project::*;
pub use pattern::*;
pub use router::*;
pub use scan::*;
pub use session::*;
pub use transport::*;
pub use watch::*;
