//! Messpit Protocol
//!
//! Defines the command/event types for communication between UI and engine.
//! This crate is the source of truth for all IPC messages.

mod commands;
mod events;
mod types;

pub use commands::*;
pub use events::*;
pub use types::*;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;
