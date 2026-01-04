//! Frontend communication types
//!
//! Request and response types for Tauri commands.

use serde::{Deserialize, Serialize};

// ============================================================================
// Process Types
// ============================================================================

/// Process info returned to frontend
#[derive(Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub attachable: bool,
}

/// Request to filter process list server-side
#[derive(Deserialize)]
pub struct ProcessListRequest {
    pub filter: Option<String>,
    pub show_only_attachable: bool,
    pub pinned_pids: Vec<u32>,
    pub limit: Option<usize>,
    pub include_paths: bool,
}

/// Process list response with total count
#[derive(Serialize)]
pub struct ProcessListResponse {
    pub processes: Vec<ProcessInfo>,
    pub total: usize,
}

/// Attach result returned to frontend
#[derive(Serialize)]
pub struct AttachResult {
    pub pid: u32,
    pub name: String,
    pub arch: String,
}

/// Region info returned to frontend
#[derive(Serialize)]
pub struct RegionInfo {
    pub start: String,
    pub end: String,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub module: Option<String>,
}

// ============================================================================
// Scan Types
// ============================================================================

/// Scan result returned to frontend
#[derive(Serialize)]
pub struct ScanResult {
    pub address: String,
    pub value: String,
}

/// Scan parameters from frontend
#[derive(Deserialize)]
pub struct ScanRequest {
    pub value_type: String,
    pub comparison: String,
    pub value: String,
}

/// Refinement parameters from frontend
#[derive(Deserialize)]
pub struct RefineRequest {
    pub mode: String,
    pub value: Option<String>,
}

// ============================================================================
// Watch Types
// ============================================================================

/// Watch entry returned to frontend
#[derive(Serialize)]
pub struct WatchInfo {
    pub id: String,
    pub address: String,
    pub value_type: String,
    pub label: String,
    pub value: Option<String>,
    pub frozen: bool,
    pub freeze_value: Option<String>,
}

/// Add watch request from frontend
#[derive(Deserialize)]
pub struct AddWatchRequest {
    pub address: String,
    pub value_type: String,
    pub label: String,
}

/// Freeze request from frontend
#[derive(Deserialize)]
pub struct FreezeRequest {
    pub entry_id: String,
    pub value: String,
}

// ============================================================================
// Memory Types
// ============================================================================

/// Write value request from frontend
#[derive(Deserialize)]
pub struct WriteValueRequest {
    pub address: String,
    pub value_type: String,
    pub value: String,
}

/// Read value request from frontend
#[derive(Deserialize)]
pub struct ReadValueRequest {
    pub address: String,
    pub value_type: String,
}

// ============================================================================
// Project Types
// ============================================================================

/// Project info returned to frontend
#[derive(Serialize)]
pub struct ProjectInfo {
    pub name: String,
    pub path: Option<String>,
    pub watch_count: usize,
    pub has_unsaved_changes: bool,
}

// ============================================================================
// Script Types
// ============================================================================

/// Script run result
#[derive(Serialize)]
pub struct ScriptRunResult {
    pub run_id: String,
}

/// Script output result
#[derive(Serialize)]
pub struct ScriptOutputResult {
    pub lines: Vec<String>,
    pub finished: bool,
    pub error: Option<String>,
}

/// Saved script info
#[derive(Serialize, Clone)]
pub struct ScriptInfo {
    pub id: String,
    pub name: String,
    pub source: String,
    pub enabled: bool,
}

// ============================================================================
// Pattern Scanning Types
// ============================================================================

/// Pattern scan request from frontend
#[derive(Deserialize)]
pub struct PatternScanRequest {
    pub pattern: String,
    pub module: Option<String>,
    #[serde(default = "default_true")]
    pub use_simd: bool,
}

fn default_true() -> bool {
    true
}

/// Pattern scan result for frontend
#[derive(Serialize)]
pub struct PatternScanResult {
    pub address: String,
    pub module: Option<String>,
    pub module_offset: Option<String>,
}

/// Signature info for frontend
#[derive(Serialize)]
pub struct SignatureInfo {
    pub id: String,
    pub label: String,
    pub pattern: String,
    pub module: String,
    pub offset: i64,
    pub value_type: String,
    pub resolved_address: Option<String>,
}

/// Add signature request
#[derive(Deserialize)]
pub struct AddSignatureRequest {
    pub label: String,
    pub pattern: String,
    pub module: String,
    pub offset: i64,
    pub value_type: String,
}

// ============================================================================
// Pointer Scanning Types
// ============================================================================

/// Pointer scan request from frontend
#[derive(Deserialize)]
pub struct PointerScanRequest {
    /// Target address to find pointers to
    pub target_address: String,
    /// Maximum pointer chain depth (1-7)
    pub max_depth: Option<usize>,
    /// Maximum offset from pointer (default 0x1000)
    pub max_offset: Option<u64>,
    /// Maximum number of results
    pub max_results: Option<usize>,
}

/// Pointer scan result for frontend
#[derive(Serialize)]
pub struct PointerScanResultItem {
    /// Human-readable chain like "[module.exe+0x1234]+0x20+0x8"
    pub chain: String,
    /// Module name if chain starts from a module
    pub module: Option<String>,
    /// Offset from module base
    pub module_offset: String,
    /// List of offsets in the chain
    pub offsets: Vec<String>,
}

/// Resolve chain request
#[derive(Deserialize)]
pub struct ResolveChainRequest {
    /// Module name (optional)
    pub module: Option<String>,
    /// Offset from module base
    pub module_offset: String,
    /// List of offsets to follow
    pub offsets: Vec<String>,
}

// ============================================================================
// Cheat Table Types
// ============================================================================

/// Cheat table export request
#[derive(Deserialize)]
pub struct ExportCheatTableRequest {
    /// Table name
    pub name: String,
    /// Author (optional)
    pub author: Option<String>,
    /// Description (optional)
    pub description: Option<String>,
    /// Which entries to export (entry IDs), or all if empty
    pub entry_ids: Option<Vec<String>>,
}

/// Cheat table entry for frontend display
#[derive(Serialize)]
pub struct CheatTableEntryInfo {
    pub id: String,
    pub label: String,
    pub group: Option<String>,
    pub value_type: String,
    pub locator: String,
    pub locator_kind: String,
    pub frozen: bool,
    pub description: Option<String>,
}

/// Cheat table info for frontend
#[derive(Serialize)]
pub struct CheatTableInfo {
    pub name: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub process_name: String,
    pub entry_count: usize,
    pub created: String,
    pub modified: String,
    pub entries: Vec<CheatTableEntryInfo>,
}

/// Import cheat table request
#[derive(Deserialize)]
pub struct ImportCheatTableRequest {
    /// Cheat table JSON
    pub json: String,
    /// Which entries to import (IDs), or all if empty
    pub entry_ids: Option<Vec<String>>,
    /// Whether to resolve pointer chains and signatures
    pub resolve: bool,
}
