//! Messpit Policy Engine
//!
//! Provides policy gating for operations and audit logging.
//!
//! Default posture: offline-first, deny risky targets by default.

use messpit_protocol::{Address, Pid, PolicyDenialReason};

/// Policy decision result
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    Deny(PolicyDenialReason),
}

/// Policy engine configuration and state
pub struct Policy {
    /// Deny list of process names (case-insensitive)
    deny_process_names: Vec<String>,
    /// Deny list of PIDs
    deny_pids: Vec<u32>,
    /// Allow writes to any address (if false, only specific ranges allowed)
    allow_arbitrary_writes: bool,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            deny_process_names: default_deny_list(),
            deny_pids: vec![],
            // Default to false for safety; users must explicitly enable writes
            allow_arbitrary_writes: false,
        }
    }

    /// Create a policy that allows writes (for trainer use case)
    pub fn permissive() -> Self {
        Self {
            deny_process_names: default_deny_list(),
            deny_pids: vec![],
            allow_arbitrary_writes: true,
        }
    }

    /// Enable or disable arbitrary writes
    pub fn set_allow_writes(&mut self, allow: bool) {
        self.allow_arbitrary_writes = allow;
    }

    /// Check if attaching to a process is allowed
    pub fn check_attach(&self, pid: Pid) -> PolicyDecision {
        // Check explicit PID deny list
        if self.deny_pids.contains(&pid.0) {
            return PolicyDecision::Deny(PolicyDenialReason {
                code: "pid_denied".into(),
                message: format!("Process {} is on the deny list", pid.0),
                suggestion: Some("Remove from deny list in settings".into()),
            });
        }

        // PID 0 and 1 are always system processes
        if pid.0 <= 1 {
            return PolicyDecision::Deny(PolicyDenialReason {
                code: "system_process".into(),
                message: "Cannot attach to system processes (PID 0 or 1)".into(),
                suggestion: None,
            });
        }

        // Check self-attach (allowed for testing)
        let my_pid = std::process::id();
        if pid.0 == my_pid {
            // Allow self-attach but log it
            tracing::info!("Self-attach requested (PID {})", pid.0);
        }

        PolicyDecision::Allow
    }

    /// Check if attaching to a named process is allowed
    pub fn check_attach_by_name(&self, name: &str) -> PolicyDecision {
        let name_lower = name.to_lowercase();

        for denied in &self.deny_process_names {
            if name_lower.contains(&denied.to_lowercase()) {
                return PolicyDecision::Deny(PolicyDenialReason {
                    code: "process_denied".into(),
                    message: format!(
                        "Process '{}' matches deny pattern '{}'",
                        name, denied
                    ),
                    suggestion: Some(
                        "This appears to be a system/protected process. \
                         If you're sure, remove from deny list in settings."
                            .into(),
                    ),
                });
            }
        }

        PolicyDecision::Allow
    }

    /// Check if a write operation is allowed
    pub fn check_write(&self, _address: Address, _reason: &str) -> PolicyDecision {
        if !self.allow_arbitrary_writes {
            return PolicyDecision::Deny(PolicyDenialReason {
                code: "writes_disabled".into(),
                message: "Arbitrary writes are disabled in policy settings".into(),
                suggestion: Some("Enable writes in settings or add address to allow list".into()),
            });
        }

        PolicyDecision::Allow
    }

    /// Check if running a script is allowed
    pub fn check_script(&self, _source: &str) -> PolicyDecision {
        // Scripts are sandboxed, so generally allowed
        // Could add content-based filtering later
        PolicyDecision::Allow
    }

    /// Add a process name to the deny list
    pub fn deny_process(&mut self, name: String) {
        if !self.deny_process_names.contains(&name) {
            self.deny_process_names.push(name);
        }
    }

    /// Remove a process name from the deny list
    pub fn allow_process(&mut self, name: &str) {
        self.deny_process_names.retain(|n| n != name);
    }

    /// Add a PID to the deny list
    pub fn deny_pid(&mut self, pid: u32) {
        if !self.deny_pids.contains(&pid) {
            self.deny_pids.push(pid);
        }
    }

    /// Remove a PID from the deny list
    pub fn allow_pid(&mut self, pid: u32) {
        self.deny_pids.retain(|&p| p != pid);
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// Default list of processes to deny attachment
fn default_deny_list() -> Vec<String> {
    vec![
        // System processes
        "kernel".into(),
        "launchd".into(),
        "init".into(),
        "systemd".into(),
        "csrss".into(),
        "smss".into(),
        "wininit".into(),
        "services".into(),
        "lsass".into(),
        "winlogon".into(),
        // Security software (no bypass attempt)
        "eac".into(),
        "battleye".into(),
        "vanguard".into(),
        "faceit".into(),
        // Our own process
        "messpit".into(),
    ]
}

/// Audit log for recording operations
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    max_entries: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub operation: String,
    pub target_pid: Option<u32>,
    pub address: Option<u64>,
    pub details: Option<String>,
    pub allowed: bool,
}

impl AuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    pub fn record(&mut self, entry: AuditEntry) {
        tracing::debug!(
            operation = %entry.operation,
            pid = ?entry.target_pid,
            addr = ?entry.address.map(|a| format!("0x{:X}", a)),
            allowed = entry.allowed,
            "Audit"
        );

        self.entries.push(entry);

        // Rotate if needed
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Export to JSON lines format
    pub fn export_jsonl(&self) -> String {
        self.entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_system_processes() {
        let policy = Policy::default();

        // PID 0 should be denied
        match policy.check_attach(Pid(0)) {
            PolicyDecision::Deny(_) => {}
            PolicyDecision::Allow => panic!("Should deny PID 0"),
        }

        // PID 1 should be denied
        match policy.check_attach(Pid(1)) {
            PolicyDecision::Deny(_) => {}
            PolicyDecision::Allow => panic!("Should deny PID 1"),
        }

        // Regular PID should be allowed
        match policy.check_attach(Pid(12345)) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(r) => panic!("Should allow regular PID: {}", r.message),
        }
    }

    #[test]
    fn deny_by_name() {
        let policy = Policy::default();

        // System process should be denied
        match policy.check_attach_by_name("launchd") {
            PolicyDecision::Deny(_) => {}
            PolicyDecision::Allow => panic!("Should deny launchd"),
        }

        // Game should be allowed
        match policy.check_attach_by_name("game.exe") {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(r) => panic!("Should allow game.exe: {}", r.message),
        }
    }
}
