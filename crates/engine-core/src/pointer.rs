//! Pointer scanning - find pointer chains from static addresses to a target
//!
//! Pointer scanning is used to find reliable paths to dynamic memory addresses.
//! Since dynamic allocations change between runs, but static pointers in modules
//! remain constant, finding a pointer chain like:
//!   [game.exe+0x1234] + 0x20 + 0x8 -> target
//! allows reliably finding the target address even after restart.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use messpit_platform::ProcessHandle;
use messpit_protocol::{Address, Module, Region};

/// Read a pointer value from a byte slice (little-endian)
///
/// Returns the pointer as u64, handling both 32-bit and 64-bit pointers.
#[inline]
fn read_pointer(bytes: &[u8], pointer_size: usize) -> u64 {
    if pointer_size == 8 && bytes.len() >= 8 {
        u64::from_le_bytes(bytes[..8].try_into().expect("length checked"))
    } else if bytes.len() >= 4 {
        u64::from(u32::from_le_bytes(
            bytes[..4].try_into().expect("length checked"),
        ))
    } else {
        0
    }
}

/// Configuration for pointer scanning
#[derive(Debug, Clone)]
pub struct PointerScanConfig {
    /// Maximum depth of pointer chain (e.g., 5 means up to 5 dereferences)
    pub max_depth: usize,
    /// Maximum offset from a pointer to consider (e.g., 0x1000)
    pub max_offset: u64,
    /// Maximum number of results to return
    pub max_results: usize,
    /// Only consider aligned pointers (recommended for performance)
    pub aligned_only: bool,
    /// Pointer size (4 for 32-bit, 8 for 64-bit)
    pub pointer_size: usize,
    /// Only start chains from module bases (static addresses)
    pub static_base_only: bool,
}

impl Default for PointerScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_offset: 0x1000,
            max_results: 1000,
            aligned_only: true,
            pointer_size: 8, // 64-bit default
            static_base_only: true,
        }
    }
}

/// A single step in a pointer chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerStep {
    /// Base address (either module base or dereferenced pointer)
    pub base: Address,
    /// Offset added after dereferencing
    pub offset: i64,
}

/// A complete pointer chain from a static address to the target
#[derive(Debug, Clone)]
pub struct PointerChain {
    /// Module name (if chain starts from a module)
    pub module: Option<String>,
    /// Offset from module base
    pub module_offset: u64,
    /// Chain of offsets to follow
    pub offsets: Vec<i64>,
    /// Final resolved address (should match target)
    pub resolved: Address,
}

impl PointerChain {
    /// Format as a human-readable string like "[module.exe+0x1234]+0x20+0x8"
    pub fn format(&self) -> String {
        let mut result = if let Some(ref module) = self.module {
            format!("[{}+0x{:X}]", module, self.module_offset)
        } else {
            format!("[0x{:X}]", self.module_offset)
        };

        for offset in &self.offsets {
            if *offset >= 0 {
                result.push_str(&format!("+0x{:X}", offset));
            } else {
                result.push_str(&format!("-0x{:X}", offset.unsigned_abs()));
            }
        }

        result
    }
}

/// Result of a pointer scan
#[derive(Debug)]
pub struct PointerScanResult {
    /// Target address that was scanned for
    pub target: Address,
    /// Found pointer chains
    pub chains: Vec<PointerChain>,
    /// Whether the scan was cancelled
    pub cancelled: bool,
    /// Number of pointers scanned
    pub pointers_scanned: usize,
}

/// Pointer scanner
pub struct PointerScanner {
    config: PointerScanConfig,
    cancelled: Arc<AtomicBool>,
}

impl PointerScanner {
    pub fn new(config: PointerScanConfig) -> Self {
        Self {
            config,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get a handle to cancel the scan
    pub fn cancellation_handle(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }

    /// Cancel the scan
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Perform a pointer scan to find chains leading to the target address
    pub fn scan(
        &self,
        process: &dyn ProcessHandle,
        target: Address,
        regions: &[Region],
        modules: &[Module],
    ) -> PointerScanResult {
        let mut result = PointerScanResult {
            target,
            chains: Vec::new(),
            cancelled: false,
            pointers_scanned: 0,
        };

        // Step 1: Build a reverse pointer map
        // Maps: target_address -> Vec<(pointer_location, offset)>
        // This tells us "which addresses point to target_address (with some offset)"
        let pointer_map = self.build_pointer_map(process, target, regions, &mut result);

        if self.cancelled.load(Ordering::SeqCst) {
            result.cancelled = true;
            return result;
        }

        // Step 2: Find static bases (module addresses)
        let static_bases: HashSet<Address> = if self.config.static_base_only {
            modules.iter().map(|m| m.base).collect()
        } else {
            // Use all readable region bases as potential static addresses
            regions
                .iter()
                .filter(|r| r.permissions.read)
                .map(|r| r.base)
                .collect()
        };

        // Step 3: BFS from target backwards through pointer map to find chains to static bases
        result.chains = self.find_chains_bfs(target, &pointer_map, &static_bases, modules);

        result
    }

    /// Build a reverse pointer map by scanning all memory for pointers
    fn build_pointer_map(
        &self,
        process: &dyn ProcessHandle,
        target: Address,
        regions: &[Region],
        result: &mut PointerScanResult,
    ) -> HashMap<Address, Vec<(Address, i64)>> {
        let mut pointer_map: HashMap<Address, Vec<(Address, i64)>> = HashMap::new();
        let ptr_size = self.config.pointer_size;
        let alignment = if self.config.aligned_only { ptr_size } else { 1 };

        // We're looking for pointers that point to addresses within max_offset of our target
        // and also building a general map for multi-level resolution
        let target_range_start = target.0.saturating_sub(self.config.max_offset);
        let target_range_end = target.0.saturating_add(self.config.max_offset);

        for region in regions {
            if self.cancelled.load(Ordering::SeqCst) {
                return pointer_map;
            }

            // Only scan readable regions
            if !region.permissions.read {
                continue;
            }

            // Skip very large regions to avoid memory issues
            if region.size > 256 * 1024 * 1024 {
                tracing::debug!(
                    "Skipping large region at 0x{:X} ({}MB)",
                    region.base.0,
                    region.size / (1024 * 1024)
                );
                continue;
            }

            // Read the entire region
            let mut buffer = vec![0u8; region.size as usize];
            if process.read_memory(region.base, &mut buffer).is_err() {
                continue;
            }

            // Scan for pointers
            let mut offset = 0usize;
            while offset + ptr_size <= buffer.len() {
                let ptr_value = read_pointer(&buffer[offset..], ptr_size);

                // Check if this pointer points to something in our target range
                if ptr_value >= target_range_start && ptr_value <= target_range_end {
                    let pointer_addr = Address(region.base.0 + offset as u64);
                    let pointed_to = Address(ptr_value);
                    let diff = target.0 as i64 - ptr_value as i64;

                    pointer_map
                        .entry(pointed_to)
                        .or_default()
                        .push((pointer_addr, diff));

                    result.pointers_scanned += 1;
                }

                // Also track pointers that could be part of a chain (pointing to valid memory)
                // We'll need this for multi-level pointer resolution
                if self.config.max_depth > 1 && self.is_valid_pointer(ptr_value, regions) {
                    let pointer_addr = Address(region.base.0 + offset as u64);
                    let pointed_to = Address(ptr_value);

                    // For chain building, we store with offset 0
                    // The actual offset is calculated during chain resolution
                    pointer_map
                        .entry(pointed_to)
                        .or_default()
                        .push((pointer_addr, 0));
                }

                offset += alignment;
            }
        }

        pointer_map
    }

    /// Check if a pointer value points to valid memory
    fn is_valid_pointer(&self, value: u64, regions: &[Region]) -> bool {
        regions
            .iter()
            .any(|r| value >= r.base.0 && value < r.base.0 + r.size)
    }

    /// Find chains from static bases to target using BFS
    fn find_chains_bfs(
        &self,
        target: Address,
        pointer_map: &HashMap<Address, Vec<(Address, i64)>>,
        _static_bases: &HashSet<Address>,
        modules: &[Module],
    ) -> Vec<PointerChain> {
        let mut chains = Vec::new();
        let mut visited: HashSet<Address> = HashSet::new();

        // BFS queue: (current_address, path_so_far)
        // path_so_far is Vec<(pointer_addr, offset_to_add)>
        let mut queue: VecDeque<(Address, Vec<(Address, i64)>)> = VecDeque::new();

        // Start from target and work backwards
        queue.push_back((target, vec![]));
        visited.insert(target);

        while let Some((current, path)) = queue.pop_front() {
            if self.cancelled.load(Ordering::SeqCst) {
                break;
            }

            if chains.len() >= self.config.max_results {
                break;
            }

            if path.len() >= self.config.max_depth {
                continue;
            }

            // Look for pointers that point to current address (with offset)
            // We need to check addresses within max_offset of current
            for offset in (-(self.config.max_offset as i64)..=self.config.max_offset as i64)
                .step_by(if self.config.aligned_only { self.config.pointer_size } else { 1 })
            {
                let check_addr = Address((current.0 as i64 + offset) as u64);

                if let Some(pointers) = pointer_map.get(&check_addr) {
                    for (ptr_addr, _) in pointers {
                        if visited.contains(ptr_addr) {
                            continue;
                        }

                        // Check if this pointer is in a static base (module)
                        let module_info = self.find_module_for_address(*ptr_addr, modules);

                        if let Some((module, module_offset)) = module_info {
                            // Found a complete chain!
                            let mut offsets: Vec<i64> = path.iter().rev().map(|(_, o)| *o).collect();
                            offsets.push(-offset); // Offset to get from pointed address to current

                            chains.push(PointerChain {
                                module: Some(module),
                                module_offset,
                                offsets,
                                resolved: target,
                            });

                            if chains.len() >= self.config.max_results {
                                return chains;
                            }
                        } else if path.len() + 1 < self.config.max_depth {
                            // Continue searching deeper
                            let mut new_path = path.clone();
                            new_path.push((*ptr_addr, -offset));
                            visited.insert(*ptr_addr);
                            queue.push_back((*ptr_addr, new_path));
                        }
                    }
                }
            }
        }

        chains
    }

    /// Find which module an address belongs to
    fn find_module_for_address(&self, addr: Address, modules: &[Module]) -> Option<(String, u64)> {
        for module in modules {
            let end = module.base.0 + module.size;
            if addr.0 >= module.base.0 && addr.0 < end {
                return Some((module.name.clone(), addr.0 - module.base.0));
            }
        }
        None
    }
}

/// Resolve a pointer chain to get the current address
pub fn resolve_chain(
    process: &dyn ProcessHandle,
    chain: &PointerChain,
    modules: &[Module],
    pointer_size: usize,
) -> Option<Address> {
    // Find module base
    let base = if let Some(ref module_name) = chain.module {
        modules
            .iter()
            .find(|m| m.name == *module_name)
            .map(|m| m.base.0)?
    } else {
        0
    };

    let mut current = base + chain.module_offset;

    // Follow the chain
    for offset in &chain.offsets {
        // Read pointer at current address
        let mut buffer = vec![0u8; pointer_size];
        if process.read_memory(Address(current), &mut buffer).is_err() {
            return None;
        }

        let ptr_value = read_pointer(&buffer, pointer_size);

        // Apply offset to get next address
        current = (ptr_value as i64 + offset) as u64;
    }

    Some(Address(current))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_chain_format() {
        let chain = PointerChain {
            module: Some("game.exe".to_string()),
            module_offset: 0x1234,
            offsets: vec![0x20, 0x8, -0x10],
            resolved: Address(0xDEADBEEF),
        };

        let formatted = chain.format();
        assert_eq!(formatted, "[game.exe+0x1234]+0x20+0x8-0x10");
    }

    #[test]
    fn test_pointer_chain_format_no_module() {
        let chain = PointerChain {
            module: None,
            module_offset: 0x400000,
            offsets: vec![0x100],
            resolved: Address(0x12345678),
        };

        let formatted = chain.format();
        assert_eq!(formatted, "[0x400000]+0x100");
    }

    #[test]
    fn test_config_default() {
        let config = PointerScanConfig::default();
        assert_eq!(config.max_depth, 5);
        assert_eq!(config.max_offset, 0x1000);
        assert_eq!(config.pointer_size, 8);
        assert!(config.aligned_only);
    }

    #[test]
    fn test_read_pointer_64bit() {
        // Little-endian 64-bit pointer: 0x0000000012345678
        let bytes = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let value = read_pointer(&bytes, 8);
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_read_pointer_32bit() {
        // Little-endian 32-bit pointer: 0xDEADBEEF
        let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
        let value = read_pointer(&bytes, 4);
        assert_eq!(value, 0xDEADBEEF);
    }

    #[test]
    fn test_read_pointer_insufficient_bytes() {
        // Not enough bytes returns 0
        let bytes = [0x12, 0x34];
        let value = read_pointer(&bytes, 8);
        // Falls back to 32-bit read with padding
        assert_eq!(value, 0);
    }

    #[test]
    fn test_pointer_chain_with_zero_offsets() {
        let chain = PointerChain {
            module: Some("test.dll".to_string()),
            module_offset: 0x1000,
            offsets: vec![0x0],
            resolved: Address(0x5000),
        };
        assert_eq!(chain.format(), "[test.dll+0x1000]+0x0");
    }

    #[test]
    fn test_config_custom() {
        let config = PointerScanConfig {
            max_depth: 3,
            max_offset: 0x500,
            max_results: 100,
            aligned_only: false,
            pointer_size: 4,
            static_base_only: false,
        };
        assert_eq!(config.max_depth, 3);
        assert_eq!(config.max_offset, 0x500);
        assert_eq!(config.pointer_size, 4);
        assert!(!config.aligned_only);
    }
}
