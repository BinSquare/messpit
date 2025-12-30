//! Pattern scanning for memory signatures
//!
//! Supports IDA-style patterns like `48 8B ?? 00` where `??` is a wildcard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use messpit_platform::ProcessHandle;
use messpit_protocol::{Address, Module, Region};

/// Maximum pattern length in bytes (prevents DoS via huge patterns)
const MAX_PATTERN_LENGTH: usize = 256;

/// A compiled pattern for memory scanning
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Pattern bytes (None = wildcard)
    bytes: Vec<Option<u8>>,
    /// First non-wildcard byte index and value for quick filtering
    first_fixed: Option<(usize, u8)>,
    /// Pattern length
    len: usize,
}

impl Pattern {
    /// Create a pattern from a vector of optional bytes
    pub fn new(bytes: Vec<Option<u8>>) -> Self {
        let len = bytes.len();
        let first_fixed = bytes
            .iter()
            .enumerate()
            .find_map(|(i, b)| b.map(|v| (i, v)));

        Self {
            bytes,
            first_fixed,
            len,
        }
    }

    /// Parse an IDA-style pattern string
    ///
    /// Format: `48 8B ?? 00` or `48 8B ? 00` or `48 8B * 00`
    /// Wildcards: `??`, `?`, `*`, `xx`, `XX`
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();

        for token in pattern.split_whitespace() {
            match token.to_lowercase().as_str() {
                "??" | "?" | "*" | "xx" => {
                    bytes.push(None);
                }
                hex if hex.len() == 2 => {
                    let byte = u8::from_str_radix(hex, 16)
                        .map_err(|_| PatternError::InvalidHexByte(token.to_string()))?;
                    bytes.push(Some(byte));
                }
                _ => {
                    return Err(PatternError::InvalidToken(token.to_string()));
                }
            }
        }

        if bytes.is_empty() {
            return Err(PatternError::EmptyPattern);
        }

        // Check pattern length limit
        if bytes.len() > MAX_PATTERN_LENGTH {
            return Err(PatternError::PatternTooLong);
        }

        // Check for all-wildcard pattern
        if bytes.iter().all(|b| b.is_none()) {
            return Err(PatternError::AllWildcard);
        }

        Ok(Self::new(bytes))
    }

    /// Pattern length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if pattern is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the pattern bytes
    pub fn bytes(&self) -> &[Option<u8>] {
        &self.bytes
    }

    /// Check if the pattern matches at the given position in data
    #[inline]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.len > data.len() {
            return false;
        }

        // Quick check with first fixed byte
        if let Some((idx, val)) = self.first_fixed {
            if data[offset + idx] != val {
                return false;
            }
        }

        // Full pattern check
        for (i, pattern_byte) in self.bytes.iter().enumerate() {
            if let Some(expected) = pattern_byte {
                if data[offset + i] != *expected {
                    return false;
                }
            }
        }

        true
    }
}

/// Errors that can occur during pattern parsing
#[derive(Debug, Clone, thiserror::Error)]
pub enum PatternError {
    #[error("Invalid hex byte: {0}")]
    InvalidHexByte(String),

    #[error("Invalid token in pattern: {0}")]
    InvalidToken(String),

    #[error("Empty pattern")]
    EmptyPattern,

    #[error("Pattern cannot be all wildcards")]
    AllWildcard,

    #[error("Pattern too long (max {MAX_PATTERN_LENGTH} bytes)")]
    PatternTooLong,
}

/// Result of a pattern scan
#[derive(Debug, Clone)]
pub struct PatternScanResult {
    pub address: Address,
    pub module: Option<String>,
    pub module_offset: Option<u64>,
}

/// Pattern scanner with multiple matching strategies
pub struct PatternScanner {
    pattern: Pattern,
    cancelled: Arc<AtomicBool>,
}

impl PatternScanner {
    /// Create a new pattern scanner
    pub fn new(pattern: Pattern) -> Self {
        Self {
            pattern,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get a cancellation handle
    pub fn cancellation_handle(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }

    /// Cancel the scan
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Scan a memory region using the baseline byte-by-byte matcher
    pub fn scan_region_baseline(
        &self,
        process: &dyn ProcessHandle,
        region: &Region,
        modules: &[Module],
    ) -> Vec<PatternScanResult> {
        let mut results = Vec::new();

        // Read the entire region into a buffer
        let mut data = vec![0u8; region.size as usize];
        let Ok(bytes_read) = process.read_memory(region.base, &mut data) else {
            return results;
        };

        // Truncate to actual bytes read
        data.truncate(bytes_read);

        // Scan through the data
        let end = data.len().saturating_sub(self.pattern.len());
        for offset in 0..=end {
            if self.cancelled.load(Ordering::Relaxed) {
                break;
            }

            if self.pattern.matches_at(&data, offset) {
                let address = Address(region.base.0 + offset as u64);
                let (module, module_offset) = find_module_for_address(address, modules);

                results.push(PatternScanResult {
                    address,
                    module,
                    module_offset,
                });
            }
        }

        results
    }

    /// Scan a memory region using SIMD acceleration (when available)
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn scan_region_simd(
        &self,
        process: &dyn ProcessHandle,
        region: &Region,
        modules: &[Module],
    ) -> Vec<PatternScanResult> {
        // Read the entire region into a buffer
        let mut data = vec![0u8; region.size as usize];
        let Ok(bytes_read) = process.read_memory(region.base, &mut data) else {
            return Vec::new();
        };

        // Truncate to actual bytes read
        data.truncate(bytes_read);

        let matches = self.find_matches_simd(&data);
        let mut results = Vec::with_capacity(matches.len());

        for offset in matches {
            let address = Address(region.base.0 + offset as u64);
            let (module, module_offset) = find_module_for_address(address, modules);

            results.push(PatternScanResult {
                address,
                module,
                module_offset,
            });
        }

        results
    }

    /// Find pattern matches using SIMD instructions
    #[cfg(target_arch = "x86_64")]
    fn find_matches_simd(&self, data: &[u8]) -> Vec<usize> {
        use std::arch::x86_64::*;

        // Runtime check for SSE2 support (should always be true on x86_64, but verify)
        // SAFETY: is_x86_feature_detected! is always safe to call
        if !is_x86_feature_detected!("sse2") {
            return self.find_matches_baseline(data);
        }

        let mut results = Vec::new();

        // Get the first non-wildcard byte for SIMD filtering
        let Some((first_idx, first_byte)) = self.pattern.first_fixed else {
            // Fall back to baseline for all-wildcard patterns (shouldn't happen)
            return self.find_matches_baseline(data);
        };

        // SSE2 is part of the x86_64 baseline specification
        let end = data.len().saturating_sub(self.pattern.len());
        if end == 0 {
            return results;
        }

        // Use SSE2 to find potential matches
        unsafe {
            let needle = _mm_set1_epi8(first_byte as i8);
            let mut i = 0;

            while i + 16 <= data.len() {
                if self.cancelled.load(Ordering::Relaxed) {
                    break;
                }

                // Load 16 bytes from data
                let chunk = _mm_loadu_si128(data[i..].as_ptr() as *const __m128i);

                // Compare with needle
                let cmp = _mm_cmpeq_epi8(chunk, needle);
                let mask = _mm_movemask_epi8(cmp) as u32;

                // Check each potential match
                if mask != 0 {
                    for bit in 0..16 {
                        if mask & (1 << bit) != 0 {
                            let potential_start = i + bit - first_idx;
                            if potential_start <= end && self.pattern.matches_at(data, potential_start) {
                                results.push(potential_start);
                            }
                        }
                    }
                }

                i += 16;
            }

            // Handle remaining bytes
            for offset in i.saturating_sub(first_idx)..=end {
                if self.cancelled.load(Ordering::Relaxed) {
                    break;
                }
                if self.pattern.matches_at(data, offset) {
                    if !results.contains(&offset) {
                        results.push(offset);
                    }
                }
            }
        }

        results.sort_unstable();
        results.dedup();
        results
    }

    /// Find pattern matches using SIMD instructions (ARM NEON)
    #[cfg(target_arch = "aarch64")]
    fn find_matches_simd(&self, data: &[u8]) -> Vec<usize> {
        use std::arch::aarch64::*;

        // Runtime check for NEON support (mandatory on AArch64, but verify)
        // SAFETY: is_aarch64_feature_detected! is always safe to call
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return self.find_matches_baseline(data);
        }

        let mut results = Vec::new();

        // Get the first non-wildcard byte for SIMD filtering
        let Some((first_idx, first_byte)) = self.pattern.first_fixed else {
            return self.find_matches_baseline(data);
        };

        // NEON is part of the AArch64 baseline specification
        let end = data.len().saturating_sub(self.pattern.len());
        if end == 0 {
            return results;
        }

        unsafe {
            let needle = vdupq_n_u8(first_byte);
            let mut i = 0;

            while i + 16 <= data.len() {
                if self.cancelled.load(Ordering::Relaxed) {
                    break;
                }

                // Load 16 bytes from data
                let chunk = vld1q_u8(data[i..].as_ptr());

                // Compare with needle
                let cmp = vceqq_u8(chunk, needle);

                // Get comparison results
                let high = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 1);
                let low = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 0);

                // Check each potential match
                if high != 0 || low != 0 {
                    for bit in 0..16 {
                        let byte_val = if bit < 8 {
                            (low >> (bit * 8)) & 0xFF
                        } else {
                            (high >> ((bit - 8) * 8)) & 0xFF
                        };

                        if byte_val == 0xFF {
                            let potential_start = (i + bit).saturating_sub(first_idx);
                            if potential_start <= end && self.pattern.matches_at(data, potential_start) {
                                results.push(potential_start);
                            }
                        }
                    }
                }

                i += 16;
            }

            // Handle remaining bytes
            for offset in i.saturating_sub(first_idx)..=end {
                if self.cancelled.load(Ordering::Relaxed) {
                    break;
                }
                if self.pattern.matches_at(data, offset)
                    && !results.contains(&offset) {
                        results.push(offset);
                    }
            }
        }

        results.sort_unstable();
        results.dedup();
        results
    }

    /// Baseline matcher (fallback)
    fn find_matches_baseline(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let end = data.len().saturating_sub(self.pattern.len());

        for offset in 0..=end {
            if self.cancelled.load(Ordering::Relaxed) {
                break;
            }
            if self.pattern.matches_at(data, offset) {
                results.push(offset);
            }
        }

        results
    }

    /// Scan multiple regions
    pub fn scan_regions(
        &self,
        process: &dyn ProcessHandle,
        regions: &[Region],
        modules: &[Module],
        use_simd: bool,
    ) -> Vec<PatternScanResult> {
        let mut all_results = Vec::new();

        for region in regions {
            if self.cancelled.load(Ordering::Relaxed) {
                break;
            }

            // Skip non-readable regions
            if !region.permissions.read {
                continue;
            }

            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            let results = if use_simd {
                self.scan_region_simd(process, region, modules)
            } else {
                self.scan_region_baseline(process, region, modules)
            };

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let results = self.scan_region_baseline(process, region, modules);

            all_results.extend(results);
        }

        all_results
    }
}

/// Find which module contains an address
fn find_module_for_address(address: Address, modules: &[Module]) -> (Option<String>, Option<u64>) {
    for module in modules {
        let module_end = module.base.0 + module.size;
        if address.0 >= module.base.0 && address.0 < module_end {
            let offset = address.0 - module.base.0;
            return (Some(module.name.clone()), Some(offset));
        }
    }
    (None, None)
}

/// Signature for persistence - a pattern with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Pattern string (IDA format)
    pub pattern: String,
    /// Expected module (for scoped scanning)
    pub module: Option<String>,
    /// Last known offset within module
    pub last_offset: Option<u64>,
    /// Description/notes
    pub description: Option<String>,
}

impl Signature {
    /// Create a new signature
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            pattern: pattern.into(),
            module: None,
            last_offset: None,
            description: None,
        }
    }

    /// Set the expected module
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Parse the pattern for scanning
    pub fn compile(&self) -> Result<Pattern, PatternError> {
        Pattern::parse(&self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_parse_simple() {
        let pattern = Pattern::parse("48 8B 05").unwrap();
        assert_eq!(pattern.len(), 3);
        assert_eq!(pattern.bytes(), &[Some(0x48), Some(0x8B), Some(0x05)]);
    }

    #[test]
    fn test_pattern_parse_with_wildcards() {
        let pattern = Pattern::parse("48 8B ?? 00").unwrap();
        assert_eq!(pattern.len(), 4);
        assert_eq!(
            pattern.bytes(),
            &[Some(0x48), Some(0x8B), None, Some(0x00)]
        );
    }

    #[test]
    fn test_pattern_parse_wildcard_variants() {
        // Test all wildcard formats
        let p1 = Pattern::parse("48 ??").unwrap();
        let p2 = Pattern::parse("48 ?").unwrap();
        let p3 = Pattern::parse("48 *").unwrap();
        let p4 = Pattern::parse("48 xx").unwrap();
        let p5 = Pattern::parse("48 XX").unwrap();

        assert_eq!(p1.bytes(), &[Some(0x48), None]);
        assert_eq!(p2.bytes(), &[Some(0x48), None]);
        assert_eq!(p3.bytes(), &[Some(0x48), None]);
        assert_eq!(p4.bytes(), &[Some(0x48), None]);
        assert_eq!(p5.bytes(), &[Some(0x48), None]);
    }

    #[test]
    fn test_pattern_parse_errors() {
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("?? ??").is_err()); // All wildcards
        assert!(Pattern::parse("GG").is_err()); // Invalid hex
        assert!(Pattern::parse("123").is_err()); // Wrong length
    }

    #[test]
    fn test_pattern_matches() {
        let pattern = Pattern::parse("48 8B ?? 00").unwrap();
        let data = [0x48, 0x8B, 0xFF, 0x00, 0x90, 0x90];

        assert!(pattern.matches_at(&data, 0));
        assert!(!pattern.matches_at(&data, 1));
        assert!(!pattern.matches_at(&data, 3)); // Too short
    }

    #[test]
    fn test_pattern_matches_all_wildcards_except_first() {
        let pattern = Pattern::parse("48 ?? ?? ??").unwrap();
        let data = [0x48, 0xFF, 0xEE, 0xDD];

        assert!(pattern.matches_at(&data, 0));
        assert!(!pattern.matches_at(&data, 1));
    }

    #[test]
    fn test_find_matches_baseline() {
        let pattern = Pattern::parse("90 90").unwrap();
        let scanner = PatternScanner::new(pattern);

        let data = [0x48, 0x90, 0x90, 0x90, 0x00];
        let matches = scanner.find_matches_baseline(&data);

        assert_eq!(matches, vec![1, 2]);
    }

    #[test]
    fn test_signature_create() {
        let sig = Signature::new("TestSig", "48 8B ?? 00")
            .with_module("game.exe")
            .with_description("Test signature");

        assert_eq!(sig.name, "TestSig");
        assert_eq!(sig.pattern, "48 8B ?? 00");
        assert_eq!(sig.module, Some("game.exe".to_string()));
        assert!(sig.compile().is_ok());
    }
}
