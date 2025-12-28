//! Memory scanning engine
//!
//! Supports two modes:
//! - Dense: Bitset + snapshot for "unknown initial" scans (memory efficient for large scans)
//! - Sparse: Address list after narrowing down results

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use rayon::prelude::*;

use messpit_protocol::{Address, Refinement, ScanComparison, ScanParams, Value, ValueType};

/// Result of a scan operation
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub addresses: Vec<(Address, Value)>,
    pub total_scanned: usize,
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(f32, u64) + Send + Sync>;

/// Cancellation token for long-running operations
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Dense scan state using bitset + snapshot
#[derive(Debug)]
pub struct DenseScanState {
    /// Base address of the scanned region
    pub base: Address,
    /// Memory snapshot
    pub snapshot: Vec<u8>,
    /// Bitset: 1 bit per aligned position (1 = valid/matched)
    pub valid_bits: Vec<u8>,
    /// Alignment used
    pub alignment: usize,
    /// Value type
    pub value_type: ValueType,
    /// Number of valid (matched) positions
    pub match_count: usize,
}

impl DenseScanState {
    /// Create a new dense scan from an initial "unknown" scan
    pub fn from_unknown_scan(
        data: Vec<u8>,
        base: Address,
        value_type: ValueType,
        alignment: usize,
    ) -> Self {
        let size = value_type.size().unwrap_or(1);
        let alignment = alignment.max(1);

        if data.len() < size {
            return Self {
                base,
                snapshot: data,
                valid_bits: vec![],
                alignment,
                value_type,
                match_count: 0,
            };
        }

        // Calculate number of aligned positions
        let num_positions = (data.len() - size) / alignment + 1;
        let num_bytes = num_positions.div_ceil(8);

        // All positions are valid initially
        let mut valid_bits = vec![0xFFu8; num_bytes];

        // Clear trailing bits in the last byte
        let trailing = num_positions % 8;
        if trailing != 0 {
            valid_bits[num_bytes - 1] = (1u8 << trailing) - 1;
        }

        Self {
            base,
            snapshot: data,
            valid_bits,
            alignment,
            value_type,
            match_count: num_positions,
        }
    }

    /// Check if a position is valid
    #[inline]
    pub fn is_valid(&self, position: usize) -> bool {
        let byte_idx = position / 8;
        let bit_idx = position % 8;
        byte_idx < self.valid_bits.len() && (self.valid_bits[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Mark a position as invalid
    #[inline]
    pub fn invalidate(&mut self, position: usize) {
        let byte_idx = position / 8;
        let bit_idx = position % 8;
        if byte_idx < self.valid_bits.len()
            && self.valid_bits[byte_idx] & (1 << bit_idx) != 0 {
                self.valid_bits[byte_idx] &= !(1 << bit_idx);
                self.match_count = self.match_count.saturating_sub(1);
            }
    }

    /// Get the address for a position
    #[inline]
    pub fn address_at(&self, position: usize) -> Address {
        Address(self.base.0 + (position * self.alignment) as u64)
    }

    /// Get value at a position from snapshot
    pub fn value_at(&self, position: usize) -> Option<Value> {
        let offset = position * self.alignment;
        let size = self.value_type.size().unwrap_or(1);
        if offset + size <= self.snapshot.len() {
            decode_at(&self.snapshot[offset..offset + size], &self.value_type)
        } else {
            None
        }
    }

    /// Apply refinement with new memory data
    pub fn refine(&mut self, new_data: &[u8], refinement: &Refinement) {
        let size = self.value_type.size().unwrap_or(1);
        let num_positions = (self.snapshot.len().min(new_data.len()) - size) / self.alignment + 1;

        for pos in 0..num_positions {
            if !self.is_valid(pos) {
                continue;
            }

            let offset = pos * self.alignment;
            if offset + size > new_data.len() {
                self.invalidate(pos);
                continue;
            }

            let old_value = match decode_at(&self.snapshot[offset..offset + size], &self.value_type)
            {
                Some(v) => v,
                None => {
                    self.invalidate(pos);
                    continue;
                }
            };

            let new_value = match decode_at(&new_data[offset..offset + size], &self.value_type) {
                Some(v) => v,
                None => {
                    self.invalidate(pos);
                    continue;
                }
            };

            if !matches_refinement(&old_value, &new_value, refinement) {
                self.invalidate(pos);
            }
        }

        // Update snapshot
        self.snapshot = new_data.to_vec();
    }

    /// Convert to sparse results (for when match count is low enough)
    pub fn to_sparse(&self) -> Vec<(Address, Value)> {
        let size = self.value_type.size().unwrap_or(1);
        let num_positions = if self.snapshot.len() >= size {
            (self.snapshot.len() - size) / self.alignment + 1
        } else {
            0
        };

        let mut results = Vec::with_capacity(self.match_count);

        for pos in 0..num_positions {
            if self.is_valid(pos)
                && let Some(value) = self.value_at(pos) {
                    results.push((self.address_at(pos), value));
                }
        }

        results
    }

    /// Threshold for switching to sparse mode
    pub const SPARSE_THRESHOLD: usize = 100_000;

    /// Check if we should switch to sparse mode
    pub fn should_switch_to_sparse(&self) -> bool {
        self.match_count <= Self::SPARSE_THRESHOLD
    }
}

/// Scan engine for memory searching
pub struct ScanEngine;

impl ScanEngine {
    /// Perform an initial scan on a memory region
    pub fn initial_scan(data: &[u8], base: Address, params: &ScanParams) -> ScanResult {
        Self::initial_scan_with_cancel(data, base, params, None, None)
    }

    /// Perform an initial scan with progress reporting and cancellation
    pub fn initial_scan_with_cancel(
        data: &[u8],
        base: Address,
        params: &ScanParams,
        progress: Option<&ProgressCallback>,
        cancel: Option<&CancellationToken>,
    ) -> ScanResult {
        let alignment = (params.alignment as usize).max(1);
        let size = params.value_type.size().unwrap_or(1);

        if data.len() < size {
            return ScanResult {
                addresses: vec![],
                total_scanned: 0,
            };
        }

        let offsets: Vec<usize> = (0..=(data.len() - size)).step_by(alignment).collect();
        let total = offsets.len();

        // Progress tracking
        let scanned = Arc::new(AtomicU64::new(0));
        let chunk_size = (total / 100).max(1000); // Report every ~1%

        let matches: Vec<(Address, Value)> = offsets
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                // Check cancellation at chunk boundaries
                if cancel.is_some_and(|c| c.is_cancelled()) {
                    return vec![];
                }

                let chunk_matches: Vec<_> = chunk
                    .iter()
                    .filter_map(|&offset| {
                        let addr = Address(base.0 + offset as u64);
                        let slice = &data[offset..offset + size];

                        if let Some(value) = decode_at(slice, &params.value_type)
                            && matches_comparison(&value, &params.comparison) {
                                return Some((addr, value));
                            }
                        None
                    })
                    .collect();

                // Update progress
                let processed = scanned.fetch_add(chunk.len() as u64, Ordering::Relaxed)
                    + chunk.len() as u64;
                if let Some(cb) = progress {
                    let percent = processed as f32 / total as f32;
                    cb(percent, processed);
                }

                chunk_matches
            })
            .collect();

        ScanResult {
            total_scanned: total,
            addresses: matches,
        }
    }

    /// Create a dense scan state for "unknown initial" scans
    pub fn create_dense_scan(
        data: Vec<u8>,
        base: Address,
        value_type: ValueType,
        alignment: usize,
    ) -> DenseScanState {
        DenseScanState::from_unknown_scan(data, base, value_type, alignment)
    }

    /// Refine an existing scan with new data
    pub fn refine_scan(
        previous: &[(Address, Value)],
        read_fn: impl Fn(Address, usize) -> Option<Vec<u8>> + Sync,
        value_type: &ValueType,
        refinement: &Refinement,
    ) -> Vec<(Address, Value)> {
        Self::refine_scan_with_cancel(previous, read_fn, value_type, refinement, None, None)
    }

    /// Refine with progress and cancellation
    pub fn refine_scan_with_cancel(
        previous: &[(Address, Value)],
        read_fn: impl Fn(Address, usize) -> Option<Vec<u8>> + Sync,
        value_type: &ValueType,
        refinement: &Refinement,
        progress: Option<&ProgressCallback>,
        cancel: Option<&CancellationToken>,
    ) -> Vec<(Address, Value)> {
        let size = value_type.size().unwrap_or(1);
        let total = previous.len();
        let scanned = Arc::new(AtomicU64::new(0));
        let chunk_size = (total / 100).max(100);

        previous
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                if cancel.is_some_and(|c| c.is_cancelled()) {
                    return vec![];
                }

                let chunk_matches: Vec<_> = chunk
                    .iter()
                    .filter_map(|(addr, prev_value)| {
                        let data = read_fn(*addr, size)?;
                        let current = decode_at(&data, value_type)?;

                        if matches_refinement(prev_value, &current, refinement) {
                            Some((*addr, current))
                        } else {
                            None
                        }
                    })
                    .collect();

                let processed =
                    scanned.fetch_add(chunk.len() as u64, Ordering::Relaxed) + chunk.len() as u64;
                if let Some(cb) = progress {
                    cb(processed as f32 / total as f32, processed);
                }

                chunk_matches
            })
            .collect()
    }
}

/// Decode a value from bytes at the start of the slice
pub fn decode_at(data: &[u8], ty: &ValueType) -> Option<Value> {
    match ty {
        ValueType::I8 if !data.is_empty() => Some(Value::I8(i8::from_le_bytes([data[0]]))),
        ValueType::I16 if data.len() >= 2 => {
            Some(Value::I16(i16::from_le_bytes([data[0], data[1]])))
        }
        ValueType::I32 if data.len() >= 4 => {
            Some(Value::I32(i32::from_le_bytes(data[..4].try_into().ok()?)))
        }
        ValueType::I64 if data.len() >= 8 => {
            Some(Value::I64(i64::from_le_bytes(data[..8].try_into().ok()?)))
        }
        ValueType::U8 if !data.is_empty() => Some(Value::U8(data[0])),
        ValueType::U16 if data.len() >= 2 => {
            Some(Value::U16(u16::from_le_bytes([data[0], data[1]])))
        }
        ValueType::U32 if data.len() >= 4 => {
            Some(Value::U32(u32::from_le_bytes(data[..4].try_into().ok()?)))
        }
        ValueType::U64 if data.len() >= 8 => {
            Some(Value::U64(u64::from_le_bytes(data[..8].try_into().ok()?)))
        }
        ValueType::F32 if data.len() >= 4 => {
            Some(Value::F32(f32::from_le_bytes(data[..4].try_into().ok()?)))
        }
        ValueType::F64 if data.len() >= 8 => {
            Some(Value::F64(f64::from_le_bytes(data[..8].try_into().ok()?)))
        }
        ValueType::Bytes { len } if data.len() >= *len => Some(Value::Bytes(data[..*len].to_vec())),
        ValueType::String { max_len } => {
            let end = data
                .iter()
                .take(*max_len)
                .position(|&b| b == 0)
                .unwrap_or(*max_len);
            String::from_utf8(data[..end].to_vec())
                .ok()
                .map(Value::String)
        }
        _ => None,
    }
}

/// Encode a value to bytes
pub fn encode_value(value: &Value) -> Vec<u8> {
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
            bytes.push(0);
            bytes
        }
    }
}

/// Check if a value matches a scan comparison
fn matches_comparison(value: &Value, comparison: &ScanComparison) -> bool {
    match comparison {
        ScanComparison::Unknown => true,
        ScanComparison::Exact { value: target } => values_equal(value, target),
        ScanComparison::Range { min, max } => {
            value_cmp(value, min) >= std::cmp::Ordering::Equal
                && value_cmp(value, max) <= std::cmp::Ordering::Equal
        }
        ScanComparison::FloatEpsilon {
            value: target,
            epsilon,
        } => match (value_as_f64(value), Some(*target)) {
            (Some(a), Some(b)) => (a - b).abs() <= *epsilon,
            _ => false,
        },
    }
}

/// Check if a value matches a refinement condition
pub fn matches_refinement(prev: &Value, current: &Value, refinement: &Refinement) -> bool {
    match refinement {
        Refinement::Changed => !values_equal(prev, current),
        Refinement::Unchanged => values_equal(prev, current),
        Refinement::Increased => value_cmp(current, prev) == std::cmp::Ordering::Greater,
        Refinement::Decreased => value_cmp(current, prev) == std::cmp::Ordering::Less,
        Refinement::Exact { value } => values_equal(current, value),
        Refinement::Range { min, max } => {
            value_cmp(current, min) >= std::cmp::Ordering::Equal
                && value_cmp(current, max) <= std::cmp::Ordering::Equal
        }
    }
}

/// Check if two values are equal
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::I8(a), Value::I8(b)) => a == b,
        (Value::I16(a), Value::I16(b)) => a == b,
        (Value::I32(a), Value::I32(b)) => a == b,
        (Value::I64(a), Value::I64(b)) => a == b,
        (Value::U8(a), Value::U8(b)) => a == b,
        (Value::U16(a), Value::U16(b)) => a == b,
        (Value::U32(a), Value::U32(b)) => a == b,
        (Value::U64(a), Value::U64(b)) => a == b,
        (Value::F32(a), Value::F32(b)) => (a - b).abs() < f32::EPSILON,
        (Value::F64(a), Value::F64(b)) => (a - b).abs() < f64::EPSILON,
        (Value::Bytes(a), Value::Bytes(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        _ => false,
    }
}

/// Compare two values
fn value_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    match (a, b) {
        (Value::I8(a), Value::I8(b)) => a.cmp(b),
        (Value::I16(a), Value::I16(b)) => a.cmp(b),
        (Value::I32(a), Value::I32(b)) => a.cmp(b),
        (Value::I64(a), Value::I64(b)) => a.cmp(b),
        (Value::U8(a), Value::U8(b)) => a.cmp(b),
        (Value::U16(a), Value::U16(b)) => a.cmp(b),
        (Value::U32(a), Value::U32(b)) => a.cmp(b),
        (Value::U64(a), Value::U64(b)) => a.cmp(b),
        (Value::F32(a), Value::F32(b)) => a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal),
        (Value::F64(a), Value::F64(b)) => a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal),
        _ => std::cmp::Ordering::Equal,
    }
}

/// Convert a value to f64 for epsilon comparison
fn value_as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::I8(v) => Some(f64::from(*v)),
        Value::I16(v) => Some(f64::from(*v)),
        Value::I32(v) => Some(f64::from(*v)),
        Value::I64(v) => Some(*v as f64),
        Value::U8(v) => Some(f64::from(*v)),
        Value::U16(v) => Some(f64::from(*v)),
        Value::U32(v) => Some(f64::from(*v)),
        Value::U64(v) => Some(*v as f64),
        Value::F32(v) => Some(f64::from(*v)),
        Value::F64(v) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_i32_scan() {
        let data: Vec<u8> = vec![
            0, 0, 0, 0, // 0
            100, 0, 0, 0, // 100
            200, 0, 0, 0, // 200
            100, 0, 0, 0, // 100 again
        ];

        let params = ScanParams {
            value_type: ValueType::I32,
            comparison: ScanComparison::Exact {
                value: Value::I32(100),
            },
            alignment: 4,
            writable_only: false,
            region_filter: vec![],
        };

        let result = ScanEngine::initial_scan(&data, Address(0x1000), &params);

        assert_eq!(result.addresses.len(), 2);
        assert_eq!(result.addresses[0].0, Address(0x1004));
        assert_eq!(result.addresses[1].0, Address(0x100C));
    }

    #[test]
    fn test_range_scan() {
        let data: Vec<u8> = vec![
            50, 0, 0, 0,  // 50 - in range
            150, 0, 0, 0, // 150 - out of range
            75, 0, 0, 0,  // 75 - in range
        ];

        let params = ScanParams {
            value_type: ValueType::I32,
            comparison: ScanComparison::Range {
                min: Value::I32(40),
                max: Value::I32(100),
            },
            alignment: 4,
            writable_only: false,
            region_filter: vec![],
        };

        let result = ScanEngine::initial_scan(&data, Address(0), &params);

        assert_eq!(result.addresses.len(), 2);
    }

    #[test]
    fn test_refinement_increased() {
        let previous = vec![
            (Address(0), Value::I32(10)),
            (Address(4), Value::I32(20)),
            (Address(8), Value::I32(30)),
        ];

        let current_values = vec![15i32, 20, 25];

        let refined = ScanEngine::refine_scan(
            &previous,
            |addr, _| {
                let idx = addr.0 as usize / 4;
                Some(current_values[idx].to_le_bytes().to_vec())
            },
            &ValueType::I32,
            &Refinement::Increased,
        );

        assert_eq!(refined.len(), 1);
        assert_eq!(refined[0].0, Address(0));
        assert_eq!(refined[0].1, Value::I32(15));
    }

    #[test]
    fn test_dense_scan_unknown() {
        let data: Vec<u8> = vec![
            10, 0, 0, 0, // 10
            20, 0, 0, 0, // 20
            30, 0, 0, 0, // 30
            40, 0, 0, 0, // 40
        ];

        let dense = ScanEngine::create_dense_scan(data.clone(), Address(0x1000), ValueType::I32, 4);

        assert_eq!(dense.match_count, 4);
        assert!(dense.is_valid(0));
        assert!(dense.is_valid(1));
        assert!(dense.is_valid(2));
        assert!(dense.is_valid(3));
    }

    #[test]
    fn test_dense_scan_refine() {
        let data: Vec<u8> = vec![
            10, 0, 0, 0, // 10
            20, 0, 0, 0, // 20
            30, 0, 0, 0, // 30
            40, 0, 0, 0, // 40
        ];

        let mut dense =
            ScanEngine::create_dense_scan(data.clone(), Address(0x1000), ValueType::I32, 4);

        // New data: 15, 20, 25, 50 (increased: 0, 3; decreased: 2; unchanged: 1)
        let new_data: Vec<u8> = vec![
            15, 0, 0, 0, // 15 - increased
            20, 0, 0, 0, // 20 - unchanged
            25, 0, 0, 0, // 25 - decreased
            50, 0, 0, 0, // 50 - increased
        ];

        dense.refine(&new_data, &Refinement::Increased);

        assert_eq!(dense.match_count, 2);
        assert!(dense.is_valid(0)); // 10 -> 15 increased
        assert!(!dense.is_valid(1)); // 20 -> 20 unchanged
        assert!(!dense.is_valid(2)); // 30 -> 25 decreased
        assert!(dense.is_valid(3)); // 40 -> 50 increased
    }

    #[test]
    fn test_cancellation() {
        let data: Vec<u8> = vec![0u8; 10000];
        let cancel = CancellationToken::new();
        cancel.cancel();

        let params = ScanParams {
            value_type: ValueType::I32,
            comparison: ScanComparison::Exact {
                value: Value::I32(0),
            },
            alignment: 4,
            writable_only: false,
            region_filter: vec![],
        };

        let result =
            ScanEngine::initial_scan_with_cancel(&data, Address(0), &params, None, Some(&cancel));

        // Should return early due to cancellation
        assert!(result.addresses.len() < 2500);
    }

    #[test]
    fn test_progress_callback() {
        use std::sync::atomic::AtomicU32;

        let data: Vec<u8> = vec![0u8; 40000]; // 10000 i32 values
        let progress_count = Arc::new(AtomicU32::new(0));
        let progress_count_clone = progress_count.clone();

        let callback: ProgressCallback = Box::new(move |_percent, _processed| {
            progress_count_clone.fetch_add(1, Ordering::Relaxed);
        });

        let params = ScanParams {
            value_type: ValueType::I32,
            comparison: ScanComparison::Exact {
                value: Value::I32(0),
            },
            alignment: 4,
            writable_only: false,
            region_filter: vec![],
        };

        let _ =
            ScanEngine::initial_scan_with_cancel(&data, Address(0), &params, Some(&callback), None);

        assert!(progress_count.load(Ordering::Relaxed) > 0);
    }
}
