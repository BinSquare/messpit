//! Helper functions and constants
//!
//! Contains error formatting, value parsing/formatting, and application constants.

use messpit_protocol::{Address, Value, ValueType};

// ============================================================================
// Application Constants
// ============================================================================

/// Maximum size for a single memory region read (256 MB)
pub const MAX_REGION_READ_SIZE: usize = 256 * 1024 * 1024;

/// Minimum valid user-space address (skip null page and low addresses)
pub const MIN_VALID_ADDRESS: u64 = 0x10000;

/// Maximum length for label strings
pub const MAX_LABEL_LENGTH: usize = 256;

/// Maximum length for pattern strings
pub const MAX_PATTERN_INPUT_LENGTH: usize = 1024;

/// Maximum length for script source
pub const MAX_SCRIPT_LENGTH: usize = 256 * 1024; // 256 KB

/// Maximum length for project name
pub const MAX_PROJECT_NAME_LENGTH: usize = 128;

/// Maximum length for notes
pub const MAX_NOTES_LENGTH: usize = 64 * 1024; // 64 KB

/// Maximum number of watch entries
pub const MAX_WATCH_ENTRIES: usize = 1000;

/// Maximum number of concurrent scripts
pub const MAX_CONCURRENT_SCRIPTS: usize = 10;

/// Maximum number of script output entries to keep
pub const MAX_SCRIPT_OUTPUT_ENTRIES: usize = 50;

/// Maximum scan results to store
pub const MAX_SCAN_RESULTS: usize = 100_000;

// ============================================================================
// Error Formatting
// ============================================================================

/// Format a user-friendly error for process operations
pub fn error_process(action: &str, details: &str) -> String {
    format!("Failed to {}: {}", action, details)
}

/// Format a user-friendly error for validation failures
pub fn error_validation(field: &str, issue: &str) -> String {
    format!("Invalid {}: {}", field, issue)
}

/// Format a user-friendly error for limit exceeded
pub fn error_limit(resource: &str, max: usize) -> String {
    format!("{} limit reached (maximum: {})", resource, max)
}

/// Format a user-friendly error for missing requirements
pub fn error_requires(requirement: &str) -> String {
    format!("This operation requires {}", requirement)
}

// ============================================================================
// Value Type Parsing and Formatting
// ============================================================================

/// Default maximum length for string scans
pub const DEFAULT_STRING_MAX_LEN: usize = 256;

/// Maximum allowed string length for scans
pub const MAX_STRING_SCAN_LEN: usize = 4096;

/// Parse a value type string from user input (case-insensitive)
/// Supports: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, string, string[N]
pub fn parse_value_type(s: &str) -> Result<ValueType, String> {
    let s_lower = s.to_lowercase();
    let s_trimmed = s_lower.trim();

    // Check for string type with optional length: "string" or "string[256]"
    if s_trimmed == "string" {
        return Ok(ValueType::String { max_len: DEFAULT_STRING_MAX_LEN });
    }

    if s_trimmed.starts_with("string[") && s_trimmed.ends_with(']') {
        let len_str = &s_trimmed[7..s_trimmed.len() - 1];
        let max_len = len_str.parse::<usize>()
            .map_err(|_| error_validation("string length", "must be a valid number"))?;

        if max_len == 0 {
            return Err(error_validation("string length", "must be greater than 0"));
        }
        if max_len > MAX_STRING_SCAN_LEN {
            return Err(error_validation("string length", &format!(
                "cannot exceed {} characters", MAX_STRING_SCAN_LEN
            )));
        }

        return Ok(ValueType::String { max_len });
    }

    match s_trimmed {
        "i8" => Ok(ValueType::I8),
        "i16" => Ok(ValueType::I16),
        "i32" => Ok(ValueType::I32),
        "i64" => Ok(ValueType::I64),
        "u8" => Ok(ValueType::U8),
        "u16" => Ok(ValueType::U16),
        "u32" => Ok(ValueType::U32),
        "u64" => Ok(ValueType::U64),
        "f32" => Ok(ValueType::F32),
        "f64" => Ok(ValueType::F64),
        _ => Err(error_validation("value type", &format!(
            "'{}' is not supported. Use: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, or string", s
        ))),
    }
}

/// Format a value type for display
pub fn format_value_type(vt: &ValueType) -> String {
    match vt {
        ValueType::I8 => "i8",
        ValueType::I16 => "i16",
        ValueType::I32 => "i32",
        ValueType::I64 => "i64",
        ValueType::U8 => "u8",
        ValueType::U16 => "u16",
        ValueType::U32 => "u32",
        ValueType::U64 => "u64",
        ValueType::F32 => "f32",
        ValueType::F64 => "f64",
        ValueType::Bytes { len } => return format!("bytes[{}]", len),
        ValueType::String { max_len } => return format!("string[{}]", max_len),
    }.to_string()
}

/// Parse a hexadecimal address string with validation
pub fn parse_address(s: &str) -> Result<Address, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

    if s.is_empty() {
        return Err(error_validation("address", "cannot be empty"));
    }

    let addr = u64::from_str_radix(s, 16)
        .map_err(|_| error_validation("address", "must be a valid hexadecimal number (e.g., 0x12345678)"))?;

    // Validate address range - reject addresses in null page / low memory
    if addr < MIN_VALID_ADDRESS {
        return Err(error_validation("address", &format!(
            "0x{:X} is in protected memory. Use addresses above 0x{:X}",
            addr, MIN_VALID_ADDRESS
        )));
    }

    Ok(Address(addr))
}

/// Parse a value string into the specified type with user-friendly errors
pub fn parse_value(s: &str, value_type: &ValueType) -> Result<Value, String> {
    let s = s.trim();

    if s.is_empty() {
        return Err(error_validation("value", "cannot be empty"));
    }

    match value_type {
        ValueType::I8 => s.parse::<i8>().map(Value::I8)
            .map_err(|_| error_validation("value", "must be a valid 8-bit signed integer (-128 to 127)")),
        ValueType::I16 => s.parse::<i16>().map(Value::I16)
            .map_err(|_| error_validation("value", "must be a valid 16-bit signed integer")),
        ValueType::I32 => s.parse::<i32>().map(Value::I32)
            .map_err(|_| error_validation("value", "must be a valid 32-bit signed integer (e.g., 100, -50)")),
        ValueType::I64 => s.parse::<i64>().map(Value::I64)
            .map_err(|_| error_validation("value", "must be a valid 64-bit signed integer")),
        ValueType::U8 => s.parse::<u8>().map(Value::U8)
            .map_err(|_| error_validation("value", "must be a valid 8-bit unsigned integer (0 to 255)")),
        ValueType::U16 => s.parse::<u16>().map(Value::U16)
            .map_err(|_| error_validation("value", "must be a valid 16-bit unsigned integer (0 to 65535)")),
        ValueType::U32 => s.parse::<u32>().map(Value::U32)
            .map_err(|_| error_validation("value", "must be a valid 32-bit unsigned integer (0 to 4294967295)")),
        ValueType::U64 => s.parse::<u64>().map(Value::U64)
            .map_err(|_| error_validation("value", "must be a valid 64-bit unsigned integer")),
        ValueType::F32 => s.parse::<f32>().map(Value::F32)
            .map_err(|_| error_validation("value", "must be a valid decimal number (e.g., 3.14)")),
        ValueType::F64 => s.parse::<f64>().map(Value::F64)
            .map_err(|_| error_validation("value", "must be a valid decimal number")),
        ValueType::String { .. } => Ok(Value::String(s.to_string())),
        ValueType::Bytes { .. } => {
            // Parse hex bytes like "DE AD BE EF"
            let bytes: Result<Vec<u8>, _> = s
                .split_whitespace()
                .map(|b| u8::from_str_radix(b, 16))
                .collect();
            bytes.map(Value::Bytes)
                .map_err(|_| error_validation("value", "must be hex bytes separated by spaces (e.g., 'DE AD BE EF')"))
        }
    }
}

/// Format a value for display (with 6 decimal places for floats)
#[allow(dead_code)]
pub fn format_value(val: &Value) -> String {
    match val {
        Value::I8(v) => v.to_string(),
        Value::I16(v) => v.to_string(),
        Value::I32(v) => v.to_string(),
        Value::I64(v) => v.to_string(),
        Value::U8(v) => v.to_string(),
        Value::U16(v) => v.to_string(),
        Value::U32(v) => v.to_string(),
        Value::U64(v) => v.to_string(),
        Value::F32(v) => format!("{:.6}", v),
        Value::F64(v) => format!("{:.6}", v),
        Value::String(s) => s.clone(),
        Value::Bytes(b) => b.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Error Formatting Tests
    // ========================================================================

    #[test]
    fn test_error_process() {
        assert_eq!(
            error_process("attach", "permission denied"),
            "Failed to attach: permission denied"
        );
    }

    #[test]
    fn test_error_validation() {
        assert_eq!(
            error_validation("address", "cannot be empty"),
            "Invalid address: cannot be empty"
        );
    }

    #[test]
    fn test_error_limit() {
        assert_eq!(
            error_limit("Watch entries", 1000),
            "Watch entries limit reached (maximum: 1000)"
        );
    }

    #[test]
    fn test_error_requires() {
        assert_eq!(
            error_requires("an attached process"),
            "This operation requires an attached process"
        );
    }

    // ========================================================================
    // Value Type Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_value_type_valid() {
        assert_eq!(parse_value_type("i8").unwrap(), ValueType::I8);
        assert_eq!(parse_value_type("i16").unwrap(), ValueType::I16);
        assert_eq!(parse_value_type("i32").unwrap(), ValueType::I32);
        assert_eq!(parse_value_type("i64").unwrap(), ValueType::I64);
        assert_eq!(parse_value_type("u8").unwrap(), ValueType::U8);
        assert_eq!(parse_value_type("u16").unwrap(), ValueType::U16);
        assert_eq!(parse_value_type("u32").unwrap(), ValueType::U32);
        assert_eq!(parse_value_type("u64").unwrap(), ValueType::U64);
        assert_eq!(parse_value_type("f32").unwrap(), ValueType::F32);
        assert_eq!(parse_value_type("f64").unwrap(), ValueType::F64);
    }

    #[test]
    fn test_parse_value_type_case_insensitive() {
        assert_eq!(parse_value_type("I32").unwrap(), ValueType::I32);
        assert_eq!(parse_value_type("U64").unwrap(), ValueType::U64);
        assert_eq!(parse_value_type("F32").unwrap(), ValueType::F32);
    }

    #[test]
    fn test_parse_value_type_invalid() {
        assert!(parse_value_type("invalid").is_err());
        assert!(parse_value_type("int").is_err());
        assert!(parse_value_type("").is_err());
    }

    #[test]
    fn test_parse_value_type_string() {
        // Default string (256 chars)
        assert_eq!(parse_value_type("string").unwrap(), ValueType::String { max_len: 256 });
        assert_eq!(parse_value_type("STRING").unwrap(), ValueType::String { max_len: 256 });

        // String with explicit length
        assert_eq!(parse_value_type("string[128]").unwrap(), ValueType::String { max_len: 128 });
        assert_eq!(parse_value_type("string[1]").unwrap(), ValueType::String { max_len: 1 });
        assert_eq!(parse_value_type("string[4096]").unwrap(), ValueType::String { max_len: 4096 });
    }

    #[test]
    fn test_parse_value_type_string_invalid() {
        // Zero length
        assert!(parse_value_type("string[0]").is_err());
        // Too long
        assert!(parse_value_type("string[4097]").is_err());
        // Invalid number
        assert!(parse_value_type("string[abc]").is_err());
        assert!(parse_value_type("string[-1]").is_err());
        // Malformed
        assert!(parse_value_type("string[").is_err());
        assert!(parse_value_type("string]").is_err());
    }

    // ========================================================================
    // Value Type Formatting Tests
    // ========================================================================

    #[test]
    fn test_format_value_type() {
        assert_eq!(format_value_type(&ValueType::I8), "i8");
        assert_eq!(format_value_type(&ValueType::I32), "i32");
        assert_eq!(format_value_type(&ValueType::U64), "u64");
        assert_eq!(format_value_type(&ValueType::F32), "f32");
        assert_eq!(format_value_type(&ValueType::Bytes { len: 16 }), "bytes[16]");
        assert_eq!(format_value_type(&ValueType::String { max_len: 256 }), "string[256]");
    }

    // ========================================================================
    // Address Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_address_valid() {
        assert_eq!(parse_address("0x12345678").unwrap(), Address(0x12345678));
        assert_eq!(parse_address("0X12345678").unwrap(), Address(0x12345678));
        assert_eq!(parse_address("12345678").unwrap(), Address(0x12345678));
        assert_eq!(parse_address("  0x12345678  ").unwrap(), Address(0x12345678));
    }

    #[test]
    fn test_parse_address_empty() {
        assert!(parse_address("").is_err());
        assert!(parse_address("   ").is_err());
        assert!(parse_address("0x").is_err());
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        assert!(parse_address("0xGGGG").is_err());
        assert!(parse_address("not_hex").is_err());
    }

    #[test]
    fn test_parse_address_too_low() {
        // Addresses below MIN_VALID_ADDRESS should be rejected
        assert!(parse_address("0x0").is_err());
        assert!(parse_address("0x100").is_err());
        assert!(parse_address("0xFFFF").is_err());
        // MIN_VALID_ADDRESS (0x10000) and above should be valid
        assert!(parse_address("0x10000").is_ok());
        assert!(parse_address("0x10001").is_ok());
    }

    // ========================================================================
    // Value Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_value_integers() {
        assert_eq!(parse_value("42", &ValueType::I32).unwrap(), Value::I32(42));
        assert_eq!(parse_value("-42", &ValueType::I32).unwrap(), Value::I32(-42));
        assert_eq!(parse_value("255", &ValueType::U8).unwrap(), Value::U8(255));
        assert_eq!(parse_value("0", &ValueType::U64).unwrap(), Value::U64(0));
    }

    #[test]
    fn test_parse_value_floats() {
        assert_eq!(parse_value("3.14", &ValueType::F32).unwrap(), Value::F32(3.14));
        assert_eq!(parse_value("-2.5", &ValueType::F64).unwrap(), Value::F64(-2.5));
    }

    #[test]
    fn test_parse_value_string() {
        assert_eq!(
            parse_value("hello world", &ValueType::String { max_len: 256 }).unwrap(),
            Value::String("hello world".to_string())
        );
    }

    #[test]
    fn test_parse_value_bytes() {
        assert_eq!(
            parse_value("DE AD BE EF", &ValueType::Bytes { len: 4 }).unwrap(),
            Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_parse_value_empty() {
        assert!(parse_value("", &ValueType::I32).is_err());
        assert!(parse_value("   ", &ValueType::I32).is_err());
    }

    #[test]
    fn test_parse_value_overflow() {
        // u8 max is 255
        assert!(parse_value("256", &ValueType::U8).is_err());
        // i8 range is -128 to 127
        assert!(parse_value("128", &ValueType::I8).is_err());
        assert!(parse_value("-129", &ValueType::I8).is_err());
    }

    #[test]
    fn test_parse_value_invalid_bytes() {
        assert!(parse_value("GG HH", &ValueType::Bytes { len: 2 }).is_err());
        assert!(parse_value("not hex", &ValueType::Bytes { len: 2 }).is_err());
    }

    // ========================================================================
    // Value Formatting Tests
    // ========================================================================

    #[test]
    fn test_format_value_integers() {
        assert_eq!(format_value(&Value::I32(42)), "42");
        assert_eq!(format_value(&Value::I32(-42)), "-42");
        assert_eq!(format_value(&Value::U64(1000)), "1000");
    }

    #[test]
    fn test_format_value_floats() {
        assert_eq!(format_value(&Value::F32(3.14)), "3.140000");
        assert_eq!(format_value(&Value::F64(2.5)), "2.500000");
    }

    #[test]
    fn test_format_value_string() {
        assert_eq!(format_value(&Value::String("test".to_string())), "test");
    }

    #[test]
    fn test_format_value_bytes() {
        assert_eq!(
            format_value(&Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])),
            "DE AD BE EF"
        );
    }

    // ========================================================================
    // Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_value_type_roundtrip() {
        let types = ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64"];
        for t in types {
            let parsed = parse_value_type(t).unwrap();
            let formatted = format_value_type(&parsed);
            assert_eq!(t, formatted);
        }
    }

    #[test]
    fn test_value_roundtrip_i32() {
        let original = "12345";
        let parsed = parse_value(original, &ValueType::I32).unwrap();
        let formatted = format_value(&parsed);
        assert_eq!(original, formatted);
    }
}
