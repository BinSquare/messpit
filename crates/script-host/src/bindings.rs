//! Host API bindings for JavaScript
//!
//! This module provides the JavaScript API that scripts can use to interact
//! with the memory trainer engine.

use std::cell::RefCell;
use std::rc::Rc;

use crate::{HostRequest, HostResponse, ScriptConfig};
use messpit_protocol::{Value, ValueType};

/// Host API context that handles requests from scripts
#[allow(dead_code)]
pub struct HostApi<F>
where
    F: Fn(HostRequest) -> HostResponse,
{
    handler: F,
    output_buffer: Rc<RefCell<String>>,
    config: ScriptConfig,
}

#[allow(dead_code)]
impl<F> HostApi<F>
where
    F: Fn(HostRequest) -> HostResponse,
{
    pub fn new(handler: F, config: ScriptConfig) -> Self {
        Self {
            handler,
            output_buffer: Rc::new(RefCell::new(String::new())),
            config,
        }
    }

    pub fn output(&self) -> String {
        self.output_buffer.borrow().clone()
    }

    fn handle(&self, request: HostRequest) -> HostResponse {
        (self.handler)(request)
    }

    fn append_output(&self, text: &str) {
        let mut buf = self.output_buffer.borrow_mut();
        buf.push_str(text);
        buf.push('\n');
    }
}

/// Parse a value type string from JavaScript
pub fn parse_value_type(type_str: &str) -> Option<ValueType> {
    match type_str.to_lowercase().as_str() {
        "i8" | "int8" | "byte" => Some(ValueType::I8),
        "i16" | "int16" | "short" => Some(ValueType::I16),
        "i32" | "int32" | "int" => Some(ValueType::I32),
        "i64" | "int64" | "long" => Some(ValueType::I64),
        "u8" | "uint8" | "ubyte" => Some(ValueType::U8),
        "u16" | "uint16" | "ushort" => Some(ValueType::U16),
        "u32" | "uint32" | "uint" => Some(ValueType::U32),
        "u64" | "uint64" | "ulong" => Some(ValueType::U64),
        "f32" | "float" | "single" => Some(ValueType::F32),
        "f64" | "double" => Some(ValueType::F64),
        _ => None,
    }
}

/// Convert a JavaScript value to a typed Value based on ValueType
pub fn js_to_value(js_val: f64, value_type: ValueType) -> Option<Value> {
    match value_type {
        ValueType::I8 => Some(Value::I8(js_val as i8)),
        ValueType::I16 => Some(Value::I16(js_val as i16)),
        ValueType::I32 => Some(Value::I32(js_val as i32)),
        ValueType::I64 => Some(Value::I64(js_val as i64)),
        ValueType::U8 => Some(Value::U8(js_val as u8)),
        ValueType::U16 => Some(Value::U16(js_val as u16)),
        ValueType::U32 => Some(Value::U32(js_val as u32)),
        ValueType::U64 => Some(Value::U64(js_val as u64)),
        ValueType::F32 => Some(Value::F32(js_val as f32)),
        ValueType::F64 => Some(Value::F64(js_val)),
        ValueType::Bytes { .. } | ValueType::String { .. } => None,
    }
}

/// Convert a Value to a JavaScript number
pub fn value_to_js(value: &Value) -> f64 {
    match value {
        Value::I8(v) => *v as f64,
        Value::I16(v) => *v as f64,
        Value::I32(v) => *v as f64,
        Value::I64(v) => *v as f64,
        Value::U8(v) => *v as f64,
        Value::U16(v) => *v as f64,
        Value::U32(v) => *v as f64,
        Value::U64(v) => *v as f64,
        Value::F32(v) => *v as f64,
        Value::F64(v) => *v,
        Value::Bytes(_) | Value::String(_) => f64::NAN,
    }
}

/// TypeScript definition for the host API
pub const TYPESCRIPT_DEFINITIONS: &str = r#"
/**
 * Messpit Host API
 *
 * This API is available to scripts running in the Messpit scripting environment.
 */

declare namespace mem {
    /**
     * Read a value from memory.
     * @param addr Memory address as a number or hex string
     * @param type Value type: "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64"
     * @returns The value at the address, or null if read failed
     */
    function read(addr: number | string, type: string): number | null;

    /**
     * Write a value to memory.
     * @param addr Memory address as a number or hex string
     * @param type Value type
     * @param value The value to write
     * @returns true if write succeeded, false otherwise
     */
    function write(addr: number | string, type: string, value: number): boolean;
}

declare namespace watch {
    /**
     * Add an address to the watch list.
     * @param addr Memory address
     * @param type Value type
     * @param label Optional label for the watch entry
     * @returns true if added successfully
     */
    function add(addr: number | string, type: string, label?: string): boolean;
}

declare namespace freeze {
    /**
     * Set a freeze on an address.
     * @param addr Memory address
     * @param type Value type
     * @param value Value to freeze to
     * @param intervalMs Update interval in milliseconds (default: 100)
     * @returns true if freeze was set
     */
    function set(addr: number | string, type: string, value: number, intervalMs?: number): boolean;

    /**
     * Clear a freeze on an address.
     * @param addr Memory address
     * @returns true if freeze was cleared
     */
    function clear(addr: number | string): boolean;
}

declare namespace ui {
    /**
     * Show a notification to the user.
     * @param message The message to display
     */
    function notify(message: string): void;

    /**
     * Print a message to the script output.
     * @param message The message to print
     */
    function print(message: string): void;
}

declare namespace time {
    /**
     * Sleep for a duration.
     * @param ms Duration in milliseconds (max 10000)
     */
    function sleep(ms: number): void;
}

declare namespace console {
    /**
     * Log a message to the script output.
     */
    function log(...args: any[]): void;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_value_type() {
        assert_eq!(parse_value_type("i32"), Some(ValueType::I32));
        assert_eq!(parse_value_type("int"), Some(ValueType::I32));
        assert_eq!(parse_value_type("float"), Some(ValueType::F32));
        assert_eq!(parse_value_type("double"), Some(ValueType::F64));
        assert_eq!(parse_value_type("invalid"), None);
    }

    #[test]
    fn test_js_to_value() {
        assert_eq!(js_to_value(42.0, ValueType::I32), Some(Value::I32(42)));
        assert_eq!(js_to_value(3.14, ValueType::F32), Some(Value::F32(3.14)));
        assert_eq!(js_to_value(255.0, ValueType::U8), Some(Value::U8(255)));
    }

    #[test]
    fn test_value_to_js() {
        assert_eq!(value_to_js(&Value::I32(42)), 42.0);
        assert_eq!(value_to_js(&Value::F64(3.14)), 3.14);
        assert_eq!(value_to_js(&Value::U8(255)), 255.0);
    }
}
