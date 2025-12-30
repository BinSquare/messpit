//! QuickJS runtime with sandbox limits

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rquickjs::{Context, Runtime};
use rquickjs::function::{Func, Rest};
use tokio::sync::mpsc;

use crate::{
    HostRequest, HostResponse, ScriptConfig, ScriptError, ScriptEvent, ScriptResult, ScriptStatus,
};
use crate::bindings::{js_to_value, parse_value_type, value_to_js};
use messpit_protocol::{Address, RunId};

/// Thread-safe cancellation flag
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Memory usage tracker for the runtime
#[derive(Debug, Clone, Default)]
pub struct MemoryTracker {
    current: Arc<AtomicUsize>,
    limit: usize,
}

impl MemoryTracker {
    pub fn new(limit: usize) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn is_exceeded(&self) -> bool {
        self.current() > self.limit
    }
}

/// Script execution context with host communication
pub struct ScriptHost {
    config: ScriptConfig,
    cancellation: CancellationToken,
}

impl ScriptHost {
    pub fn new(config: ScriptConfig) -> Self {
        Self {
            config,
            cancellation: CancellationToken::new(),
        }
    }

    /// Get the cancellation token for this host
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Execute a script with host API bindings
    pub async fn execute<F>(
        &self,
        run_id: RunId,
        source: &str,
        host_handler: F,
        event_sender: mpsc::Sender<ScriptEvent>,
    ) -> Result<ScriptResult, ScriptError>
    where
        F: Fn(HostRequest) -> HostResponse + Send + Sync + 'static,
    {
        let config = self.config.clone();
        let cancellation = self.cancellation.clone();
        let source = source.to_string();
        let handler = Arc::new(host_handler);

        // Run the script in a blocking task
        let handle = tokio::task::spawn_blocking(move || {
            execute_script_sync(run_id, &source, &config, &cancellation, handler)
        });

        // Wait with timeout
        let timeout = Duration::from_millis(self.config.timeout_ms);
        match tokio::time::timeout(timeout, handle).await {
            Ok(Ok(result)) => {
                let status = match &result {
                    Ok(_) => ScriptStatus::Success,
                    Err(ScriptError::Cancelled) => ScriptStatus::Cancelled,
                    Err(ScriptError::Timeout) => ScriptStatus::Timeout,
                    Err(e) => ScriptStatus::Error {
                        message: e.to_string(),
                    },
                };
                let _ = event_sender
                    .send(ScriptEvent::Finished { run_id, status })
                    .await;
                result
            }
            Ok(Err(e)) => {
                let _ = event_sender
                    .send(ScriptEvent::Finished {
                        run_id,
                        status: ScriptStatus::Error {
                            message: e.to_string(),
                        },
                    })
                    .await;
                Err(ScriptError::InitError(e.to_string()))
            }
            Err(_) => {
                // Timeout - cancel the script
                self.cancellation.cancel();
                let _ = event_sender
                    .send(ScriptEvent::Finished {
                        run_id,
                        status: ScriptStatus::Timeout,
                    })
                    .await;
                Err(ScriptError::Timeout)
            }
        }
    }

    /// Cancel a running script
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl Default for ScriptHost {
    fn default() -> Self {
        Self::new(ScriptConfig::default())
    }
}

/// Synchronous script execution (runs in blocking task)
fn execute_script_sync<F>(
    _run_id: RunId,
    source: &str,
    config: &ScriptConfig,
    cancellation: &CancellationToken,
    host_handler: Arc<F>,
) -> Result<ScriptResult, ScriptError>
where
    F: Fn(HostRequest) -> HostResponse + Send + Sync + 'static,
{
    // Create runtime with memory limit
    let runtime = Runtime::new().map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Set memory limit
    runtime.set_memory_limit(config.memory_limit);

    // Set up interrupt handler for cancellation and timeout
    let start_time = Instant::now();
    let timeout_ms = config.timeout_ms;
    let cancel_flag = cancellation.cancelled.clone();

    runtime.set_interrupt_handler(Some(Box::new(move || {
        // Check cancellation
        if cancel_flag.load(Ordering::SeqCst) {
            return true; // Interrupt
        }
        // Check timeout
        if start_time.elapsed().as_millis() as u64 > timeout_ms {
            return true; // Interrupt
        }
        false // Continue
    })));

    // Create context
    let context = Context::full(&runtime).map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Collected output
    let output = Rc::new(RefCell::new(String::new()));
    let mut return_value = None;

    // Execute in context
    let result = context.with(|ctx| {
        // Get the global object
        let globals = ctx.globals();

        // Create host API namespace objects and bind functions
        create_host_bindings(&ctx, &globals, host_handler.clone(), output.clone(), config)?;

        // Evaluate the script
        match ctx.eval::<rquickjs::Value, _>(source) {
            Ok(val) => {
                // Try to convert return value to string
                if !val.is_undefined() && !val.is_null() {
                    if let Ok(s) = val.get::<String>() {
                        return_value = Some(s);
                    } else if let Ok(n) = val.get::<f64>() {
                        return_value = Some(n.to_string());
                    } else if let Ok(b) = val.get::<bool>() {
                        return_value = Some(b.to_string());
                    }
                }
                Ok(())
            }
            Err(e) => {
                // Check if it was an interrupt
                if cancellation.is_cancelled() {
                    Err(ScriptError::Cancelled)
                } else if start_time.elapsed().as_millis() as u64 > timeout_ms {
                    Err(ScriptError::Timeout)
                } else {
                    Err(ScriptError::JsError(e.to_string()))
                }
            }
        }
    });

    result?;

    let output_str = output.borrow().clone();
    Ok(ScriptResult {
        output: output_str,
        return_value,
    })
}

/// Create host API bindings in the JavaScript context
fn create_host_bindings<'js, F>(
    ctx: &rquickjs::Ctx<'js>,
    globals: &rquickjs::Object<'js>,
    host_handler: Arc<F>,
    output: Rc<RefCell<String>>,
    config: &ScriptConfig,
) -> Result<(), ScriptError>
where
    F: Fn(HostRequest) -> HostResponse + Send + Sync + 'static,
{
    // Create console object with log function
    let console = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let output_clone = output.clone();
    let log_fn = Func::from(move |args: Rest<String>| {
        let msg = args.0.join(" ");
        let mut out = output_clone.borrow_mut();
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&msg);
    });

    console.set("log", log_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("console", console)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Create ui namespace
    let ui = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let output_clone = output.clone();
    let handler_clone = host_handler.clone();
    let print_fn = Func::from(move |msg: String| {
        let mut out = output_clone.borrow_mut();
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&msg);
        handler_clone(HostRequest::Print { message: msg.clone() });
    });

    ui.set("print", print_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let notify_fn = Func::from(move |msg: String| {
        handler_clone(HostRequest::Notify { message: msg });
    });

    ui.set("notify", notify_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("ui", ui)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Create time namespace
    let time = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let max_sleep = config.max_sleep_ms;
    let handler_clone = host_handler.clone();
    let sleep_fn = Func::from(move |ms: u64| {
        let duration = ms.min(max_sleep);
        handler_clone(HostRequest::Sleep { duration_ms: duration });
    });

    time.set("sleep", sleep_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("time", time)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Create mem namespace
    let mem = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let read_fn = Func::from(move |addr: u64, type_str: String| -> Option<f64> {
        let value_type = parse_value_type(&type_str)?;
        let response = handler_clone(HostRequest::ReadMemory {
            address: Address(addr),
            value_type,
        });
        match response {
            HostResponse::Value(Some(val)) => Some(value_to_js(&val)),
            _ => None,
        }
    });

    mem.set("read", read_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let write_fn = Func::from(move |addr: u64, type_str: String, val: f64| -> bool {
        let Some(value_type) = parse_value_type(&type_str) else {
            return false;
        };
        let Some(value) = js_to_value(val, value_type) else {
            return false;
        };
        let response = handler_clone(HostRequest::WriteMemory {
            address: Address(addr),
            value,
        });
        matches!(response, HostResponse::Ok)
    });

    mem.set("write", write_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("mem", mem)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Create watch namespace
    let watch = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let add_fn = Func::from(move |addr: u64, type_str: String, label: Option<String>| -> bool {
        let Some(value_type) = parse_value_type(&type_str) else {
            return false;
        };
        let response = handler_clone(HostRequest::AddWatch {
            address: Address(addr),
            value_type,
            label: label.unwrap_or_else(|| format!("0x{:X}", addr)),
        });
        matches!(response, HostResponse::Ok)
    });

    watch.set("add", add_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("watch", watch)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    // Create freeze namespace
    let freeze = rquickjs::Object::new(ctx.clone())
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let set_fn = Func::from(move |addr: u64, type_str: String, val: f64, interval: Option<u32>| -> bool {
        let Some(value_type) = parse_value_type(&type_str) else {
            return false;
        };
        let Some(value) = js_to_value(val, value_type) else {
            return false;
        };
        let response = handler_clone(HostRequest::SetFreeze {
            address: Address(addr),
            value,
            interval_ms: interval.unwrap_or(100),
        });
        matches!(response, HostResponse::Ok)
    });

    freeze.set("set", set_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    let handler_clone = host_handler.clone();
    let clear_fn = Func::from(move |addr: u64| -> bool {
        let response = handler_clone(HostRequest::ClearFreeze {
            address: Address(addr),
        });
        matches!(response, HostResponse::Ok)
    });

    freeze.set("clear", clear_fn)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    globals.set("freeze", freeze)
        .map_err(|e| ScriptError::InitError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_simple_script() {
        let host = ScriptHost::default();
        let (tx, _rx) = mpsc::channel(10);
        let run_id = RunId::new();

        let result = host
            .execute(run_id, "1 + 1", |_req| HostResponse::Ok, tx)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.return_value, Some("2".to_string()));
    }

    #[tokio::test]
    async fn test_console_log() {
        let host = ScriptHost::default();
        let (tx, _rx) = mpsc::channel(10);
        let run_id = RunId::new();

        let result = host
            .execute(run_id, "console.log('hello', 'world'); 42", |_req| HostResponse::Ok, tx)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.output, "hello world");
        assert_eq!(result.return_value, Some("42".to_string()));
    }

    #[tokio::test]
    async fn test_cancellation() {
        let config = ScriptConfig {
            timeout_ms: 100,
            ..Default::default()
        };
        let host = ScriptHost::new(config);
        let (tx, _rx) = mpsc::channel(10);
        let run_id = RunId::new();

        // Infinite loop script
        let result = host
            .execute(run_id, "while(true) {}", |_req| HostResponse::Ok, tx)
            .await;

        assert!(matches!(result, Err(ScriptError::Timeout)));
    }

    #[test]
    fn test_cancellation_token() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_host_api_calls() {
        use std::sync::atomic::AtomicUsize;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let host = ScriptHost::default();
        let (tx, _rx) = mpsc::channel(10);
        let run_id = RunId::new();

        let result = host
            .execute(
                run_id,
                r#"
                    ui.print("Hello from script");
                    watch.add(0x12345678, "i32", "test");
                    42
                "#,
                move |req| {
                    call_count_clone.fetch_add(1, Ordering::SeqCst);
                    match req {
                        HostRequest::Print { .. } => HostResponse::Ok,
                        HostRequest::AddWatch { .. } => HostResponse::Ok,
                        _ => HostResponse::Error("Not implemented".into()),
                    }
                },
                tx,
            )
            .await;

        assert!(result.is_ok());
        // Should have called handler at least twice (print + watch.add)
        assert!(call_count.load(Ordering::SeqCst) >= 2);
    }
}
