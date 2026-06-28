//! Stdio JSON helper for language SDKs without UniFFI bindings (e.g. C# on Windows).
//! Keeps [`EatPassClient`] sessions in memory for begin → attest → finalize.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eat_pass_mobile::{BeginResult, EatPassClient, MobileError};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Line {
    op: String,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    issuer_pk_json: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    origin_info: String,
    #[serde(default)]
    count: u32,
    #[serde(default)]
    sign_response_json: String,
}

struct State {
    next_id: AtomicU64,
    clients: Mutex<HashMap<u64, Arc<EatPassClient>>>,
}

fn ok(value: serde_json::Value) -> String {
    json!({"ok": true, "result": value}).to_string()
}

fn err(message: &str) -> String {
    json!({"ok": false, "error": message}).to_string()
}

fn mobile_err(e: MobileError) -> String {
    err(&e.to_string())
}

fn handle(state: &State, line: Line) -> String {
    match line.op.as_str() {
        "new" => {
            let id = state.next_id.fetch_add(1, Ordering::Relaxed);
            match EatPassClient::new(line.issuer_pk_json, line.issuer_name, line.origin_info) {
                Ok(client) => {
                    state.clients.lock().unwrap().insert(id, client);
                    ok(json!({"id": id}))
                }
                Err(e) => mobile_err(e),
            }
        }
        "begin" => {
            let clients = state.clients.lock().unwrap();
            let Some(client) = clients.get(&line.id) else {
                return err("unknown session id; call new first");
            };
            match client.begin(line.count.max(1)) {
                Ok(BeginResult {
                    request_json,
                    binding_hex,
                }) => ok(json!({
                    "request_json": request_json,
                    "binding_hex": binding_hex,
                })),
                Err(e) => mobile_err(e),
            }
        }
        "finalize" => {
            let clients = state.clients.lock().unwrap();
            let Some(client) = clients.get(&line.id) else {
                return err("unknown session id; call new first");
            };
            match client.finalize(line.sign_response_json) {
                Ok(headers) => {
                    let header = headers.into_iter().next().unwrap_or_default();
                    ok(json!({"authorization_header": header}))
                }
                Err(e) => mobile_err(e),
            }
        }
        "drop" => {
            state.clients.lock().unwrap().remove(&line.id);
            ok(json!({}))
        }
        _ => err("unknown op; use new, begin, finalize, drop"),
    }
}

fn main() {
    let state = State {
        next_id: AtomicU64::new(1),
        clients: Mutex::new(HashMap::new()),
    };
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(stdout, "{}", err(&e.to_string()));
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Line = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stdout, "{}", err(&format!("invalid json: {e}")));
                let _ = stdout.flush();
                continue;
            }
        };
        let out = handle(&state, parsed);
        let _ = writeln!(stdout, "{out}");
        let _ = stdout.flush();
    }
}
