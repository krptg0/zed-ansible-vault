//! Drives the real binary over stdio: handshake, one request, clean exit.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn send(stdin: &mut impl Write, message: Value) {
    let body = message.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    stdin.flush().unwrap();
}

fn receive(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut length = 0;
    loop {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    stdout.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[test]
fn handshake_request_and_clean_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ansible-vault-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "capabilities": {} } }),
    );
    let init = receive(&mut stdout);
    assert_eq!(
        init["result"]["capabilities"]["codeActionProvider"]["resolveProvider"],
        true
    );
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );

    let uri = if cfg!(windows) {
        "file:///C:/repo/a.yml"
    } else {
        "file:///repo/a.yml"
    };
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": { "uri": uri, "languageId": "yaml", "version": 1, "text": "k: value\n" } } }),
    );
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": {
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 0, "character": 3 }, "end": { "line": 0, "character": 8 } },
            "context": { "diagnostics": [] } } }),
    );
    let actions = receive(&mut stdout);
    assert_eq!(
        actions["result"][0]["title"],
        "Ansible Vault: Encrypt selection"
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": null }),
    );
    assert_eq!(receive(&mut stdout)["id"], 3);
    send(&mut stdin, json!({ "jsonrpc": "2.0", "method": "exit" }));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().ok();
            panic!("server did not exit after `exit`");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success());
}
