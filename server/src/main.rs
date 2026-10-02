//! SPIKE — throwaway server used to observe how Zed drives code actions,
//! resolve, hover and showMessage. Replaced by the real server afterwards.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::{
    notification::{DidChangeTextDocument, DidOpenTextDocument, Notification as _, ShowMessage},
    request::{CodeActionRequest, CodeActionResolveRequest, HoverRequest, Request as _},
    CodeAction, CodeActionKind, CodeActionOptions, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, Hover, HoverContents, HoverParams, HoverProviderCapability,
    MarkupContent, MarkupKind, MessageType, OptionalVersionedTextDocumentIdentifier, Position,
    Range, ServerCapabilities, ShowMessageParams, TextDocumentEdit, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextEdit, WorkspaceEdit,
};

const LOG: &str = "/tmp/ansible-vault-lsp-spike.log";

fn log(line: impl AsRef<str>) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG) {
        let _ = writeln!(f, "{}", line.as_ref());
    }
}

struct Doc {
    text: String,
    version: i32,
}

fn main() {
    let (connection, io_threads) = Connection::stdio();
    let caps = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
            code_action_kinds: Some(vec![
                CodeActionKind::REFACTOR_REWRITE,
                CodeActionKind::SOURCE,
            ]),
            resolve_provider: Some(true),
            work_done_progress_options: Default::default(),
        })),
        ..Default::default()
    };
    let init = connection
        .initialize(serde_json::to_value(caps).unwrap())
        .expect("initialize");
    log(format!("=== initialize: {init}"));

    let mut docs: HashMap<String, Doc> = HashMap::new();
    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req).unwrap_or(true) {
                    break;
                }
                handle_request(&connection, &docs, req);
            }
            Message::Notification(not) => handle_notification(&mut docs, not),
            Message::Response(resp) => log(format!("response: {resp:?}")),
        }
    }
    io_threads.join().ok();
}

fn handle_notification(docs: &mut HashMap<String, Doc>, not: Notification) {
    match not.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let p: lsp_types::DidOpenTextDocumentParams =
                serde_json::from_value(not.params).unwrap();
            log(format!(
                "didOpen {} lang={} v={}",
                p.text_document.uri.as_str(),
                p.text_document.language_id,
                p.text_document.version
            ));
            docs.insert(
                p.text_document.uri.as_str().to_string(),
                Doc {
                    text: p.text_document.text,
                    version: p.text_document.version,
                },
            );
        }
        DidChangeTextDocument::METHOD => {
            let p: lsp_types::DidChangeTextDocumentParams =
                serde_json::from_value(not.params).unwrap();
            if let Some(change) = p.content_changes.into_iter().last() {
                docs.insert(
                    p.text_document.uri.as_str().to_string(),
                    Doc {
                        text: change.text,
                        version: p.text_document.version,
                    },
                );
            }
            log(format!("didChange v={}", p.text_document.version));
        }
        other => log(format!("notification {other}")),
    }
}

fn handle_request(connection: &Connection, docs: &HashMap<String, Doc>, req: Request) {
    let result = match req.method.as_str() {
        CodeActionRequest::METHOD => {
            let p: CodeActionParams = serde_json::from_value(req.params).unwrap();
            let uri = p.text_document.uri.as_str().to_string();
            let r = p.range;
            log(format!(
                "codeAction {}:{}-{}:{} only={:?} trigger={:?}",
                r.start.line,
                r.start.character,
                r.end.line,
                r.end.character,
                p.context.only,
                p.context.trigger_kind
            ));
            let mut actions = Vec::new();
            let make = |title: String| {
                CodeActionOrCommand::CodeAction(CodeAction {
                    title,
                    kind: Some(CodeActionKind::new("refactor.rewrite.ansible-vault.spike")),
                    data: Some(serde_json::json!({ "uri": uri, "range": r })),
                    ..Default::default()
                })
            };
            let doc = docs.get(&uri);
            let whole = doc.is_some_and(|d| covers_whole(&d.text, &r));
            if whole {
                actions.push(make("Ansible Vault (spike): whole buffer selected".into()));
            } else if r.start != r.end {
                actions.push(make(format!(
                    "Ansible Vault (spike): selection {}:{}-{}:{}",
                    r.start.line, r.start.character, r.end.line, r.end.character
                )));
            }
            if let Some(d) = doc {
                if d.text
                    .lines()
                    .nth(r.start.line as usize)
                    .is_some_and(|l| l.contains("!vault"))
                {
                    actions.push(make("Ansible Vault (spike): vault line".into()));
                }
            }
            serde_json::to_value(actions).unwrap()
        }
        CodeActionResolveRequest::METHOD => {
            let mut action: CodeAction = serde_json::from_value(req.params).unwrap();
            log(format!("RESOLVE {}", action.title));
            let data = action.data.clone().unwrap();
            let uri_str = data["uri"].as_str().unwrap().to_string();
            let range: Range = serde_json::from_value(data["range"].clone()).unwrap();
            let version = docs.get(&uri_str).map(|d| d.version);
            show(
                connection,
                &format!("spike: resolve called for '{}'", action.title),
            );
            let insert_at = Position::new(range.start.line, 0);
            action.edit = Some(WorkspaceEdit {
                document_changes: Some(lsp_types::DocumentChanges::Edits(vec![TextDocumentEdit {
                    text_document: OptionalVersionedTextDocumentIdentifier {
                        uri: uri_str.parse().unwrap(),
                        version,
                    },
                    edits: vec![lsp_types::OneOf::Left(TextEdit::new(
                        Range::new(insert_at, insert_at),
                        "# spike was here\n".into(),
                    ))],
                }])),
                ..Default::default()
            });
            serde_json::to_value(action).unwrap()
        }
        HoverRequest::METHOD => {
            let p: HoverParams = serde_json::from_value(req.params).unwrap();
            let pos = p.text_document_position_params.position;
            log(format!("hover {}:{}", pos.line, pos.character));
            serde_json::to_value(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!(
                        "**Ansible Vault (spike)**\n\n```yaml\nline: {}\n```",
                        pos.line
                    ),
                }),
                range: Some(Range::new(
                    Position::new(pos.line, 0),
                    Position::new(pos.line + 1, 0),
                )),
            })
            .unwrap()
        }
        other => {
            log(format!("request {other}"));
            serde_json::Value::Null
        }
    };
    connection
        .sender
        .send(Message::Response(Response::new_ok(req.id, result)))
        .unwrap();
}

fn show(connection: &Connection, message: &str) {
    let params = ShowMessageParams {
        typ: MessageType::INFO,
        message: message.into(),
    };
    connection
        .sender
        .send(Message::Notification(Notification::new(
            ShowMessage::METHOD.into(),
            params,
        )))
        .unwrap();
}

fn covers_whole(text: &str, r: &Range) -> bool {
    let lines: Vec<&str> = text.split('\n').collect();
    let last = lines.len().saturating_sub(1) as u32;
    let last_len = lines.last().map(|l| l.encode_utf16().count()).unwrap_or(0) as u32;
    r.start == Position::new(0, 0)
        && r.end.line >= last
        && (r.end.line > last || r.end.character >= last_len)
}
