//! LSP message handling: documents, workspace roots, code actions, hover and
//! the decrypted-secret guard. Pure state machine: messages in, messages out.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lsp_server::{ErrorCode, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidChangeWorkspaceFolders, DidCloseTextDocument, DidOpenTextDocument,
    Notification as _, PublishDiagnostics, ShowMessage,
};
use lsp_types::request::{CodeActionRequest, CodeActionResolveRequest, HoverRequest, Request as _};
use lsp_types::{
    CodeAction, CodeActionOptions, CodeActionParams, CodeActionProviderCapability, Diagnostic,
    DiagnosticSeverity, DidChangeTextDocumentParams, DidChangeWorkspaceFoldersParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentChanges, Hover, HoverContents,
    HoverParams, HoverProviderCapability, InitializeParams, MarkupContent, MarkupKind, MessageType,
    OneOf, OptionalVersionedTextDocumentIdentifier, PublishDiagnosticsParams, ServerCapabilities,
    ShowMessageParams, TextDocumentEdit, TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
    WorkspaceEdit, WorkspaceFoldersServerCapabilities, WorkspaceServerCapabilities,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::actions::{self, ActionData, ActionError, Revealed};
use crate::block;
use crate::document::Document;
use crate::hover::{self, HoverCache};
use crate::password::{Context, Env, PasswordStore};
use crate::vault::{self, VaultError};

const GUARD_SOURCE: &str = "ansible-vault";
/// Shorter decrypted values would flag unrelated text.
const GUARD_MIN_CHARS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub vault_password_file: Option<String>,
    pub hover: bool,
}

impl Settings {
    pub fn from_options(options: Option<&Value>) -> Self {
        let get = |key: &str| options.and_then(|o| o.get(key));
        Self {
            vault_password_file: get("vaultPasswordFile")
                .and_then(Value::as_str)
                .map(str::to_string),
            hover: get("hover").and_then(Value::as_bool).unwrap_or(true),
        }
    }
}

/// Values decrypted in a document during this session.
#[derive(Default)]
struct Guard {
    values: Vec<GuardedValue>,
    whole_file: bool,
}

/// A decrypted value is flagged while it occurs more often than it did
/// before decryption, so identical text elsewhere does not pin the warning.
struct GuardedValue {
    value: String,
    baseline: usize,
    /// Became flagged at least once (the edit may not be applied yet).
    seen: bool,
}

/// How long a password lookup failure is reused by hover, so a failing
/// password script is not re-run on every mouse rest.
const HOVER_ERROR_TTL: Duration = Duration::from_secs(15);

pub struct Server {
    docs: HashMap<String, Document>,
    folders: Vec<PathBuf>,
    root: Option<PathBuf>,
    settings: Settings,
    env: Env,
    passwords: PasswordStore,
    hover_cache: HoverCache,
    guards: HashMap<String, Guard>,
    flagged: HashSet<String>,
    hover_password_error: Option<(Instant, String)>,
}

impl Server {
    pub fn capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(actions::kinds()),
                resolve_provider: Some(true),
                work_done_progress_options: Default::default(),
            })),
            workspace: Some(WorkspaceServerCapabilities {
                workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                    supported: Some(true),
                    change_notifications: Some(OneOf::Left(true)),
                }),
                file_operations: None,
            }),
            ..Default::default()
        }
    }

    #[allow(deprecated)] // root_uri is the fallback when no workspace folder is sent
    pub fn new(params: InitializeParams, env: Env) -> Self {
        let folders = params
            .workspace_folders
            .unwrap_or_default()
            .iter()
            .filter_map(|f| uri_to_path(f.uri.as_str()))
            .collect();
        let root = params
            .root_uri
            .as_ref()
            .and_then(|u| uri_to_path(u.as_str()));
        Self {
            docs: HashMap::new(),
            folders,
            root,
            settings: Settings::from_options(params.initialization_options.as_ref()),
            env,
            passwords: PasswordStore::default(),
            hover_cache: HoverCache::default(),
            guards: HashMap::new(),
            flagged: HashSet::new(),
            hover_password_error: None,
        }
    }

    pub fn handle(&mut self, message: Message) -> Vec<Message> {
        match message {
            Message::Request(request) => self.handle_request(request),
            Message::Notification(notification) => self.handle_notification(notification),
            Message::Response(_) => Vec::new(),
        }
    }

    fn handle_request(&mut self, request: Request) -> Vec<Message> {
        let id = request.id.clone();
        let mut out = Vec::new();
        let response = match request.method.as_str() {
            CodeActionRequest::METHOD => parse(request).map(|p| self.code_actions(p)),
            CodeActionResolveRequest::METHOD => {
                parse(request).and_then(|a| self.resolve(a, &mut out))
            }
            HoverRequest::METHOD => parse(request).map(|p| self.hover(p)),
            _ => Err((
                ErrorCode::MethodNotFound,
                format!("unhandled method {}", request.method),
            )),
        };
        out.push(Message::Response(match response {
            Ok(value) => Response::new_ok(id, value),
            Err((code, message)) => Response::new_err(id, code as i32, message),
        }));
        out
    }

    fn handle_notification(&mut self, notification: Notification) -> Vec<Message> {
        let params = notification.params;
        match notification.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let Ok(p) = serde_json::from_value::<DidOpenTextDocumentParams>(params) else {
                    return Vec::new();
                };
                let uri = p.text_document.uri.as_str().to_string();
                self.docs.insert(
                    uri.clone(),
                    Document::new(p.text_document.text, p.text_document.version),
                );
                self.guard_diagnostics(&uri)
            }
            DidChangeTextDocument::METHOD => {
                let Ok(p) = serde_json::from_value::<DidChangeTextDocumentParams>(params) else {
                    return Vec::new();
                };
                let uri = p.text_document.uri.as_str().to_string();
                if let Some(change) = p.content_changes.into_iter().last() {
                    self.docs.insert(
                        uri.clone(),
                        Document::new(change.text, p.text_document.version),
                    );
                }
                self.guard_diagnostics(&uri)
            }
            DidCloseTextDocument::METHOD => {
                let Ok(p) = serde_json::from_value::<DidCloseTextDocumentParams>(params) else {
                    return Vec::new();
                };
                let uri = p.text_document.uri.as_str().to_string();
                self.docs.remove(&uri);
                self.guards.remove(&uri);
                if self.flagged.remove(&uri) {
                    return vec![publish(&uri, Vec::new())];
                }
                Vec::new()
            }
            DidChangeWorkspaceFolders::METHOD => {
                if let Ok(p) = serde_json::from_value::<DidChangeWorkspaceFoldersParams>(params) {
                    let removed: Vec<PathBuf> = p
                        .event
                        .removed
                        .iter()
                        .filter_map(|f| uri_to_path(f.uri.as_str()))
                        .collect();
                    self.folders.retain(|f| !removed.contains(f));
                    self.folders.extend(
                        p.event
                            .added
                            .iter()
                            .filter_map(|f| uri_to_path(f.uri.as_str())),
                    );
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn code_actions(&self, params: CodeActionParams) -> Value {
        let uri = params.text_document.uri.as_str();
        let Some(doc) = self.docs.get(uri) else {
            return Value::Null;
        };
        let actions = actions::list(doc, uri, params.range, params.context.only.as_deref());
        serde_json::to_value(actions).expect("serializable")
    }

    fn resolve(
        &mut self,
        mut action: CodeAction,
        out: &mut Vec<Message>,
    ) -> Result<Value, (ErrorCode, String)> {
        let data: ActionData = action
            .data
            .clone()
            .and_then(|d| serde_json::from_value(d).ok())
            .ok_or((
                ErrorCode::InvalidParams,
                "code action without ansible-vault data".to_string(),
            ))?;
        let doc = self
            .docs
            .get(&data.uri)
            .ok_or((ErrorCode::RequestFailed, "document is not open".to_string()))?
            .clone();

        let mut result = self.resolve_once(&doc, &data);
        if matches!(result, Err(ActionError::Vault(VaultError::WrongPassword))) {
            // A password script may now return another value: ask again once.
            self.passwords.invalidate();
            result = self.resolve_once(&doc, &data);
        }
        let resolved = result.map_err(|error| {
            out.push(show_error(&format!("Ansible Vault: {error}")));
            (ErrorCode::RequestFailed, error.to_string())
        })?;

        let guard = self.guards.entry(data.uri.clone()).or_default();
        match resolved.revealed {
            Revealed::Value(value) => {
                let baseline = doc.text.matches(value.as_str()).count();
                guard.values.push(GuardedValue {
                    value,
                    baseline,
                    seen: false,
                });
            }
            Revealed::File => guard.whole_file = true,
            Revealed::Nothing => {}
        }
        let uri: Uri = data
            .uri
            .parse()
            .map_err(|_| (ErrorCode::InvalidParams, "invalid uri".to_string()))?;
        action.edit = Some(WorkspaceEdit {
            document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier {
                    uri,
                    version: Some(doc.version),
                },
                edits: vec![OneOf::Left(resolved.edit)],
            }])),
            ..Default::default()
        });
        Ok(serde_json::to_value(action).expect("serializable"))
    }

    fn resolve_once(
        &mut self,
        doc: &Document,
        data: &ActionData,
    ) -> Result<actions::Resolved, ActionError> {
        let path = uri_to_path(&data.uri);
        let Self {
            passwords,
            settings,
            env,
            folders,
            root,
            ..
        } = self;
        let mut secrets = || {
            let path = path
                .as_deref()
                .ok_or("only file:// documents are supported")?;
            let document_dir = path.parent().unwrap_or(path);
            let worktree_root = worktree_root(folders, root.as_deref(), document_dir);
            let ctx = Context {
                document_dir,
                worktree_root: &worktree_root,
                setting: settings.vault_password_file.as_deref(),
                env,
            };
            passwords.secrets(&ctx).map_err(|e| e.0)
        };
        actions::resolve(doc, data, &mut secrets)
    }

    fn hover(&mut self, params: HoverParams) -> Value {
        if !self.settings.hover {
            return Value::Null;
        }
        let position = params.text_document_position_params;
        let uri = position.text_document.uri.as_str().to_string();
        let Some(doc) = self.docs.get(&uri) else {
            return Value::Null;
        };
        let Some((envelope, range)) = hover::target(doc, position.position) else {
            return Value::Null;
        };

        let markdown = match self.hover_cache.get(&envelope) {
            Some(cached) => cached.clone(),
            None => match self.decrypt_for_hover(&uri, &envelope) {
                Ok(rendered) => {
                    self.hover_cache.insert(&envelope, rendered.clone());
                    rendered
                }
                Err(message) => hover::render_error(&message),
            },
        };
        serde_json::to_value(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: markdown,
            }),
            range: Some(range),
        })
        .expect("serializable")
    }

    fn decrypt_for_hover(&mut self, uri: &str, envelope: &str) -> Result<String, String> {
        let path = uri_to_path(uri).ok_or("only file:// documents are supported")?;
        let document_dir = path.parent().unwrap_or(&path).to_path_buf();
        let worktree_root = worktree_root(&self.folders, self.root.as_deref(), &document_dir);
        let ctx = Context {
            document_dir: &document_dir,
            worktree_root: &worktree_root,
            setting: self.settings.vault_password_file.as_deref(),
            env: &self.env,
        };
        if let Some((at, message)) = &self.hover_password_error {
            if at.elapsed() < HOVER_ERROR_TTL {
                return Err(message.clone());
            }
        }
        let secrets = match self.passwords.secrets(&ctx) {
            Ok(secrets) => {
                self.hover_password_error = None;
                secrets
            }
            Err(error) => {
                self.hover_password_error = Some((Instant::now(), error.0.clone()));
                return Err(error.0);
            }
        };
        let decrypted = vault::decrypt(envelope, &secrets).map_err(|e| e.to_string())?;
        let plaintext = String::from_utf8(decrypted.plaintext)
            .map_err(|_| "decrypted data is not UTF-8 text")?;
        Ok(hover::render(
            &decrypted.version,
            decrypted.vault_id.as_deref(),
            &plaintext,
        ))
    }

    /// Flags decrypted values (and decrypted files) still present in clear.
    fn guard_diagnostics(&mut self, uri: &str) -> Vec<Message> {
        let (Some(doc), Some(guard)) = (self.docs.get(uri), self.guards.get_mut(uri)) else {
            return Vec::new();
        };
        let mut diagnostics = Vec::new();
        if guard.whole_file {
            if block::is_vault_file(doc) {
                guard.whole_file = false;
            } else {
                let (start, end) = doc.line_bounds(0);
                diagnostics.push(warning(
                    doc.range_of(start, end),
                    "Decrypted vault file: re-encrypt it before saving or committing",
                ));
            }
        }
        guard.values.retain_mut(|guarded| {
            let flagged = doc.text.matches(guarded.value.as_str()).count() > guarded.baseline;
            guarded.seen |= flagged;
            flagged || !guarded.seen
        });
        for guarded in &guard.values {
            let flagged = doc.text.matches(guarded.value.as_str()).count() > guarded.baseline;
            if !flagged || guarded.value.chars().count() < GUARD_MIN_CHARS {
                continue;
            }
            for (start, _) in doc.text.match_indices(guarded.value.as_str()) {
                diagnostics.push(warning(
                    doc.range_of(start, start + guarded.value.len()),
                    "Decrypted vault value: re-encrypt it before saving or committing",
                ));
            }
        }
        if !guard.whole_file && guard.values.is_empty() {
            self.guards.remove(uri);
        }

        if diagnostics.is_empty() && !self.flagged.remove(uri) {
            return Vec::new();
        }
        if !diagnostics.is_empty() {
            self.flagged.insert(uri.to_string());
        }
        vec![publish(uri, diagnostics)]
    }
}

fn parse<T: DeserializeOwned>(request: Request) -> Result<T, (ErrorCode, String)> {
    serde_json::from_value(request.params).map_err(|e| (ErrorCode::InvalidParams, e.to_string()))
}

fn warning(range: lsp_types::Range, message: &str) -> Diagnostic {
    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::WARNING),
        source: Some(GUARD_SOURCE.into()),
        message: message.into(),
        ..Default::default()
    }
}

fn publish(uri: &str, diagnostics: Vec<Diagnostic>) -> Message {
    let params = PublishDiagnosticsParams {
        uri: uri.parse().expect("uri came from the client"),
        diagnostics,
        version: None,
    };
    Message::Notification(Notification::new(PublishDiagnostics::METHOD.into(), params))
}

fn show_error(message: &str) -> Message {
    let params = ShowMessageParams {
        typ: MessageType::ERROR,
        message: message.into(),
    };
    Message::Notification(Notification::new(ShowMessage::METHOD.into(), params))
}

pub fn uri_to_path(uri: &str) -> Option<PathBuf> {
    url::Url::parse(uri).ok()?.to_file_path().ok()
}

/// Workspace folder containing the document (deepest first), then the
/// initialize root, then the document's own directory.
fn worktree_root(folders: &[PathBuf], root: Option<&Path>, document_dir: &Path) -> PathBuf {
    folders
        .iter()
        .filter(|f| document_dir.starts_with(f))
        .max_by_key(|f| f.components().count())
        .cloned()
        .or_else(|| {
            root.filter(|r| document_dir.starts_with(r))
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(|| document_dir.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::tests::{apply, PASSWORD};
    use lsp_server::RequestId;
    use serde_json::json;

    struct Harness {
        server: Server,
        dir: tempfile::TempDir,
        uri: String,
        version: i32,
        next_id: i32,
    }

    impl Harness {
        fn new(with_password: bool, options: Value) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("repo");
            std::fs::create_dir_all(root.join("group_vars")).unwrap();
            if with_password {
                std::fs::write(
                    root.join("ansible.cfg"),
                    "[defaults]\nvault_password_file=.vaultpass\n",
                )
                .unwrap();
                std::fs::write(root.join(".vaultpass"), format!("{PASSWORD}\n")).unwrap();
            }
            let env = Env {
                vars: HashMap::new(),
                home: Some(dir.path().join("home")),
                system_cfg: dir.path().join("none"),
            };
            let folder = url::Url::from_directory_path(&root).unwrap();
            let params: InitializeParams = serde_json::from_value(json!({
                "capabilities": {},
                "workspaceFolders": [{ "uri": folder.as_str(), "name": "repo" }],
                "initializationOptions": options,
            }))
            .unwrap();
            let uri = url::Url::from_file_path(root.join("group_vars/all.yml"))
                .unwrap()
                .to_string();
            Self {
                server: Server::new(params, env),
                dir,
                uri,
                version: 0,
                next_id: 0,
            }
        }

        fn notify(&mut self, method: &str, params: Value) -> Vec<Message> {
            self.server.handle(Message::Notification(Notification::new(
                method.into(),
                params,
            )))
        }

        fn open(&mut self, text: &str) -> Vec<Message> {
            self.version = 1;
            let uri = self.uri.clone();
            self.notify(
                DidOpenTextDocument::METHOD,
                json!({ "textDocument": { "uri": uri, "languageId": "yaml", "version": 1, "text": text } }),
            )
        }

        fn change(&mut self, text: &str) -> Vec<Message> {
            self.version += 1;
            let (uri, version) = (self.uri.clone(), self.version);
            self.notify(
                DidChangeTextDocument::METHOD,
                json!({ "textDocument": { "uri": uri, "version": version }, "contentChanges": [{ "text": text }] }),
            )
        }

        fn request(
            &mut self,
            method: &str,
            params: Value,
        ) -> (Result<Value, String>, Vec<Message>) {
            self.next_id += 1;
            let mut out = self.server.handle(Message::Request(Request::new(
                RequestId::from(self.next_id),
                method.into(),
                params,
            )));
            let Some(Message::Response(response)) = out.pop() else {
                panic!("no response")
            };
            (response.response_result.map_err(|error| error.message), out)
        }

        fn actions(&mut self, range: Value) -> Vec<Value> {
            let uri = self.uri.clone();
            let (result, _) = self.request(
                CodeActionRequest::METHOD,
                json!({ "textDocument": { "uri": uri }, "range": range, "context": { "diagnostics": [] } }),
            );
            result.unwrap().as_array().cloned().unwrap_or_default()
        }

        /// Resolves the first action, applies its edit and syncs the change.
        fn run_first(&mut self, range: Value) -> Vec<Message> {
            let action = self.actions(range).into_iter().next().expect("an action");
            let (result, _) = self.request(CodeActionResolveRequest::METHOD, action);
            let resolved: CodeAction = serde_json::from_value(result.unwrap()).unwrap();
            let Some(DocumentChanges::Edits(edits)) = resolved.edit.unwrap().document_changes
            else {
                panic!()
            };
            assert_eq!(edits[0].text_document.version, Some(self.version));
            let OneOf::Left(edit) = &edits[0].edits[0] else {
                panic!()
            };
            let doc = self.server.docs[&self.uri].clone();
            self.change(&apply(&doc, edit))
        }

        fn text(&self) -> &str {
            &self.server.docs[&self.uri].text
        }
    }

    fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Value {
        json!({ "start": { "line": sl, "character": sc }, "end": { "line": el, "character": ec } })
    }

    fn diagnostics(messages: &[Message]) -> Option<usize> {
        messages.iter().find_map(|m| match m {
            Message::Notification(n) if n.method == PublishDiagnostics::METHOD => {
                Some(n.params["diagnostics"].as_array().unwrap().len())
            }
            _ => None,
        })
    }

    #[test]
    fn encrypt_decrypt_cycle_with_guard_diagnostics() {
        let mut h = Harness::new(true, Value::Null);
        h.open("db_password: s3cr3t\nother: 1\n");

        let after_encrypt = h.run_first(range(0, 13, 0, 19));
        assert!(h.text().starts_with("db_password: !vault |\n"));
        assert_eq!(diagnostics(&after_encrypt), None);

        let after_decrypt = h.run_first(range(1, 5, 1, 5));
        assert_eq!(h.text(), "db_password: s3cr3t\nother: 1\n");
        assert_eq!(diagnostics(&after_decrypt), Some(1));

        let after_reencrypt = h.run_first(range(0, 13, 0, 19));
        assert_eq!(diagnostics(&after_reencrypt), Some(0));
        assert!(h.text().contains("$ANSIBLE_VAULT;1.1;AES256"));
    }

    #[test]
    fn guard_ignores_copies_that_existed_before_decryption() {
        let mut h = Harness::new(true, Value::Null);
        h.open("user: admin1\npassword: admin1\n");
        h.run_first(range(1, 10, 1, 16));
        let after_decrypt = h.run_first(range(2, 0, 2, 0));
        assert_eq!(h.text(), "user: admin1\npassword: admin1\n");
        assert_eq!(diagnostics(&after_decrypt), Some(2));
        assert_eq!(diagnostics(&h.run_first(range(1, 10, 1, 16))), Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn hover_does_not_rerun_a_failing_password_script() {
        use std::os::unix::fs::PermissionsExt;
        let mut h = Harness::new(false, json!({ "vaultPasswordFile": "pw.sh" }));
        let runs = h.dir.path().join("runs");
        let script = h.dir.path().join("repo/pw.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho run >> '{}'\nexit 1\n", runs.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let envelope = vault::encrypt(b"x", &vault::Secret::new("default", PASSWORD));
        let body: String = envelope.lines().map(|l| format!("  {l}\n")).collect();
        h.open(&format!("k: !vault |\n{body}"));
        let uri = h.uri.clone();
        for _ in 0..3 {
            let (result, _) = h.request(
                HoverRequest::METHOD,
                json!({ "textDocument": { "uri": uri }, "position": { "line": 1, "character": 3 } }),
            );
            assert!(result.unwrap()["contents"]["value"]
                .as_str()
                .unwrap()
                .contains("cannot decrypt"));
        }
        assert_eq!(std::fs::read_to_string(runs).unwrap().lines().count(), 1);
    }

    #[test]
    fn decrypted_file_is_flagged_until_encrypted_again() {
        let mut h = Harness::new(true, Value::Null);
        h.open("api_token: abc123\n");
        h.run_first(range(0, 0, 1, 0));
        assert!(vault::is_vault(h.text()));

        let after_decrypt = h.run_first(range(0, 0, 0, 0));
        assert_eq!(h.text(), "api_token: abc123\n");
        assert_eq!(diagnostics(&after_decrypt), Some(1));
        assert_eq!(diagnostics(&h.run_first(range(0, 0, 1, 0))), Some(0));
    }

    #[test]
    fn hover_shows_the_value_unless_disabled() {
        let mut h = Harness::new(true, Value::Null);
        h.open("k: v4lue\n");
        h.run_first(range(0, 3, 0, 8));
        let uri = h.uri.clone();
        let hover_at = |h: &mut Harness| {
            h.request(HoverRequest::METHOD, json!({ "textDocument": { "uri": uri }, "position": { "line": 2, "character": 4 } }))
                .0
                .unwrap()
        };
        let shown = hover_at(&mut h);
        assert!(shown["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("\nv4lue\n"));

        let mut quiet = Harness::new(true, json!({ "hover": false }));
        quiet.open(h.text());
        assert_eq!(hover_at(&mut quiet), Value::Null);
    }

    #[test]
    fn missing_password_shows_an_error_message() {
        let mut h = Harness::new(false, Value::Null);
        h.open("k: value\n");
        let action = h.actions(range(0, 3, 0, 8)).remove(0);
        let (result, notifications) = h.request(CodeActionResolveRequest::METHOD, action);
        assert!(result.unwrap_err().contains("no vault password configured"));
        assert!(
            matches!(&notifications[..], [Message::Notification(n)] if n.method == ShowMessage::METHOD)
        );
    }

    #[test]
    fn setting_points_to_the_password_file() {
        let mut h = Harness::new(false, json!({ "vaultPasswordFile": "secrets/pw" }));
        let pw = h.dir.path().join("repo/secrets/pw");
        std::fs::create_dir_all(pw.parent().unwrap()).unwrap();
        std::fs::write(&pw, PASSWORD).unwrap();
        h.open("k: value\n");
        h.run_first(range(0, 3, 0, 8));
        assert!(h.text().starts_with("k: !vault |"));
    }

    #[test]
    fn worktree_root_prefers_the_deepest_containing_folder() {
        let folders = vec![PathBuf::from("/w"), PathBuf::from("/w/sub")];
        assert_eq!(
            worktree_root(&folders, None, Path::new("/w/sub/x")),
            PathBuf::from("/w/sub")
        );
        assert_eq!(
            worktree_root(&folders, None, Path::new("/elsewhere")),
            PathBuf::from("/elsewhere")
        );
        assert_eq!(
            worktree_root(&[], Some(Path::new("/r")), Path::new("/r/a")),
            PathBuf::from("/r")
        );
    }
}
