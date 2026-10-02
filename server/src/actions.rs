//! Code actions. Listing only detects what applies (Zed asks on every cursor
//! move); all cryptography happens in `codeAction/resolve`, which re-detects
//! the action on the current text since Zed may resolve a stale list.

use lsp_types::{CodeAction, CodeActionKind, Range, TextEdit};
use serde::{Deserialize, Serialize};

use crate::block;
use crate::document::Document;
use crate::vault::{self, Secret, VaultError};

pub const DECRYPT_VALUE: &str = "refactor.rewrite.ansible-vault.decrypt";
pub const DECRYPT_FILE: &str = "source.ansible-vault.decrypt-file";
pub const ENCRYPT_SELECTION: &str = "refactor.rewrite.ansible-vault.encrypt";
pub const ENCRYPT_FILE: &str = "source.ansible-vault.encrypt-file";

pub fn kinds() -> Vec<CodeActionKind> {
    [DECRYPT_VALUE, DECRYPT_FILE, ENCRYPT_SELECTION, ENCRYPT_FILE]
        .into_iter()
        .map(CodeActionKind::from)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Op {
    DecryptValue,
    DecryptFile,
    EncryptSelection,
    EncryptFile,
}

impl Op {
    fn title(self) -> &'static str {
        match self {
            Self::DecryptValue => "Ansible Vault: Decrypt value",
            Self::DecryptFile => "Ansible Vault: Decrypt file",
            Self::EncryptSelection => "Ansible Vault: Encrypt selection",
            Self::EncryptFile => "Ansible Vault: Encrypt file",
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::DecryptValue => DECRYPT_VALUE,
            Self::DecryptFile => DECRYPT_FILE,
            Self::EncryptSelection => ENCRYPT_SELECTION,
            Self::EncryptFile => ENCRYPT_FILE,
        }
    }
}

/// Payload carried by a listed action until it is resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionData {
    pub uri: String,
    pub op: Op,
    pub range: Range,
}

/// Actions applicable to `range`, most specific first (Enter runs the first).
pub fn list(
    doc: &Document,
    uri: &str,
    range: Range,
    only: Option<&[CodeActionKind]>,
) -> Vec<CodeAction> {
    let mut ops = Vec::new();
    if block::inline_vault_at(doc, range.start.line as usize).is_some() {
        ops.push(Op::DecryptValue);
    }
    if block::is_vault_file(doc) {
        ops.push(Op::DecryptFile);
    } else if range.start != range.end {
        if doc.covers_all(range) {
            ops.push(Op::EncryptFile);
        } else if selection_to_encrypt(doc, range).is_some() {
            ops.push(Op::EncryptSelection);
        }
    }

    ops.into_iter()
        .filter(|op| {
            only.is_none_or(|kinds| kinds.iter().any(|k| kind_matches(op.kind(), k.as_str())))
        })
        .map(|op| CodeAction {
            title: op.title().to_string(),
            kind: Some(CodeActionKind::from(op.kind())),
            data: Some(
                serde_json::to_value(ActionData {
                    uri: uri.to_string(),
                    op,
                    range,
                })
                .expect("serializable"),
            ),
            ..Default::default()
        })
        .collect()
}

fn kind_matches(kind: &str, requested: &str) -> bool {
    requested.is_empty()
        || kind == requested
        || kind
            .strip_prefix(requested)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Selected text eligible for inline encryption: non-blank, not already a
/// vault, not starting inside a vault block.
fn selection_to_encrypt(doc: &Document, range: Range) -> Option<(usize, usize)> {
    let (start, end) = (doc.offset_of(range.start), doc.offset_of(range.end));
    let text = &doc.text[start..end];
    let inside_vault = block::inline_vault_at(doc, range.start.line as usize).is_some();
    (!text.trim().is_empty() && !text.contains(vault::HEADER) && !inside_vault)
        .then_some((start, end))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    /// The action no longer applies to the current text.
    Stale(String),
    Password(String),
    Vault(VaultError),
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale(detail) | Self::Password(detail) => f.write_str(detail),
            Self::Vault(error) => error.fmt(f),
        }
    }
}

/// What a resolved action reveals in clear, for the decrypted-secret guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revealed {
    Nothing,
    Value(String),
    File,
}

#[derive(Debug)]
pub struct Resolved {
    pub edit: TextEdit,
    pub revealed: Revealed,
}

/// Computes the edit of an action against the current document. `secrets` is
/// only called once the action is known to still apply.
pub fn resolve(
    doc: &Document,
    data: &ActionData,
    secrets: &mut dyn FnMut() -> Result<Vec<Secret>, String>,
) -> Result<Resolved, ActionError> {
    let mut secrets = || secrets().map_err(ActionError::Password);
    match data.op {
        Op::DecryptValue => {
            let found = block::inline_vault_at(doc, data.range.start.line as usize)
                .ok_or_else(|| ActionError::Stale("no vault value at the cursor anymore".into()))?;
            let plaintext = decrypt_text(&found.envelope, &secrets()?)?;
            Ok(Resolved {
                edit: TextEdit::new(doc.range_of(found.start, found.end), plaintext.clone()),
                revealed: Revealed::Value(plaintext),
            })
        }
        Op::DecryptFile => {
            if !block::is_vault_file(doc) {
                return Err(ActionError::Stale(
                    "the file is not vault encrypted anymore".into(),
                ));
            }
            let plaintext = decrypt_text(&doc.text, &secrets()?)?;
            Ok(Resolved {
                edit: TextEdit::new(doc.full_range(), plaintext),
                revealed: Revealed::File,
            })
        }
        Op::EncryptSelection => {
            let (start, end) = selection_to_encrypt(doc, data.range).ok_or_else(|| {
                ActionError::Stale("nothing to encrypt in the selection anymore".into())
            })?;
            let secret = first_secret(secrets()?)?;
            let envelope = vault::encrypt(&doc.text.as_bytes()[start..end], &secret);
            let indent = body_indent(doc, data.range.start.line as usize, start);
            Ok(Resolved {
                edit: TextEdit::new(
                    doc.range_of(start, end),
                    inline_block(&envelope, indent, doc.eol()),
                ),
                revealed: Revealed::Nothing,
            })
        }
        Op::EncryptFile => {
            if block::is_vault_file(doc) || doc.text.trim().is_empty() {
                return Err(ActionError::Stale("nothing to encrypt in this file".into()));
            }
            let secret = first_secret(secrets()?)?;
            let envelope = vault::encrypt(doc.text.as_bytes(), &secret);
            let text = envelope
                .lines()
                .map(|line| format!("{line}{}", doc.eol()))
                .collect();
            Ok(Resolved {
                edit: TextEdit::new(doc.full_range(), text),
                revealed: Revealed::Nothing,
            })
        }
    }
}

pub fn decrypt_text(envelope: &str, secrets: &[Secret]) -> Result<String, ActionError> {
    let decrypted = vault::decrypt(envelope, secrets).map_err(ActionError::Vault)?;
    String::from_utf8(decrypted.plaintext).map_err(|_| {
        ActionError::Vault(VaultError::Format(
            "decrypted data is not UTF-8 text".into(),
        ))
    })
}

fn first_secret(secrets: Vec<Secret>) -> Result<Secret, ActionError> {
    secrets
        .into_iter()
        .next()
        .ok_or_else(|| ActionError::Password("no vault secret available".into()))
}

/// Envelope lines align with the selection start (like the VSCode
/// extension), but always sit deeper than the line's own indentation.
fn body_indent(doc: &Document, line: usize, start: usize) -> usize {
    let (line_start, _) = doc.line_bounds(line);
    let column = doc.text[line_start..start].chars().count();
    let line_indent = doc.line(line).len() - doc.line(line).trim_start().len();
    column.max(line_indent + 2)
}

fn inline_block(envelope: &str, indent: usize, eol: &str) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::from("!vault |");
    for line in envelope.lines() {
        out.push_str(eol);
        out.push_str(&pad);
        out.push_str(line);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vault::DEFAULT_VAULT_ID;
    use lsp_types::Position;

    pub const PASSWORD: &str = "test-password-123";

    pub fn apply(doc: &Document, edit: &TextEdit) -> String {
        let (start, end) = (
            doc.offset_of(edit.range.start),
            doc.offset_of(edit.range.end),
        );
        format!(
            "{}{}{}",
            &doc.text[..start],
            edit.new_text,
            &doc.text[end..]
        )
    }

    fn secrets() -> Result<Vec<Secret>, String> {
        Ok(vec![Secret::new(DEFAULT_VAULT_ID, PASSWORD)])
    }

    fn vault_doc() -> Document {
        let envelope = crate::vault::encrypt(b"x", &secrets().unwrap()[0]);
        let body: String = envelope.lines().map(|l| format!("  {l}\n")).collect();
        Document::new(format!("k: !vault |\n{body}"), 1)
    }

    fn titles(actions: &[CodeAction]) -> Vec<&str> {
        actions.iter().map(|a| a.title.as_str()).collect()
    }

    fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Range {
        Range::new(Position::new(sl, sc), Position::new(el, ec))
    }

    fn run(doc: &Document, op: Op, range: Range) -> Result<Resolved, ActionError> {
        resolve(
            doc,
            &ActionData {
                uri: "file:///x.yml".into(),
                op,
                range,
            },
            &mut secrets,
        )
    }

    #[test]
    fn plain_cursor_offers_nothing() {
        let doc = Document::new("a: hello\nb: 2\n".into(), 1);
        assert!(list(&doc, "u", range(0, 3, 0, 3), None).is_empty());
    }

    #[test]
    fn encrypt_selection_then_decrypt_value_round_trips() {
        let doc = Document::new("db_password: s3cr3t\nnext: 1\n".into(), 1);
        let sel = range(0, 13, 0, 19);
        assert_eq!(
            titles(&list(&doc, "u", sel, None)),
            ["Ansible Vault: Encrypt selection"]
        );

        let encrypted = Document::new(
            apply(&doc, &run(&doc, Op::EncryptSelection, sel).unwrap().edit),
            2,
        );
        assert!(encrypted
            .text
            .starts_with("db_password: !vault |\n             $ANSIBLE_VAULT;1.1;AES256\n"));
        assert!(encrypted.text.ends_with("\nnext: 1\n"));

        let cursor = range(2, 20, 2, 20);
        assert_eq!(
            titles(&list(&encrypted, "u", cursor, None)),
            ["Ansible Vault: Decrypt value"]
        );
        let resolved = run(&encrypted, Op::DecryptValue, cursor).unwrap();
        assert_eq!(resolved.revealed, Revealed::Value("s3cr3t".into()));
        assert_eq!(apply(&encrypted, &resolved.edit), doc.text);
    }

    #[test]
    fn body_is_indented_deeper_than_the_line() {
        let doc = Document::new("list:\n  - token\n".into(), 1);
        let sel = range(1, 0, 1, 9);
        let text = apply(&doc, &run(&doc, Op::EncryptSelection, sel).unwrap().edit);
        assert!(text.contains("!vault |\n    $ANSIBLE_VAULT"), "{text}");
    }

    #[test]
    fn crlf_document_keeps_crlf() {
        let doc = Document::new("k: value\r\n".into(), 1);
        let text = apply(
            &doc,
            &run(&doc, Op::EncryptSelection, range(0, 3, 0, 8))
                .unwrap()
                .edit,
        );
        assert!(text.starts_with("k: !vault |\r\n   $ANSIBLE_VAULT"));
        assert!(!text.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn whole_buffer_selection_offers_encrypt_file_and_round_trips() {
        let doc = Document::new("api_token: abc123\nport: 8080\n".into(), 1);
        let all = range(0, 0, 2, 0);
        assert_eq!(
            titles(&list(&doc, "u", all, None)),
            ["Ansible Vault: Encrypt file"]
        );

        let encrypted = Document::new(
            apply(&doc, &run(&doc, Op::EncryptFile, all).unwrap().edit),
            2,
        );
        assert!(block::is_vault_file(&encrypted));
        assert_eq!(
            titles(&list(&encrypted, "u", range(3, 0, 3, 0), None)),
            ["Ansible Vault: Decrypt file"]
        );

        let resolved = run(&encrypted, Op::DecryptFile, range(3, 0, 3, 0)).unwrap();
        assert_eq!(resolved.revealed, Revealed::File);
        assert_eq!(apply(&encrypted, &resolved.edit), doc.text);
    }

    #[test]
    fn selection_inside_a_vault_offers_decrypt_not_encrypt() {
        let doc = vault_doc();
        assert_eq!(
            titles(&list(&doc, "u", range(1, 2, 2, 10), None)),
            ["Ansible Vault: Decrypt value"]
        );
    }

    #[test]
    fn only_filter_matches_kind_hierarchy() {
        let doc = Document::new("k: value\nx: 1\n".into(), 1);
        let sel = range(0, 3, 0, 8);
        let refactor = [CodeActionKind::REFACTOR];
        let source = [CodeActionKind::SOURCE];
        assert_eq!(list(&doc, "u", sel, Some(&refactor)).len(), 1);
        assert!(list(&doc, "u", sel, Some(&source)).is_empty());
    }

    #[test]
    fn stale_actions_fail_without_asking_for_secrets() {
        let doc = Document::new("k: value\n".into(), 1);
        let mut asked = false;
        let mut secrets = || {
            asked = true;
            secrets()
        };
        let data = ActionData {
            uri: "u".into(),
            op: Op::DecryptValue,
            range: range(0, 0, 0, 0),
        };
        assert!(matches!(
            resolve(&doc, &data, &mut secrets),
            Err(ActionError::Stale(_))
        ));
        assert!(!asked);
    }

    #[test]
    fn wrong_password_surfaces_as_vault_error() {
        let doc = vault_doc();
        let data = ActionData {
            uri: "u".into(),
            op: Op::DecryptValue,
            range: range(0, 0, 0, 0),
        };
        let mut bad = || Ok(vec![Secret::new(DEFAULT_VAULT_ID, "bad")]);
        assert_eq!(
            resolve(&doc, &data, &mut bad).unwrap_err(),
            ActionError::Vault(VaultError::WrongPassword)
        );
    }
}
