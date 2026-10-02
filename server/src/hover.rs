//! Hover preview of decrypted values. Zed hovers on mouse rest, so results
//! are cached by envelope digest to avoid re-running PBKDF2 every time.

use std::collections::{HashMap, VecDeque};

use lsp_types::{Position, Range};
use sha2::{Digest, Sha256};

use crate::block;
use crate::document::Document;

const CACHE_CAPACITY: usize = 256;

/// The envelope under `position` and the range it covers.
pub fn target(doc: &Document, position: Position) -> Option<(String, Range)> {
    let line = position.line as usize;
    if let Some(found) = block::inline_vault_at(doc, line) {
        return Some((found.envelope, doc.range_of(found.start, found.end)));
    }
    if block::is_vault_file(doc) && line == 0 {
        let (start, end) = doc.line_bounds(0);
        return Some((doc.text.clone(), doc.range_of(start, end)));
    }
    None
}

pub fn render(version: &str, vault_id: Option<&str>, plaintext: &str) -> String {
    let fence = "`".repeat(longest_backtick_run(plaintext).max(2) + 1);
    let id = vault_id.unwrap_or(crate::vault::DEFAULT_VAULT_ID);
    format!("**Ansible Vault** · `{version}` · id `{id}`\n\n{fence}text\n{plaintext}\n{fence}")
}

pub fn render_error(message: &str) -> String {
    format!("**Ansible Vault** · cannot decrypt\n\n{message}")
}

fn longest_backtick_run(text: &str) -> usize {
    text.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// Bounded cache of rendered hovers keyed by envelope SHA-256.
#[derive(Default)]
pub struct HoverCache {
    entries: HashMap<[u8; 32], String>,
    order: VecDeque<[u8; 32]>,
}

impl HoverCache {
    pub fn get(&self, envelope: &str) -> Option<&String> {
        self.entries.get(&digest(envelope))
    }

    pub fn insert(&mut self, envelope: &str, rendered: String) {
        let key = digest(envelope);
        if self.entries.insert(key, rendered).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > CACHE_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }
}

fn digest(envelope: &str) -> [u8; 32] {
    let normalized: String = envelope.split_whitespace().collect();
    Sha256::digest(normalized.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_is_longer_than_any_backtick_run_in_the_value() {
        let rendered = render("1.1", None, "a ```` b");
        assert!(
            rendered.contains("`````text\na ```` b\n`````"),
            "{rendered}"
        );
        assert!(render("1.2", Some("dev"), "x").starts_with("**Ansible Vault** · `1.2` · id `dev`"));
    }

    #[test]
    fn cache_is_bounded_and_ignores_indentation() {
        let mut cache = HoverCache::default();
        cache.insert("$ANSIBLE_VAULT;1.1;AES256\n3030\n", "first".into());
        assert_eq!(
            cache
                .get("  $ANSIBLE_VAULT;1.1;AES256\n  3030\n")
                .map(String::as_str),
            Some("first")
        );
        for i in 0..CACHE_CAPACITY {
            cache.insert(&format!("e{i}"), String::new());
        }
        assert!(cache.get("$ANSIBLE_VAULT;1.1;AES256\n3030\n").is_none());
        assert_eq!(cache.entries.len(), CACHE_CAPACITY);
    }

    #[test]
    fn target_finds_inline_block_and_file_header_only() {
        let doc = Document::new(
            "k: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  3030\nx: 1\n".into(),
            1,
        );
        assert!(target(&doc, Position::new(2, 1)).is_some());
        assert!(target(&doc, Position::new(3, 1)).is_none());
        let file = Document::new("$ANSIBLE_VAULT;1.1;AES256\n3030\n".into(), 1);
        assert!(target(&file, Position::new(0, 3)).is_some());
        assert!(target(&file, Position::new(1, 0)).is_none());
    }
}
