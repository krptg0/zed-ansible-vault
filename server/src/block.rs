//! Line-based detection of inline `!vault |` values and whole-file vaults.
//! No YAML parser on purpose: it must work on half-edited, invalid YAML.

use crate::document::Document;
use crate::vault;

/// An inline vault value: from the `!vault` tag to its last envelope line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineVault {
    /// Byte offset of `!vault`.
    pub start: usize,
    /// Byte offset of the end of the last envelope line.
    pub end: usize,
    pub first_line: usize,
    pub last_line: usize,
    /// Envelope with indentation removed, ending with `\n`.
    pub envelope: String,
}

impl InlineVault {
    pub fn contains_line(&self, line: usize) -> bool {
        (self.first_line..=self.last_line).contains(&line)
    }
}

pub fn is_vault_file(doc: &Document) -> bool {
    vault::is_vault(&doc.text)
}

pub fn inline_vault_at(doc: &Document, line: usize) -> Option<InlineVault> {
    inline_vaults(doc)
        .into_iter()
        .find(|v| v.contains_line(line))
}

pub fn inline_vaults(doc: &Document) -> Vec<InlineVault> {
    let mut found = Vec::new();
    let mut line = 0;
    while line < doc.line_count() {
        let text = doc.line(line);
        let Some(tag) = find_vault_tag(text) else {
            line += 1;
            continue;
        };
        let parent_indent = indent_of(text);

        let mut body = Vec::new();
        let mut last_line = line;
        for next in line + 1..doc.line_count() {
            let content = doc.line(next);
            if content.trim().is_empty() {
                continue;
            }
            if indent_of(content) <= parent_indent {
                break;
            }
            body.push(content.trim());
            last_line = next;
        }

        if body.first().is_some_and(|first| vault::is_vault(first)) {
            let (line_start, _) = doc.line_bounds(line);
            let (_, end) = doc.line_bounds(last_line);
            let mut envelope = body.join("\n");
            envelope.push('\n');
            found.push(InlineVault {
                start: line_start + tag,
                end,
                first_line: line,
                last_line,
                envelope,
            });
            line = last_line + 1;
        } else {
            line += 1;
        }
    }
    found
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

/// Byte index of a `!vault` tag introducing a literal block scalar
/// (`!vault |`, `|-`, `|+`, `|2`, trailing comment), outside quotes and comments.
fn find_vault_tag(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev: Option<char> = None;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single && prev != Some('\\') => in_double = !in_double,
            '#' if !in_single && !in_double && prev.is_none_or(char::is_whitespace) => return None,
            '!' if !in_single
                && !in_double
                && prev.is_none_or(char::is_whitespace)
                && line[i..].starts_with("!vault")
                && is_block_indicator(&line[i + "!vault".len()..]) =>
            {
                return Some(i);
            }
            _ => {}
        }
        prev = Some(ch);
    }
    None
}

fn is_block_indicator(rest: &str) -> bool {
    if !rest.starts_with([' ', '\t']) {
        return false;
    }
    let rest = rest.trim_start();
    let Some(after_pipe) = rest.strip_prefix('|') else {
        return false;
    };
    let after =
        after_pipe.trim_start_matches(['-', '+', '1', '2', '3', '4', '5', '6', '7', '8', '9']);
    let after = after.trim_start();
    after.is_empty() || after.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENVELOPE: [&str; 3] = [
        "$ANSIBLE_VAULT;1.1;AES256",
        "30303031303230333034303530363037303830393061306230633064306530663130313131323133",
        "6264",
    ];

    fn doc(text: &str) -> Document {
        Document::new(text.to_string(), 1)
    }

    fn block(prefix: &str, body_indent: usize) -> String {
        let pad = " ".repeat(body_indent);
        let mut out = format!("{prefix}\n");
        for line in ENVELOPE {
            out.push_str(&format!("{pad}{line}\n"));
        }
        out
    }

    #[test]
    fn detects_key_value_with_aligned_body() {
        let text = format!("---\n{}other: value\n", block("db_password: !vault |", 13));
        let d = doc(&text);
        let found = inline_vaults(&d);
        assert_eq!(found.len(), 1);
        let v = &found[0];
        assert_eq!((v.first_line, v.last_line), (1, 4));
        assert_eq!(&d.text[v.start..v.start + 6], "!vault");
        assert!(d.text[..v.end].ends_with("6264"));
        assert_eq!(v.envelope, format!("{}\n", ENVELOPE.join("\n")));
    }

    #[test]
    fn detects_encrypt_string_indentation_and_list_items() {
        let text = format!(
            "{}passwords:\n{}",
            block("token: !vault |", 10),
            block("  - !vault |-", 6)
        );
        let found = inline_vaults(&doc(&text));
        assert_eq!(
            found.iter().map(|v| v.first_line).collect::<Vec<_>>(),
            vec![0, 5]
        );
    }

    #[test]
    fn hit_test_covers_tag_and_body_lines_only() {
        let text = format!("a: 1\n{}b: 2\n", block("key: !vault | # secret", 4));
        let d = doc(&text);
        assert!(inline_vault_at(&d, 0).is_none());
        assert!(inline_vault_at(&d, 1).is_some());
        assert!(inline_vault_at(&d, 4).is_some());
        assert!(inline_vault_at(&d, 5).is_none());
    }

    #[test]
    fn blank_lines_inside_body_are_tolerated() {
        let text = "k: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n\n  3030\n\nnext: 1\n";
        let v = inline_vault_at(&doc(text), 0).unwrap();
        assert_eq!(v.last_line, 3);
        assert_eq!(v.envelope, "$ANSIBLE_VAULT;1.1;AES256\n3030\n");
    }

    #[test]
    fn crlf_document_is_supported() {
        let text = block("k: !vault |", 2).replace('\n', "\r\n");
        let d = doc(&text);
        let v = inline_vault_at(&d, 1).unwrap();
        assert!(!v.envelope.contains('\r'));
        assert!(d.text[..v.end].ends_with("6264"));
    }

    #[test]
    fn ignores_quoted_commented_and_non_vault_blocks() {
        let quoted = "pw: \"!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  3030\"\n";
        assert!(inline_vaults(&doc(quoted)).is_empty());
        let commented = format!("# {}", block("k: !vault |", 2));
        assert!(inline_vaults(&doc(&commented)).is_empty());
        assert!(inline_vaults(&doc("k: !vault |\n  not a vault\n")).is_empty());
        assert!(inline_vaults(&doc("k: !vaulted |\n  $ANSIBLE_VAULT;1.1;AES256\n")).is_empty());
        assert!(inline_vaults(&doc("k: !vault >\n  $ANSIBLE_VAULT;1.1;AES256\n")).is_empty());
    }

    #[test]
    fn whole_file_vault_requires_header_at_start() {
        assert!(is_vault_file(&doc(&format!("{}\n", ENVELOPE.join("\n")))));
        assert!(!is_vault_file(&doc(&format!(
            "\n{}\n",
            ENVELOPE.join("\n")
        ))));
    }
}
