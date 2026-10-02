//! Open documents (full sync) and LSP position ↔ byte offset conversions.
//! Zed only speaks UTF-16 positions.

use lsp_types::{Position, Range};

#[derive(Debug, Clone)]
pub struct Document {
    pub text: String,
    pub version: i32,
    /// Byte offset of the first character of every line.
    line_starts: Vec<usize>,
}

impl Document {
    pub fn new(text: String, version: i32) -> Self {
        let line_starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        Self {
            text,
            version,
            line_starts,
        }
    }

    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Byte range of a line's content, without `\n` nor a trailing `\r`.
    pub fn line_bounds(&self, line: usize) -> (usize, usize) {
        let start = self.line_starts[line];
        let mut end = self
            .line_starts
            .get(line + 1)
            .map_or(self.text.len(), |next| next - 1);
        if self.text[start..end].ends_with('\r') {
            end -= 1;
        }
        (start, end)
    }

    pub fn line(&self, line: usize) -> &str {
        let (start, end) = self.line_bounds(line);
        &self.text[start..end]
    }

    /// Line ending used by the document, reused for generated text.
    pub fn eol(&self) -> &'static str {
        if self.text.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        }
    }

    /// Byte offset of a UTF-16 position, clamped to the line content.
    pub fn offset_of(&self, position: Position) -> usize {
        let line = position.line as usize;
        if line >= self.line_count() {
            return self.text.len();
        }
        let (start, end) = self.line_bounds(line);
        let mut units = 0u32;
        for (i, ch) in self.text[start..end].char_indices() {
            if units >= position.character {
                return start + i;
            }
            units += ch.len_utf16() as u32;
        }
        end
    }

    pub fn position_of(&self, offset: usize) -> Position {
        let offset = offset.min(self.text.len());
        let line = self.line_starts.partition_point(|&start| start <= offset) - 1;
        let start = self.line_starts[line];
        let character = self.text[start..offset].encode_utf16().count() as u32;
        Position::new(line as u32, character)
    }

    pub fn range_of(&self, start: usize, end: usize) -> Range {
        Range::new(self.position_of(start), self.position_of(end))
    }

    pub fn full_range(&self) -> Range {
        self.range_of(0, self.text.len())
    }

    /// True when `range` spans the whole document, ignoring surrounding
    /// whitespace (a trailing newline outside the selection still counts).
    pub fn covers_all(&self, range: Range) -> bool {
        let start = self.offset_of(range.start);
        let end = self.offset_of(range.end);
        !self.text.trim().is_empty()
            && self.text[..start].trim().is_empty()
            && self.text[end..].trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_positions_round_trip_through_byte_offsets() {
        let doc = Document::new("a: é🔑x\nb: y\n".into(), 1);
        // `é` is 1 UTF-16 unit / 2 bytes, `🔑` 2 units / 4 bytes.
        assert_eq!(doc.offset_of(Position::new(0, 4)), 5);
        assert_eq!(doc.offset_of(Position::new(0, 6)), 9);
        assert_eq!(&doc.text[doc.offset_of(Position::new(0, 6))..][..1], "x");
        assert_eq!(doc.position_of(9), Position::new(0, 6));
        assert_eq!(doc.position_of(doc.text.len()), Position::new(2, 0));
    }

    #[test]
    fn crlf_lines_exclude_carriage_return() {
        let doc = Document::new("a: 1\r\nb: 2\r\n".into(), 1);
        assert_eq!(doc.line(0), "a: 1");
        assert_eq!(doc.eol(), "\r\n");
        assert_eq!(doc.offset_of(Position::new(0, 99)), 4);
    }

    #[test]
    fn covers_all_ignores_surrounding_whitespace() {
        let doc = Document::new("a: 1\nb: 2\n".into(), 1);
        assert!(doc.covers_all(Range::new(Position::new(0, 0), Position::new(1, 4))));
        assert!(doc.covers_all(doc.full_range()));
        assert!(!doc.covers_all(Range::new(Position::new(0, 0), Position::new(1, 2))));
        assert!(!Document::new("\n".into(), 1).covers_all(Range::default()));
    }
}
