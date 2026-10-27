//! Safe rendering of untrusted text in a terminal.

use std::io::IsTerminal;

use neccrit_core::contact::is_invisible_format_char;

/// Runs of more blank characters than this are shown as `<N spaces>`.
const MAX_BLANK_RUN: usize = 8;

/// Highlighting of text produced by neccrit itself (sender labels). Message
/// bodies can never contain escape sequences (see [`sanitize`]), so a forged
/// "sender: text" line inside a message cannot look highlighted.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    enabled: bool,
}

impl Style {
    /// Highlight only on a real terminal and unless `NO_COLOR` is set.
    pub fn detect() -> Self {
        Self { enabled: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }

    /// Bold green for verified contacts, bold yellow for unverified ones.
    pub fn sender(&self, label: &str, verified: bool) -> String {
        if self.enabled {
            let colour = if verified { 32 } else { 33 };
            format!("\u{1b}[1;{colour}m{label}\u{1b}[0m")
        } else {
            label.to_owned()
        }
    }
}

/// Make untrusted text safe to print:
///
/// * terminal control sequences (ESC, other C0/C1 controls, DEL) are shown
///   as `<U+XXXX>` so a peer cannot move the cursor, change colours, spoof
///   lines or retitle the terminal;
/// * invisible and text-reordering characters (bidi overrides, zero-width
///   characters, Unicode tags) are made visible the same way, so hidden
///   content and spoofed text direction cannot go unnoticed;
/// * line breaks are kept but continuation lines are indented with `indent`,
///   and long runs of blanks (which could push text onto a fresh terminal
///   row) are shown as `<N spaces>`. Together with highlighted sender labels
///   ([`Style`]) this keeps a message from passing as another sender's line.
pub fn sanitize(text: &str, indent: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut blanks = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        // U+2028/U+2029 count as whitespace but break lines; they are escaped below.
        let is_blank = c.is_whitespace() && !matches!(c, '\n' | '\r') && !is_invisible_format_char(c);
        if is_blank {
            blanks += if c == '\t' { 4 } else { 1 };
            continue;
        }
        flush_blanks(&mut out, &mut blanks);
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                out.push('\n');
                out.push_str(indent);
            }
            c if c.is_control() || is_invisible_format_char(c) => {
                out.push_str(&format!("<U+{:04X}>", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    flush_blanks(&mut out, &mut blanks);
    out
}

fn flush_blanks(out: &mut String, blanks: &mut usize) {
    if *blanks > MAX_BLANK_RUN {
        out.push_str(&format!("<{blanks} spaces>"));
    } else {
        out.extend(std::iter::repeat_n(' ', *blanks));
    }
    *blanks = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_unchanged() {
        assert_eq!(sanitize("Hallo, wie geht's? 👋 ÄÖÜ", ""), "Hallo, wie geht's? 👋 ÄÖÜ");
    }

    #[test]
    fn escapes_terminal_controls() {
        let s = sanitize("\u{1b}[2J\u{1b}]0;pwned\u{7}x\u{9b}y\u{7f}", "");
        assert!(!s.chars().any(char::is_control), "{s:?}");
        assert!(s.contains("<U+001B>"));
        assert!(s.contains("<U+009B>"));
        assert!(s.contains("<U+007F>"));
    }

    #[test]
    fn reveals_invisible_and_bidi() {
        assert_eq!(sanitize("a\u{200b}b", ""), "a<U+200B>b");
        assert_eq!(sanitize("evil\u{202e}gpj.exe", ""), "evil<U+202E>gpj.exe");
        assert_eq!(sanitize("x\u{e0041}", ""), "x<U+E0041>");
    }

    #[test]
    fn collapses_long_blank_runs() {
        assert_eq!(sanitize("a        b", ""), "a        b");
        assert_eq!(sanitize(&format!("x{}[12:00] alice: hi", " ".repeat(2400)), ""), "x<2400 spaces>[12:00] alice: hi");
        assert_eq!(sanitize("a\t\t\tb", ""), "a<12 spaces>b");
        assert_eq!(sanitize("a\u{3000}\u{a0}b", ""), "a  b");
        assert_eq!(sanitize("end   ", ""), "end   ");
    }

    #[test]
    fn reveals_other_invisible_characters() {
        for c in ['\u{1BCA0}', '\u{2028}', '\u{2029}', '\u{0600}', '\u{110BD}', '\u{13430}', '\u{FEFF}'] {
            let shown = sanitize(&format!("a{c}b"), "");
            assert_eq!(shown, format!("a<U+{:04X}>b", u32::from(c)));
        }
    }

    #[test]
    fn style_only_adds_escapes_when_enabled() {
        assert_eq!(Style { enabled: false }.sender("alice:", true), "alice:");
        assert!(Style { enabled: true }.sender("alice:", false).starts_with('\u{1b}'));
    }

    #[test]
    fn indents_continuation_lines() {
        assert_eq!(sanitize("one\ntwo\r\nthree\rfour", "  | "), "one\n  | two\n  | three\n  | four");
    }
}
