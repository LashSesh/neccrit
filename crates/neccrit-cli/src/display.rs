//! Safe rendering of untrusted text in a terminal.

use neccrit_core::contact::is_invisible_format_char;

/// Make untrusted text safe to print:
///
/// * terminal control sequences (ESC, other C0/C1 controls, DEL) are shown
///   as `<U+XXXX>` so a peer cannot move the cursor, change colours, spoof
///   lines or retitle the terminal;
/// * invisible and text-reordering characters (bidi overrides, zero-width
///   characters, Unicode tags) are made visible the same way, so hidden
///   content and spoofed text direction cannot go unnoticed;
/// * line breaks are kept but continuation lines are indented with `indent`
///   so that a message cannot imitate another sender's line.
pub fn sanitize(text: &str, indent: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                out.push('\n');
                out.push_str(indent);
            }
            '\t' => out.push_str("    "),
            c if c.is_control() || is_invisible_format_char(c) => {
                out.push_str(&format!("<U+{:04X}>", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
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
    fn indents_continuation_lines() {
        assert_eq!(sanitize("one\ntwo\r\nthree\rfour", "  | "), "one\n  | two\n  | three\n  | four");
    }
}
