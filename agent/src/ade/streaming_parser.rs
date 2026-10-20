//! Streaming JSON-completion detector (Sub-tappa 6.8).
//!
//! Tracks brace depth across a token stream while honouring JSON
//! string and escape semantics so the engine can stop the decode
//! loop the moment the verdict object closes — without ever waiting
//! to parse the full string. Foundation-Sec is configured with
//! `max_output_tokens = 1500`; the verdict typically closes around
//! token 400-500, so this saves ~1000 tokens of CPU work per
//! inference on the memory-bound CCX23 reference host.
//!
//! The detector only flags the **first** outermost object close. The
//! engine accumulates the full decoded text separately and feeds it
//! to [`super::parser::VerdictParser`]; this module's only job is to
//! say "yes, the JSON is structurally complete — you can stop now".
//! It reads the stream as the parser reads the output: a `<think> …
//! </think>` block first, then the first balanced `{ … }` after it.

/// The longer of the two reasoning markers, in characters.
const MARKER_CHARS: usize = "</think>".len();

/// Brace-depth tracker that recognises a complete top-level JSON
/// object inside a (possibly noisy) text stream.
///
/// Behaviour:
///
/// - Ignores every character before the first `{` — quotes and `}`
///   included. Foundation-Sec sometimes emits prose like
///   `Verdict: {…}`; the leading characters are simply absorbed.
///   External audit LLMP-010 (NN-AUD-322): a `}` there took the depth to
///   -1 for good, and a `"` switched string mode on before the object,
///   so that an odd count of quotes read the object's own quotes
///   inverted; either way the object never closed and the decode ran to
///   `max_output_tokens`.
/// - Skips a `<think> … </think>` reasoning block before the object, as
///   the parser strips it: a balanced `{ … }` in the reasoning stopped
///   the decode there, before `</think>`, and the parser then refused the
///   output (an unclosed reasoning block) — an Escalate for a verdict
///   the model had not written yet. Markers split across chunks are
///   matched.
/// - Tracks string mode inside the object: `"`-delimited spans don't
///   contribute to brace depth. Escaped quotes (`\"`) inside strings
///   are honoured.
/// - Returns `true` from [`feed`](Self::feed) the first time the
///   outermost object closes. Subsequent calls keep returning `false`
///   so the engine can safely keep feeding text past the boundary
///   without re-firing.
#[derive(Debug, Default)]
pub struct StreamingJsonDetector {
    /// The last characters before the object, at most
    /// [`MARKER_CHARS`]: where a reasoning marker is matched.
    tail: String,
    in_think: bool,
    in_json: bool,
    brace_depth: u32,
    in_string: bool,
    escape_next: bool,
    completed: bool,
}

impl StreamingJsonDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `chunk` and report whether the outermost JSON object has
    /// just closed. Idempotent after the first completion: once `true`
    /// is returned, all further `feed` calls return `false`. Nothing is
    /// kept of the text but the few characters a marker needs (the
    /// engine has the output).
    pub fn feed(&mut self, chunk: &str) -> bool {
        if self.completed {
            return false;
        }
        for c in chunk.chars() {
            if !self.in_json {
                self.before_object(c);
                continue;
            }
            if self.escape_next {
                self.escape_next = false;
                continue;
            }
            if self.in_string {
                match c {
                    '\\' => self.escape_next = true,
                    '"' => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => self.in_string = true,
                '{' => self.brace_depth += 1,
                '}' => {
                    self.brace_depth = self.brace_depth.saturating_sub(1);
                    if self.brace_depth == 0 {
                        self.completed = true;
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// One character before the object: a reasoning marker, the object's
    /// first `{`, or nothing.
    fn before_object(&mut self, c: char) {
        self.tail.push(c);
        if self.tail.chars().count() > MARKER_CHARS {
            let first = self.tail.chars().next().map_or(0, char::len_utf8);
            self.tail.drain(..first);
        }
        if self.in_think {
            if self.tail.ends_with("</think>") {
                self.in_think = false;
                self.tail.clear();
            }
            return;
        }
        if self.tail.ends_with("<think>") {
            self.in_think = true;
            self.tail.clear();
        } else if c == '{' {
            self.in_json = true;
            self.brace_depth = 1;
            self.tail.clear();
        }
    }

    /// `true` if [`feed`](Self::feed) has reported a complete object
    /// at any point in the stream's history.
    pub fn is_complete(&self) -> bool {
        self.completed
    }
}

#[cfg(test)]
mod tests {
    use super::StreamingJsonDetector;

    /// Feeds `s` one character at a time; the index of the character at
    /// which the detector fired.
    fn fires_at(s: &str) -> Option<usize> {
        let mut d = StreamingJsonDetector::new();
        let mut at = None;
        for (i, ch) in s.chars().enumerate() {
            let mut buf = [0u8; 4];
            if d.feed(ch.encode_utf8(&mut buf)) {
                assert!(at.is_none(), "fired twice");
                at = Some(i);
            }
        }
        at
    }

    #[test]
    fn empty_input_does_not_complete() {
        let mut d = StreamingJsonDetector::new();
        assert!(!d.feed(""));
        assert!(!d.is_complete());
    }

    #[test]
    fn simple_object_completes_at_closing_brace() {
        let mut d = StreamingJsonDetector::new();
        assert!(d.feed("{\"a\":1}"));
        assert!(d.is_complete());
    }

    #[test]
    fn nested_object_only_completes_at_outermost_close() {
        let mut d = StreamingJsonDetector::new();
        // Feed the inner close first — must NOT complete here.
        assert!(!d.feed("{\"a\":{\"b\":1}"));
        assert!(!d.is_complete());
        // Feed the outer close — now it completes.
        assert!(d.feed("}"));
        assert!(d.is_complete());
    }

    #[test]
    fn braces_inside_strings_are_ignored() {
        let mut d = StreamingJsonDetector::new();
        // The string "}{}" contains both kinds of brace and must
        // NOT contribute to brace_depth.
        assert!(d.feed("{\"a\":\"}{}\"}"));
        assert!(d.is_complete());
    }

    #[test]
    fn escaped_quotes_inside_strings_dont_break_string_mode() {
        let mut d = StreamingJsonDetector::new();
        // The escaped \" must keep us in_string until the unescaped ".
        assert!(d.feed("{\"a\":\"x\\\"y\"}"));
        assert!(d.is_complete());
    }

    #[test]
    fn progressive_one_char_at_a_time_completes_at_correct_boundary() {
        let s = "{\"k\":[1,2,3],\"o\":{\"n\":true}}";
        assert_eq!(fires_at(s), Some(s.chars().count() - 1));
    }

    #[test]
    fn prose_before_json_is_absorbed_and_completion_fires_at_object_close() {
        let mut d = StreamingJsonDetector::new();
        // Foundation-Sec sometimes emits prose before the JSON
        // payload. The detector must ignore the lead-in, then
        // complete exactly at the outermost `}`.
        assert!(!d.feed("Here is the verdict for the analyst:\n"));
        assert!(d.feed("{\"verdict\":\"Allow\"}"));
        assert!(d.is_complete());
    }

    #[test]
    fn second_object_in_stream_does_not_re_fire_completion() {
        let mut d = StreamingJsonDetector::new();
        // First completion fires.
        assert!(d.feed("{\"a\":1}"));
        // The model keeps emitting tokens; they must not re-signal
        // completion (the engine has already told the backend to stop).
        assert!(!d.feed(" trailing prose {\"b\":2} more"));
        assert!(d.is_complete());
    }

    /// External audit LLMP-010: a `}` before the object took the depth
    /// to -1 for good.
    #[test]
    fn stray_closing_brace_before_json_still_completes() {
        let mut d = StreamingJsonDetector::new();
        assert!(!d.feed("Note: } and }} are not the verdict.\n"));
        assert!(d.feed("{\"verdict\":\"Allow\",\"o\":{\"n\":1}}"));
        let s = "x}{\"a\":1}";
        assert_eq!(fires_at(s), Some(s.chars().count() - 1));
    }

    /// External audit LLMP-010, wider than reported: an odd count of
    /// quotes before the object read its own quotes inverted.
    #[test]
    fn odd_quote_in_preamble_still_completes() {
        let mut d = StreamingJsonDetector::new();
        assert!(!d.feed("The process \"xmrig looks like a miner.\n"));
        assert!(d.feed("{\"verdict\":\"Kill\",\"note\":\"a } in a string\"}"));
        let s = "\"\"\" {\"a\":\"b\"}";
        assert_eq!(fires_at(s), Some(s.chars().count() - 1));
    }

    /// A balanced `{ … }` in the reasoning block is not the verdict: the
    /// detector completes at the object after `</think>`, as the parser
    /// reads it.
    #[test]
    fn braces_in_the_reasoning_block_do_not_stop_the_decode() {
        let think = "<think>The event {pid: 4242} has \"comm\" xmrig; the answer is {\"verdict\": …}.</think>\n";
        let object = "{\"verdict\":\"Kill\"}";
        let s = format!("{think}{object} trailing");
        assert_eq!(
            fires_at(&s),
            Some(think.chars().count() + object.chars().count() - 1)
        );
    }

    /// The markers are matched when the tokenizer splits them.
    #[test]
    fn reasoning_markers_split_across_chunks_are_matched() {
        let mut d = StreamingJsonDetector::new();
        for chunk in [
            "<th",
            "ink",
            ">{a}",
            " {\"x\":1} </",
            "thi",
            "nk>",
            "\n{\"v\":",
        ] {
            assert!(!d.feed(chunk), "{chunk:?}");
        }
        assert!(d.feed("2}"));
    }

    /// A reasoning block that never closes never completes (the parser
    /// refuses that output; the decode runs to its budget, as before).
    #[test]
    fn unclosed_reasoning_block_never_completes() {
        assert_eq!(fires_at("<think>{\"a\":1} {b} still thinking"), None);
    }

    /// A marker inside the object is part of a string, not a marker.
    #[test]
    fn markers_inside_the_object_are_text() {
        let s = "{\"a\":\"<think>\",\"b\":\"}\"}";
        assert_eq!(fires_at(s), Some(s.chars().count() - 1));
    }

    #[test]
    fn multibyte_text_before_the_object_is_absorbed() {
        let s = "Verdetto è «pronto» → ";
        let full = format!("{s}{{\"a\":1}}");
        assert_eq!(fires_at(&full), Some(full.chars().count() - 1));
    }
}
