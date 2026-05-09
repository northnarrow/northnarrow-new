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

/// Brace-depth tracker that recognises a complete top-level JSON
/// object inside a (possibly noisy) text stream.
///
/// Behaviour:
///
/// - Ignores any text that precedes the first `{`. Foundation-Sec
///   sometimes emits prose like `"Verdict: {…}"`; the leading
///   characters are simply absorbed.
/// - Tracks string mode: `"`-delimited spans don't contribute to
///   brace depth. Escaped quotes (`\"`) inside strings are honoured.
/// - Returns `true` from [`feed`](Self::feed) the first time the
///   outermost object closes (`brace_depth == 0` after at least one
///   `{`). Subsequent calls keep returning `false` so the engine can
///   safely keep feeding text past the boundary without re-firing.
#[derive(Debug, Default)]
pub struct StreamingJsonDetector {
    buffer: String,
    in_json: bool,
    brace_depth: i32,
    in_string: bool,
    escape_next: bool,
    completed: bool,
}

impl StreamingJsonDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `chunk` to the rolling buffer and report whether the
    /// outermost JSON object has just closed. Idempotent after the
    /// first completion: once `true` is returned, all further
    /// `feed` calls store the bytes but always return `false`.
    pub fn feed(&mut self, chunk: &str) -> bool {
        if self.completed {
            self.buffer.push_str(chunk);
            return false;
        }
        for c in chunk.chars() {
            self.buffer.push(c);

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
                '{' => {
                    if !self.in_json {
                        self.in_json = true;
                    }
                    self.brace_depth += 1;
                }
                '}' => {
                    self.brace_depth -= 1;
                    if self.in_json && self.brace_depth == 0 {
                        self.completed = true;
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// All bytes seen so far, in order.
    pub fn buffer(&self) -> &str {
        &self.buffer
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

    #[test]
    fn empty_input_does_not_complete() {
        let mut d = StreamingJsonDetector::new();
        assert!(!d.feed(""));
        assert!(!d.is_complete());
        assert_eq!(d.buffer(), "");
    }

    #[test]
    fn simple_object_completes_at_closing_brace() {
        let mut d = StreamingJsonDetector::new();
        assert!(d.feed("{\"a\":1}"));
        assert!(d.is_complete());
        assert_eq!(d.buffer(), "{\"a\":1}");
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
        assert_eq!(d.buffer(), "{\"a\":{\"b\":1}}");
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
        let mut d = StreamingJsonDetector::new();
        let mut completed_at = None;
        for (i, ch) in s.chars().enumerate() {
            let mut buf = [0u8; 4];
            let chunk = ch.encode_utf8(&mut buf);
            if d.feed(chunk) && completed_at.is_none() {
                completed_at = Some(i);
            }
        }
        assert_eq!(completed_at, Some(s.len() - 1));
        assert_eq!(d.buffer(), s);
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
        // The model keeps emitting tokens; we accumulate them but
        // must not re-signal completion (the engine has already
        // told the backend to stop).
        assert!(!d.feed(" trailing prose {\"b\":2} more"));
        assert!(d.is_complete());
        assert_eq!(d.buffer(), "{\"a\":1} trailing prose {\"b\":2} more");
    }
}
