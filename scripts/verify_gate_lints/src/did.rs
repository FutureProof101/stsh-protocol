//! `.did` service-block parsing (brief §2, §3 S2 third leg).
//!
//! Methods are split on TOP-LEVEL `;` with `(`/`{` depth tracking, never by a
//! per-line grep: several methods span multiple lines and a per-line rule
//! silently miscounts them (brief §8). The constructor signature is EXCLUDED —
//! the body parsed is the token span strictly between the constructor's closing
//! `-> {` and the block's final `}` (V5 RED-2).

#[derive(Debug, Clone)]
pub struct DidMethod {
    pub name: String,
    pub line: usize,
    pub is_query: bool,
}

/// Parse the service block of a `.did` file.
pub fn service_methods(text: &str) -> Vec<DidMethod> {
    // Locate `service ... {` and take the LAST `{` before the body begins, so a
    // parameterised constructor `service : (Args) -> { ... }` contributes its
    // signature to neither the method list nor the depth tracking.
    let Some(svc) = text.find("service") else { return Vec::new() };
    let after = &text[svc + "service".len()..];
    let mut paren = 0i32;
    let mut open_rel = None;
    for (i, c) in after.char_indices() {
        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            // The constructor's argument record braces all sit inside `( … )`,
            // so the first `{` seen at paren-depth 0 is the service block body
            // (V5 RED-2: the constructor signature is excluded, and a naive
            // "first `{` after `service`" takes the record's brace instead).
            '{' if paren == 0 => {
                open_rel = Some(i);
                break;
            }
            _ => {}
        }
    }
    let Some(open_rel) = open_rel else { return Vec::new() };
    let body_start = svc + "service".len() + open_rel + 1;

    let bytes: Vec<char> = text.chars().collect();
    // Map char index -> line, computed once.
    let mut line_of = Vec::with_capacity(bytes.len() + 1);
    let mut line = 1usize;
    for c in &bytes {
        line_of.push(line);
        if *c == '\n' {
            line += 1;
        }
    }
    line_of.push(line);

    let start_chars = text[..body_start].chars().count();
    let mut depth = 0i32;
    let mut buf = String::new();
    let mut buf_start = start_chars;
    let mut out = Vec::new();
    let mut in_line_comment = false;

    let mut i = start_chars;
    while i < bytes.len() {
        let c = bytes[i];
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                buf.push(' ');
            }
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == '/' {
            in_line_comment = true;
            i += 2;
            continue;
        }
        match c {
            '(' | '{' => {
                depth += 1;
                buf.push(c);
            }
            ')' => {
                depth -= 1;
                buf.push(c);
            }
            '}' => {
                if depth == 0 {
                    // End of the service block.
                    break;
                }
                depth -= 1;
                buf.push(c);
            }
            ';' if depth == 0 => {
                if let Some(m) = parse_method(&buf, line_of[buf_start.min(line_of.len() - 1)]) {
                    out.push(m);
                }
                buf.clear();
                buf_start = i + 1;
            }
            _ => {
                if buf.trim().is_empty() && !c.is_whitespace() {
                    buf_start = i;
                }
                buf.push(c);
            }
        }
        i += 1;
    }
    out
}

fn parse_method(chunk: &str, line: usize) -> Option<DidMethod> {
    let t = chunk.trim();
    if t.is_empty() {
        return None;
    }
    let (name_part, rest) = t.split_once(':')?;
    let name = name_part.trim().trim_matches('"').to_string();
    if name.is_empty() || !name.chars().next()?.is_ascii_alphabetic() && !name.starts_with('_') {
        return None;
    }
    let tail = rest.trim_end();
    let is_query = tail.ends_with("query") || tail.ends_with("composite_query");
    Some(DidMethod { name, line, is_query })
}

/// Update methods only — mode is not `query`/`composite_query`.
pub fn update_methods(text: &str) -> Vec<DidMethod> {
    service_methods(text).into_iter().filter(|m| !m.is_query).collect()
}
