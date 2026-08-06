//! RFC 8785 (JCS) canonical-JSON serialisation — the ONE implementation of the MLCH-1 canon family
//! shared by every module that needs deterministic canonical bytes over a `serde_json::Value`.
//!
//! Extracted from [`signed_leaf`](crate::signed_leaf) (where it originally lived as
//! `canonical_leaf_bytes`'s private helpers) so R7's [`self_contained`](crate::self_contained)
//! proof-bundle signing canon can reuse the identical, already-tested algorithm rather than a second,
//! independently-maintained copy — two canon implementations WILL eventually drift, which is exactly
//! the class of bug ADR-043 exists to prevent (producer and verifier must never disagree on bytes).
//!
//! Kept in its own module with NO feature gate of its own — gated instead at the `mod jcs;`
//! declaration in `lib.rs` on `any(feature = "offline-verify", feature = "leaf-verify")`, its two
//! current consumers, so a plain no-features build carries no dead code, and neither consumer's
//! feature has to imply the other's (heavier) dependencies.
//!
//! See [`signed_leaf::canonical_leaf_bytes`](crate::signed_leaf::canonical_leaf_bytes)'s module docs
//! for the exact byte-layout rules this implements (UTF-16 key sort, RFC 8785 string escaping, the
//! MLCH-1 big-integer-as-string rule); this module is that ONE implementation, not a restatement.

use serde_json::{Map, Value};

/// Largest integer exactly representable as an IEEE-754 double (`Number.MAX_SAFE_INTEGER`) — the
/// big-integer-as-string threshold (MLCH-1, ADR-042 §6.1).
const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

/// Deterministic RFC 8785 canonical bytes of `v`. Total and never panics: `serde_json` numbers are
/// always finite, so the number path always yields a deterministic string.
/// RFC 8785 (JCS) canonical JSON bytes of `v` — the ONE canon shared by the leaf-envelope signature,
/// the M6-c decision-record preimage (built by each platform's agent), and MESHLOGIC03's independent
/// verifier. Exposed so producers canonicalize the record IDENTICALLY across Windows + macOS.
pub fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    serialize_value(v, &mut out);
    out.into_bytes()
}

fn serialize_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => serialize_string(s, out),
        Value::Number(n) => serialize_number(n, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_value(e, out);
            }
            out.push(']');
        }
        Value::Object(obj) => serialize_object(obj, out),
    }
}

fn serialize_object(obj: &Map<String, Value>, out: &mut String) {
    // RFC 8785 §3.2.3: sort member names by UTF-16 code units. `sort_by_cached_key` encodes each
    // key's UTF-16 once (not per comparison).
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort_by_cached_key(|k| k.encode_utf16().collect::<Vec<u16>>());
    out.push('{');
    let mut first = true;
    for k in keys {
        if !first {
            out.push(',');
        }
        first = false;
        serialize_string(k, out);
        out.push(':');
        serialize_value(&obj[k], out);
    }
    out.push('}');
}

/// RFC 8785 §3.2.2.2 string production (identical to the MLCH-1 record canon).
fn serialize_string(s: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn serialize_number(n: &serde_json::Number, out: &mut String) {
    // Big-integer rule (MLCH-1, ADR-042 §6.1): integer-typed values with magnitude > MAX_SAFE_INTEGER
    // serialize as a JSON STRING (so an event_sequence u64 survives losslessly).
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            serialize_string(&u.to_string(), out);
        } else {
            out.push_str(&u.to_string());
        }
        return;
    }
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            serialize_string(&i.to_string(), out);
        } else {
            out.push_str(&i.to_string());
        }
        return;
    }
    // Floats are out-of-spec for a leaf envelope; render deterministically (ES6 layout) so the
    // function stays total. `serde_json` numbers are always finite.
    let f = n.as_f64().unwrap_or(0.0);
    out.push_str(&es6_number(f));
}

/// ES6 `Number::toString` (RFC 8785 §3.2.2.3) for a finite double. Ported verbatim from the MLCH-1
/// record canon so the (unexpected) float path stays byte-consistent with `content_hash`.
fn es6_number(f: f64) -> String {
    if !f.is_finite() {
        return "0".to_string(); // unreachable from serde_json (always finite); deterministic fallback
    }
    if f == 0.0 {
        return "0".to_string();
    }
    let sign = if f < 0.0 { "-" } else { "" };
    let plain = format!("{}", f.abs());
    if plain.contains('e') || plain.contains('E') {
        return format!("{sign}{plain}"); // defensive: never expected for finite f64 Display
    }
    let (int_part, frac_part) = match plain.split_once('.') {
        Some((i, fr)) => (i, fr),
        None => (plain.as_str(), ""),
    };
    let concat: String = format!("{int_part}{frac_part}");
    let lead = concat.len() - concat.trim_start_matches('0').len();
    let trimmed = concat[lead..].trim_end_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    let k = digits.len() as i64;
    let n = int_part.len() as i64 - lead as i64;

    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let e_sign = if e >= 0 { "+" } else { "-" };
        if k == 1 {
            format!("{}e{}{}", digits, e_sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], e_sign, e.abs())
        }
    };
    format!("{sign}{body}")
}
