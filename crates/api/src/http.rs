#![allow(dead_code)]

use memchr::memmem;

const POST_FRAUD: &[u8] = b"POST /fraud-score";
const GET_READY: &[u8] = b"GET /ready";
const CONTENT_LENGTH: &[u8] = b"content-length:";

#[derive(Debug, Eq, PartialEq)]
pub enum Parsed {

    Incomplete,

    Bad,

    Ready { consumed: usize },

    NotFound { consumed: usize },

    FraudScore {
        body_start: usize,
        body_end: usize,
        consumed: usize,
    },
}

pub fn parse(buf: &[u8]) -> Parsed {
    if buf.len() < 16 {
        return Parsed::Incomplete;
    }

    let header_end = match memmem::find(buf, b"\r\n\r\n") {
        Some(p) => p,
        None => return Parsed::Incomplete,
    };
    let headers = &buf[..header_end];
    let header_total = header_end + 4;

    if buf.starts_with(POST_FRAUD) {
        match path_terminator(buf, POST_FRAUD.len()) {
            Some(_) => {
                let cl = match find_content_length(headers) {
                    Some(v) => v,
                    None => return Parsed::Bad,
                };
                let body_start = header_total;
                let body_end = body_start + cl;
                if buf.len() < body_end {
                    return Parsed::Incomplete;
                }
                Parsed::FraudScore {
                    body_start,
                    body_end,
                    consumed: body_end,
                }
            }
            None => Parsed::NotFound {
                consumed: header_total,
            },
        }
    } else if buf.starts_with(GET_READY) {
        match path_terminator(buf, GET_READY.len()) {
            Some(_) => Parsed::Ready {
                consumed: header_total,
            },
            None => Parsed::NotFound {
                consumed: header_total,
            },
        }
    } else if is_known_method_prefix(buf) {
        Parsed::NotFound {
            consumed: header_total,
        }
    } else {
        Parsed::Bad
    }
}

#[inline(always)]
fn path_terminator(buf: &[u8], at: usize) -> Option<u8> {
    match buf.get(at).copied() {
        Some(c @ (b' ' | b'?')) => Some(c),
        _ => None,
    }
}

#[inline(always)]
fn is_known_method_prefix(buf: &[u8]) -> bool {
    buf.starts_with(b"GET ")
        || buf.starts_with(b"POST ")
        || buf.starts_with(b"PUT ")
        || buf.starts_with(b"DELETE ")
        || buf.starts_with(b"PATCH ")
        || buf.starts_with(b"HEAD ")
        || buf.starts_with(b"OPTIONS ")
}

fn find_content_length(headers: &[u8]) -> Option<usize> {
    let key_len = CONTENT_LENGTH.len();
    if headers.len() < key_len {
        return None;
    }

    let mut i = 0usize;
    while i + key_len <= headers.len() {
        if header_eq_ascii_ci(&headers[i..i + key_len], CONTENT_LENGTH) {
            let mut p = i + key_len;
            while p < headers.len() && (headers[p] == b' ' || headers[p] == b'\t') {
                p += 1;
            }
            let mut v = 0usize;
            let mut digits = 0;
            while p < headers.len() && headers[p].is_ascii_digit() {
                v = v.wrapping_mul(10).wrapping_add((headers[p] - b'0') as usize);
                p += 1;
                digits += 1;
            }
            if digits == 0 {
                return None;
            }
            return Some(v);
        }

        match memchr::memchr(b'\n', &headers[i..]) {
            Some(off) => i += off + 1,
            None => return None,
        }
    }
    None
}

#[inline(always)]
fn header_eq_ascii_ci(a: &[u8], b_lower: &[u8]) -> bool {
    if a.len() != b_lower.len() {
        return false;
    }
    for j in 0..a.len() {
        let c = a[j];
        let lc = if c.is_ascii_uppercase() { c | 0x20 } else { c };
        if lc != b_lower[j] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready() {
        let r = b"GET /ready HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse(r) {
            Parsed::Ready { consumed } => assert_eq!(consumed, r.len()),
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn fraud() {
        let body = br#"{"id":"abc"}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"POST /fraud-score HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\n");
        buf.extend_from_slice(body);
        match parse(&buf) {
            Parsed::FraudScore {
                body_start,
                body_end,
                consumed,
            } => {
                assert_eq!(&buf[body_start..body_end], body);
                assert_eq!(consumed, buf.len());
            }
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn fraud_pipelined() {
        let body = br#"{"id":"abc"}"#;
        let mut buf = Vec::new();
        for _ in 0..2 {
            buf.extend_from_slice(b"POST /fraud-score HTTP/1.1\r\nContent-Length: 12\r\n\r\n");
            buf.extend_from_slice(body);
        }
        let mut head = 0;
        let mut requests = 0;
        loop {
            match parse(&buf[head..]) {
                Parsed::FraudScore { consumed, .. } => {
                    head += consumed;
                    requests += 1;
                }
                Parsed::Incomplete => break,
                other => panic!("unexpected {:?}", other),
            }
        }
        assert_eq!(requests, 2);
        assert_eq!(head, buf.len());
    }

    #[test]
    fn fraud_missing_content_length() {
        let r = b"POST /fraud-score HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(parse(r), Parsed::Bad);
    }

    #[test]
    fn fraud_incomplete_body() {
        let r = b"POST /fraud-score HTTP/1.1\r\nContent-Length: 50\r\n\r\n{\"id\":\"abc\"}";
        assert_eq!(parse(r), Parsed::Incomplete);
    }

    #[test]
    fn fraud_lowercase_header() {
        let body = br#"{"id":"abc"}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"POST /fraud-score HTTP/1.1\r\ncontent-length: 12\r\n\r\n");
        buf.extend_from_slice(body);
        assert!(matches!(parse(&buf), Parsed::FraudScore { .. }));
    }

    #[test]
    fn unknown_path() {
        let r = b"GET /metrics HTTP/1.1\r\n\r\n";
        match parse(r) {
            Parsed::NotFound { consumed } => assert_eq!(consumed, r.len()),
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn bad_method() {
        let r = b"FOOBAR /ready HTTP/1.1\r\n\r\n";
        assert_eq!(parse(r), Parsed::Bad);
    }

    #[test]
    fn incomplete_headers() {
        let r = b"GET /ready HTTP/1.1\r\nHost: x";
        assert_eq!(parse(r), Parsed::Incomplete);
    }

    #[test]
    fn ready_with_query() {
        let r = b"GET /ready?cache=0 HTTP/1.1\r\n\r\n";
        assert!(matches!(parse(r), Parsed::Ready { .. }));
    }
}
