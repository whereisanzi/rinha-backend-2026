#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub const RESP_READY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

pub const RESP_NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

pub const RESP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub const RESP_PAYLOAD_TOO_LARGE: &[u8] =
    b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub const RESP_FRAUD: [&[u8]; 6] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\n{\"approved\":true,\"fraud_score\":0.0}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\n{\"approved\":true,\"fraud_score\":0.2}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 35\r\n\r\n{\"approved\":true,\"fraud_score\":0.4}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\n\r\n{\"approved\":false,\"fraud_score\":0.6}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\n\r\n{\"approved\":false,\"fraud_score\":0.8}",
    b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\n\r\n{\"approved\":false,\"fraud_score\":1.0}",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(resp: &[u8]) -> &[u8] {
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header separator missing");
        &resp[header_end + 4..]
    }

    fn extract_content_length(resp: &[u8]) -> usize {
        let s = std::str::from_utf8(resp).expect("ascii response");
        let key = "Content-Length: ";
        let i = s.find(key).expect("Content-Length header");
        let rest = &s[i + key.len()..];
        let end = rest.find('\r').unwrap();
        rest[..end].parse().expect("number")
    }

    #[test]
    fn fraud_responses_are_consistent() {
        for (i, resp) in RESP_FRAUD.iter().enumerate() {
            let body = body_of(resp);
            let cl = extract_content_length(resp);
            assert_eq!(body.len(), cl, "fraud[{}] body len mismatch", i);

            let approved = i < 3;
            let expected_score = format!("{:.1}", i as f32 / 5.0);
            let body_str = std::str::from_utf8(body).unwrap();
            assert!(
                body_str.contains(&format!("\"approved\":{}", approved)),
                "fraud[{}] approved mismatch: {}",
                i,
                body_str
            );
            assert!(
                body_str.contains(&format!("\"fraud_score\":{}", expected_score)),
                "fraud[{}] score mismatch: {}",
                i,
                body_str
            );
        }
    }

    #[test]
    fn non_fraud_responses_have_zero_body() {
        for resp in [
            RESP_READY,
            RESP_NOT_FOUND,
            RESP_BAD_REQUEST,
            RESP_PAYLOAD_TOO_LARGE,
        ] {
            assert_eq!(body_of(resp).len(), 0);
            assert_eq!(extract_content_length(resp), 0);
        }
    }
}
