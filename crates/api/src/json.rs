use memchr::memmem;
use std::sync::LazyLock;

static F_TRANSACTION: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(KEY_TRANSACTION));
static F_CUSTOMER: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(KEY_CUSTOMER));
static F_MERCHANT: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(KEY_MERCHANT));
static F_TERMINAL: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(KEY_TERMINAL));
static F_LAST_TX: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(KEY_LAST_TX));

#[derive(Debug)]
pub struct LastTx<'a> {
    pub timestamp: &'a [u8],
    pub km_from_current: f32,
}

#[derive(Debug)]
pub struct Payload<'a> {
    pub amount: f32,
    pub installments: u32,
    pub requested_at: &'a [u8],
    pub customer_avg_amount: f32,
    pub tx_count_24h: u32,
    pub merchant_id_in_known: bool,
    pub merchant_mcc: &'a [u8],
    pub merchant_avg_amount: f32,
    pub is_online: bool,
    pub card_present: bool,
    pub km_from_home: f32,
    pub last_tx: Option<LastTx<'a>>,
}

const KEY_TRANSACTION: &[u8] = b"\"transaction\"";
const KEY_CUSTOMER: &[u8] = b"\"customer\"";
const KEY_MERCHANT: &[u8] = b"\"merchant\"";
const KEY_TERMINAL: &[u8] = b"\"terminal\"";
const KEY_LAST_TX: &[u8] = b"\"last_transaction\"";

pub fn parse(body: &[u8]) -> Option<Payload<'_>> {
    let transaction = find_object_with(body, KEY_TRANSACTION, &F_TRANSACTION)?;
    let customer = find_object_with(body, KEY_CUSTOMER, &F_CUSTOMER)?;
    let merchant = find_object_with(body, KEY_MERCHANT, &F_MERCHANT)?;
    let terminal = find_object_with(body, KEY_TERMINAL, &F_TERMINAL)?;

    let merchant_id = obj_string(merchant, b"\"id\"")?;
    let merchant_mcc = obj_string(merchant, b"\"mcc\"")?;
    let merchant_avg_amount = obj_number_f32(merchant, b"\"avg_amount\"")?;

    let customer_avg_amount = obj_number_f32(customer, b"\"avg_amount\"")?;
    let tx_count_24h = obj_number_u32(customer, b"\"tx_count_24h\"")?;
    let merchant_id_in_known = known_merchants_contains(customer, merchant_id)?;

    let amount = obj_number_f32(transaction, b"\"amount\"")?;
    let installments = obj_number_u32(transaction, b"\"installments\"")?;
    let requested_at = obj_string(transaction, b"\"requested_at\"")?;

    let is_online = obj_bool(terminal, b"\"is_online\"")?;
    let card_present = obj_bool(terminal, b"\"card_present\"")?;
    let km_from_home = obj_number_f32(terminal, b"\"km_from_home\"")?;

    let last_tx = parse_last_tx(body)?;

    Some(Payload {
        amount,
        installments,
        requested_at,
        customer_avg_amount,
        tx_count_24h,
        merchant_id_in_known,
        merchant_mcc,
        merchant_avg_amount,
        is_online,
        card_present,
        km_from_home,
        last_tx,
    })
}

#[inline(always)]
fn skip_ws(buf: &[u8], mut i: usize) -> usize {
    while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn find_value_start(buf: &[u8], key: &[u8]) -> Option<usize> {
    let pos = memmem::find(buf, key)?;
    let mut p = pos + key.len();
    p = skip_ws(buf, p);
    if buf.get(p)? != &b':' {
        return None;
    }
    p += 1;
    p = skip_ws(buf, p);
    if p >= buf.len() {
        return None;
    }
    Some(p)
}

fn matching_brace(buf: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(buf.get(open).copied(), Some(b'{'));
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut esc = false;
    let mut i = open;
    while i < buf.len() {
        let c = buf[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn find_object_with<'a>(
    buf: &'a [u8],
    key: &[u8],
    finder: &memmem::Finder<'static>,
) -> Option<&'a [u8]> {
    let p = find_value_start_with(buf, key, finder)?;
    if buf.get(p)? != &b'{' {
        return None;
    }
    let end = matching_brace(buf, p)?;
    Some(&buf[p + 1..end])
}

fn find_value_start_with(
    buf: &[u8],
    key: &[u8],
    finder: &memmem::Finder<'static>,
) -> Option<usize> {
    let pos = finder.find(buf)?;
    let mut p = pos + key.len();
    p = skip_ws(buf, p);
    if buf.get(p)? != &b':' {
        return None;
    }
    p += 1;
    p = skip_ws(buf, p);
    if p >= buf.len() {
        return None;
    }
    Some(p)
}

fn obj_string<'a>(buf: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let p = find_value_start(buf, key)?;
    if buf.get(p)? != &b'"' {
        return None;
    }
    let s_start = p + 1;
    let off = memchr::memchr(b'"', &buf[s_start..])?;
    Some(&buf[s_start..s_start + off])
}

fn obj_number_f32(buf: &[u8], key: &[u8]) -> Option<f32> {
    let p = find_value_start(buf, key)?;
    let mut e = p;
    while e < buf.len()
        && matches!(buf[e], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
    {
        e += 1;
    }
    if e == p {
        return None;
    }
    std::str::from_utf8(&buf[p..e]).ok()?.parse().ok()
}

fn obj_number_u32(buf: &[u8], key: &[u8]) -> Option<u32> {
    let p = find_value_start(buf, key)?;
    let mut e = p;
    while e < buf.len() && buf[e].is_ascii_digit() {
        e += 1;
    }
    if e == p {
        return None;
    }
    std::str::from_utf8(&buf[p..e]).ok()?.parse().ok()
}

fn obj_bool(buf: &[u8], key: &[u8]) -> Option<bool> {
    let p = find_value_start(buf, key)?;
    if buf[p..].starts_with(b"true") {
        Some(true)
    } else if buf[p..].starts_with(b"false") {
        Some(false)
    } else {
        None
    }
}

fn known_merchants_contains(customer: &[u8], merchant_id: &[u8]) -> Option<bool> {
    let p = find_value_start(customer, b"\"known_merchants\"")?;
    if customer.get(p)? != &b'[' {
        return None;
    }
    let mut i = p + 1;
    loop {
        i = skip_array_ws_comma(customer, i);
        if i >= customer.len() {
            return None;
        }
        match customer[i] {
            b']' => return Some(false),
            b'"' => {
                let s_start = i + 1;
                let off = memchr::memchr(b'"', &customer[s_start..])?;
                let s = &customer[s_start..s_start + off];
                if s == merchant_id {
                    return Some(true);
                }
                i = s_start + off + 1;
            }
            _ => return None,
        }
    }
}

#[inline(always)]
fn skip_array_ws_comma(buf: &[u8], mut i: usize) -> usize {
    while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
        i += 1;
    }
    i
}

fn parse_last_tx(body: &[u8]) -> Option<Option<LastTx<'_>>> {
    let p = find_value_start_with(body, KEY_LAST_TX, &F_LAST_TX)?;
    if body[p..].starts_with(b"null") {
        return Some(None);
    }
    if body.get(p)? != &b'{' {
        return None;
    }
    let end = matching_brace(body, p)?;
    let inner = &body[p + 1..end];
    let timestamp = obj_string(inner, b"\"timestamp\"")?;
    let km_from_current = obj_number_f32(inner, b"\"km_from_current\"")?;
    Some(Some(LastTx {
        timestamp,
        km_from_current,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{
        "id": "tx-3576980410",
        "transaction": { "amount": 384.88, "installments": 3, "requested_at": "2026-03-11T20:23:35Z" },
        "customer": { "avg_amount": 769.76, "tx_count_24h": 3, "known_merchants": ["MERC-009", "MERC-001", "MERC-001"] },
        "merchant": { "id": "MERC-001", "mcc": "5912", "avg_amount": 298.95 },
        "terminal": { "is_online": false, "card_present": true, "km_from_home": 13.7090520965 },
        "last_transaction": { "timestamp": "2026-03-11T14:58:35Z", "km_from_current": 18.8626479774 }
    }"#;

    const SAMPLE_NULL_LT: &[u8] = br#"{
        "id": "tx-1",
        "transaction": { "amount": 41.12, "installments": 2, "requested_at": "2026-03-11T18:45:53Z" },
        "customer": { "avg_amount": 82.24, "tx_count_24h": 3, "known_merchants": ["MERC-003", "MERC-016"] },
        "merchant": { "id": "MERC-016", "mcc": "5411", "avg_amount": 60.25 },
        "terminal": { "is_online": false, "card_present": true, "km_from_home": 29.23 },
        "last_transaction": null
    }"#;

    #[test]
    fn parses_full_payload() {
        let p = parse(SAMPLE).expect("parse failed");
        assert!((p.amount - 384.88).abs() < 1e-3);
        assert_eq!(p.installments, 3);
        assert_eq!(p.requested_at, b"2026-03-11T20:23:35Z");
        assert!((p.customer_avg_amount - 769.76).abs() < 1e-3);
        assert_eq!(p.tx_count_24h, 3);
        assert!(p.merchant_id_in_known);
        assert_eq!(p.merchant_mcc, b"5912");
        assert!((p.merchant_avg_amount - 298.95).abs() < 1e-3);
        assert!(!p.is_online);
        assert!(p.card_present);
        assert!((p.km_from_home - 13.709052).abs() < 1e-3);
        let lt = p.last_tx.expect("expected last_tx");
        assert_eq!(lt.timestamp, b"2026-03-11T14:58:35Z");
        assert!((lt.km_from_current - 18.862648).abs() < 1e-3);
    }

    #[test]
    fn parses_null_last_transaction() {
        let p = parse(SAMPLE_NULL_LT).expect("parse failed");
        assert!(p.last_tx.is_none());
        assert!(p.merchant_id_in_known);
    }

    #[test]
    fn merchant_not_in_known_list() {
        let body = br#"{
            "id":"tx-2",
            "transaction":{"amount":1.0,"installments":1,"requested_at":"2026-03-11T01:00:00Z"},
            "customer":{"avg_amount":1.0,"tx_count_24h":1,"known_merchants":["MERC-A","MERC-B"]},
            "merchant":{"id":"MERC-Z","mcc":"5411","avg_amount":1.0},
            "terminal":{"is_online":true,"card_present":false,"km_from_home":0.0},
            "last_transaction":null
        }"#;
        let p = parse(body).expect("parse failed");
        assert!(!p.merchant_id_in_known);
    }

    #[test]
    fn rejects_missing_field() {
        let body = br#"{
            "transaction":{"amount":1.0,"installments":1,"requested_at":"2026-03-11T01:00:00Z"}
        }"#;
        assert!(parse(body).is_none());
    }

    #[test]
    fn handles_no_whitespace() {
        let body = br#"{"id":"x","transaction":{"amount":1,"installments":1,"requested_at":"2026-03-11T01:00:00Z"},"customer":{"avg_amount":1,"tx_count_24h":1,"known_merchants":[]},"merchant":{"id":"M","mcc":"5411","avg_amount":1},"terminal":{"is_online":true,"card_present":true,"km_from_home":1},"last_transaction":null}"#;
        let p = parse(body).expect("parse failed");
        assert!(!p.merchant_id_in_known);
        assert!(p.last_tx.is_none());
    }
}
