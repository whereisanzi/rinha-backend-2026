use crate::DIM;
use crate::json::Payload;

const MAX_AMOUNT: f32 = 10_000.0;
const MAX_INSTALLMENTS: f32 = 12.0;
const AMOUNT_VS_AVG_RATIO: f32 = 10.0;
const MAX_MINUTES: f32 = 1440.0;
const MAX_KM: f32 = 1000.0;
const MAX_TX_COUNT_24H: f32 = 20.0;
const MAX_MERCHANT_AVG_AMOUNT: f32 = 10_000.0;

pub fn vectorize(p: &Payload<'_>) -> [f32; DIM] {
    let hour = iso_hour(p.requested_at);
    let weekday = weekday_mon0(
        iso_year(p.requested_at),
        iso_month(p.requested_at),
        iso_day(p.requested_at),
    );

    let (mins_last, km_last) = match &p.last_tx {
        Some(lt) => {
            let mins = minutes_between_abs(p.requested_at, lt.timestamp);
            (
                clamp01(mins as f32 / MAX_MINUTES),
                clamp01(lt.km_from_current / MAX_KM),
            )
        }
        None => (-1.0, -1.0),
    };

    let amount_vs_avg = if p.customer_avg_amount > 0.0 {
        clamp01(p.amount / p.customer_avg_amount / AMOUNT_VS_AVG_RATIO)
    } else {
        1.0
    };

    [
        clamp01(p.amount / MAX_AMOUNT),
        clamp01(p.installments as f32 / MAX_INSTALLMENTS),
        amount_vs_avg,
        hour as f32 / 23.0,
        weekday as f32 / 6.0,
        mins_last,
        km_last,
        clamp01(p.km_from_home / MAX_KM),
        clamp01(p.tx_count_24h as f32 / MAX_TX_COUNT_24H),
        if p.is_online { 1.0 } else { 0.0 },
        if p.card_present { 1.0 } else { 0.0 },
        if p.merchant_id_in_known { 0.0 } else { 1.0 },
        mcc_risk(p.merchant_mcc),
        clamp01(p.merchant_avg_amount / MAX_MERCHANT_AVG_AMOUNT),
    ]
}

#[inline(always)]
fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

#[inline(always)]
fn mcc_risk(mcc: &[u8]) -> f32 {

    match mcc {
        b"5411" => 0.15,
        b"5812" => 0.30,
        b"5912" => 0.20,
        b"5944" => 0.45,
        b"7801" => 0.80,
        b"7802" => 0.75,
        b"7995" => 0.85,
        b"4511" => 0.35,
        b"5311" => 0.25,
        b"5999" => 0.50,
        _ => 0.5,
    }
}

#[inline(always)]
fn iso_year(s: &[u8]) -> i32 {
    (s[0] - b'0') as i32 * 1000
        + (s[1] - b'0') as i32 * 100
        + (s[2] - b'0') as i32 * 10
        + (s[3] - b'0') as i32
}

#[inline(always)]
fn iso_month(s: &[u8]) -> u32 {
    (s[5] - b'0') as u32 * 10 + (s[6] - b'0') as u32
}

#[inline(always)]
fn iso_day(s: &[u8]) -> u32 {
    (s[8] - b'0') as u32 * 10 + (s[9] - b'0') as u32
}

#[inline(always)]
fn iso_hour(s: &[u8]) -> u32 {
    let h = (s[11] - b'0') as u32 * 10 + (s[12] - b'0') as u32;
    h.min(23)
}

#[inline(always)]
fn iso_minute(s: &[u8]) -> u32 {
    (s[14] - b'0') as u32 * 10 + (s[15] - b'0') as u32
}

#[inline(always)]
fn iso_second(s: &[u8]) -> u32 {
    (s[17] - b'0') as u32 * 10 + (s[18] - b'0') as u32
}

#[inline]
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe as i64 - 719468
}

#[inline]
fn weekday_mon0(y: i32, m: u32, d: u32) -> u32 {

    let days = days_from_civil(y, m, d);
    let w = (days + 3).rem_euclid(7);
    w as u32
}

#[inline]
fn iso_to_epoch_seconds(s: &[u8]) -> i64 {
    let days = days_from_civil(iso_year(s), iso_month(s), iso_day(s));
    days * 86400
        + iso_hour(s) as i64 * 3600
        + iso_minute(s) as i64 * 60
        + iso_second(s) as i64
}

#[inline]
fn minutes_between_abs(a: &[u8], b: &[u8]) -> i64 {
    (iso_to_epoch_seconds(a) - iso_to_epoch_seconds(b)).abs() / 60
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn approx(a: f32, b: f32, tol: f32) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn weekday_known_dates() {

        assert_eq!(weekday_mon0(2026, 3, 11), 2);

        assert_eq!(weekday_mon0(2026, 3, 14), 5);

        assert_eq!(weekday_mon0(2026, 3, 15), 6);

        assert_eq!(weekday_mon0(2026, 3, 16), 0);
    }

    #[test]
    fn iso_field_extraction() {
        let s = b"2026-03-11T20:23:35Z";
        assert_eq!(iso_year(s), 2026);
        assert_eq!(iso_month(s), 3);
        assert_eq!(iso_day(s), 11);
        assert_eq!(iso_hour(s), 20);
        assert_eq!(iso_minute(s), 23);
        assert_eq!(iso_second(s), 35);
    }

    #[test]
    fn legit_example_matches_spec() {
        let body = br#"{
            "id":"tx-1329056812",
            "transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},
            "customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-003","MERC-016"]},
            "merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},
            "terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},
            "last_transaction":null
        }"#;
        let p = json::parse(body).unwrap();
        let v = vectorize(&p);

        assert!(approx(v[0], 0.0041, 1e-3), "v0 = {}", v[0]);
        assert!(approx(v[1], 0.1667, 1e-3), "v1 = {}", v[1]);
        assert!(approx(v[2], 0.05, 1e-3), "v2 = {}", v[2]);
        assert!(approx(v[3], 0.7826, 1e-3), "v3 = {}", v[3]);
        assert!(approx(v[4], 0.3333, 1e-3), "v4 = {}", v[4]);
        assert_eq!(v[5], -1.0);
        assert_eq!(v[6], -1.0);
        assert!(approx(v[7], 0.0292, 1e-3), "v7 = {}", v[7]);
        assert!(approx(v[8], 0.15, 1e-3), "v8 = {}", v[8]);
        assert_eq!(v[9], 0.0);
        assert_eq!(v[10], 1.0);
        assert_eq!(v[11], 0.0);
        assert!(approx(v[12], 0.15, 1e-3), "v12 = {}", v[12]);
        assert!(approx(v[13], 0.006, 1e-3), "v13 = {}", v[13]);
    }

    #[test]
    fn fraud_example_matches_spec() {
        let body = br#"{
            "id":"tx-3330991687",
            "transaction":{"amount":9505.97,"installments":10,"requested_at":"2026-03-14T05:15:12Z"},
            "customer":{"avg_amount":81.28,"tx_count_24h":20,"known_merchants":["MERC-008","MERC-007","MERC-005"]},
            "merchant":{"id":"MERC-068","mcc":"7802","avg_amount":54.86},
            "terminal":{"is_online":false,"card_present":true,"km_from_home":952.27},
            "last_transaction":null
        }"#;
        let p = json::parse(body).unwrap();
        let v = vectorize(&p);

        assert!(approx(v[0], 0.9506, 1e-3), "v0 = {}", v[0]);
        assert!(approx(v[1], 0.8333, 1e-3), "v1 = {}", v[1]);
        assert_eq!(v[2], 1.0);
        assert!(approx(v[3], 0.2174, 1e-3), "v3 = {}", v[3]);
        assert!(approx(v[4], 0.8333, 1e-3), "v4 = {}", v[4]);
        assert_eq!(v[5], -1.0);
        assert_eq!(v[6], -1.0);
        assert!(approx(v[7], 0.9523, 1e-3), "v7 = {}", v[7]);
        assert_eq!(v[8], 1.0);
        assert_eq!(v[9], 0.0);
        assert_eq!(v[10], 1.0);
        assert_eq!(v[11], 1.0);
        assert!(approx(v[12], 0.75, 1e-3), "v12 = {}", v[12]);
        assert!(approx(v[13], 0.0055, 1e-3), "v13 = {}", v[13]);
    }

    #[test]
    fn last_transaction_minutes_and_km() {

        let body = br#"{
            "id":"x",
            "transaction":{"amount":100.0,"installments":1,"requested_at":"2026-03-11T20:23:35Z"},
            "customer":{"avg_amount":100.0,"tx_count_24h":1,"known_merchants":["M"]},
            "merchant":{"id":"M","mcc":"5411","avg_amount":100.0},
            "terminal":{"is_online":false,"card_present":true,"km_from_home":1.0},
            "last_transaction":{"timestamp":"2026-03-11T14:58:35Z","km_from_current":18.8626479774}
        }"#;
        let p = json::parse(body).unwrap();
        let v = vectorize(&p);

        assert!(approx(v[5], 0.225694, 1e-3), "v5 = {}", v[5]);

        assert!(approx(v[6], 0.01886, 1e-3), "v6 = {}", v[6]);
    }

    #[test]
    fn mcc_default_for_unknown() {
        assert_eq!(mcc_risk(b"9999"), 0.5);
        assert_eq!(mcc_risk(b""), 0.5);
        assert_eq!(mcc_risk(b"5411"), 0.15);
    }
}
