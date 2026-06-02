// Offline detection oracle / harness.
//
// Loads the 3M reference vectors and the official 54_100-entry test set
// (test/test-data.json, which carries `expected_approved` per entry as computed
// by the reference C evaluator), runs an EXACT brute-force k=5 NN search with
// the same squared-L2 metric and lowest-index tie-break as the evaluator, and
// reports false positives / false negatives.
//
// Purpose: attribute our submitted 17 false positives to either feature
// precision (f32 vs f64) or IVF approximation, and validate a 0-error recipe
// WITHOUT spending public rinha submissions.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Instant;

use flate2::read::GzDecoder;
use rayon::prelude::*;
use serde::Deserialize;
use serde::de::{Deserializer, SeqAccess, Visitor};

const DIM: usize = 14;
const KNN_K: usize = 5;

// ---------------------------------------------------------------------------
// Quantization: round4(x) * 10_000 as i16. The reference C evaluator rounds
// every feature to 4 decimals (round-half-away-from-zero) before the k-NN, and
// our i16 representation IS that value scaled by 10_000, so the i16 squared-L2
// ordering is bit-identical to the evaluator's round4 f64 ordering.
// ---------------------------------------------------------------------------

#[inline]
fn quant_f64(x: f64) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * 10_000.0;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

#[inline]
fn quant_f32(x: f32) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * 10_000.0;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

// ---------------------------------------------------------------------------
// Date helpers (UTC ISO-8601 "YYYY-MM-DDTHH:MM:SSZ")
// ---------------------------------------------------------------------------

#[inline]
fn d2(s: &[u8], i: usize) -> i64 {
    (s[i] - b'0') as i64 * 10 + (s[i + 1] - b'0') as i64
}

#[inline]
fn iso_year(s: &[u8]) -> i64 {
    (s[0] - b'0') as i64 * 1000
        + (s[1] - b'0') as i64 * 100
        + (s[2] - b'0') as i64 * 10
        + (s[3] - b'0') as i64
}

#[inline]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mm = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[inline]
fn epoch_secs(s: &[u8]) -> i64 {
    let y = iso_year(s);
    let mo = d2(s, 5);
    let da = d2(s, 8);
    let h = d2(s, 11);
    let mi = d2(s, 14);
    let se = d2(s, 17);
    days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + se
}

#[inline]
fn hour_of(s: &[u8]) -> i64 {
    d2(s, 11).min(23)
}

#[inline]
fn weekday_mon0(s: &[u8]) -> i64 {
    let days = days_from_civil(iso_year(s), d2(s, 5), d2(s, 8));
    (days + 3).rem_euclid(7)
}

#[inline]
fn minutes_signed(req: &[u8], last: &[u8]) -> i64 {
    (epoch_secs(req) - epoch_secs(last)) / 60
}

fn mcc_risk(mcc: &str) -> f64 {
    match mcc {
        "5411" => 0.15,
        "5812" => 0.30,
        "5912" => 0.20,
        "5944" => 0.45,
        "7801" => 0.80,
        "7802" => 0.75,
        "7995" => 0.85,
        "4511" => 0.35,
        "5311" => 0.25,
        "5999" => 0.50,
        _ => 0.5,
    }
}

// ---------------------------------------------------------------------------
// Test-data schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TestData {
    entries: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    request: serde_json::Value,
    expected_approved: bool,
    expected_fraud_score: f64,
}
#[derive(Deserialize)]
struct Req {
    transaction: Tx,
    customer: Cust,
    merchant: Merch,
    terminal: Term,
    last_transaction: Option<LastTx>,
}
#[derive(Deserialize)]
struct Tx {
    amount: f64,
    installments: f64,
    requested_at: String,
}
#[derive(Deserialize)]
struct Cust {
    avg_amount: f64,
    tx_count_24h: f64,
    known_merchants: Vec<String>,
}
#[derive(Deserialize)]
struct Merch {
    id: String,
    mcc: String,
    avg_amount: f64,
}
#[derive(Deserialize)]
struct Term {
    is_online: bool,
    card_present: bool,
    km_from_home: f64,
}
#[derive(Deserialize)]
struct LastTx {
    timestamp: String,
    km_from_current: f64,
}

fn known_contains(list: &[String], id: &str) -> bool {
    list.iter().any(|m| m == id)
}

// ---------------------------------------------------------------------------
// Vectorizers — identical formulas, only the arithmetic precision differs.
// ---------------------------------------------------------------------------

fn vec_f64(r: &Req) -> [i16; DIM] {
    let amount = r.transaction.amount;
    let installments = r.transaction.installments;
    let cust_avg = r.customer.avg_amount;
    let km_home = r.terminal.km_from_home;
    let merch_avg = r.merchant.avg_amount;
    let tx24 = r.customer.tx_count_24h;
    let req = r.transaction.requested_at.as_bytes();
    let hour = hour_of(req) as f64;
    let dow = weekday_mon0(req) as f64;

    let (mins, km_last) = match &r.last_transaction {
        Some(lt) => {
            let m = minutes_signed(req, lt.timestamp.as_bytes()) as f64;
            (
                (m / 1440.0).clamp(0.0, 1.0),
                (lt.km_from_current / 1000.0).clamp(0.0, 1.0),
            )
        }
        None => (-1.0, -1.0),
    };
    let avg_vs = if cust_avg > 0.0 {
        (amount / cust_avg / 10.0).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let f = [
        (amount / 10000.0).clamp(0.0, 1.0),
        (installments / 12.0).clamp(0.0, 1.0),
        avg_vs,
        hour / 23.0,
        dow / 6.0,
        mins,
        km_last,
        (km_home / 1000.0).clamp(0.0, 1.0),
        (tx24 / 20.0).clamp(0.0, 1.0),
        if r.terminal.is_online { 1.0 } else { 0.0 },
        if r.terminal.card_present { 1.0 } else { 0.0 },
        if known_contains(&r.customer.known_merchants, &r.merchant.id) {
            0.0
        } else {
            1.0
        },
        mcc_risk(&r.merchant.mcc),
        (merch_avg / 10000.0).clamp(0.0, 1.0),
    ];
    let mut out = [0i16; DIM];
    for j in 0..DIM {
        out[j] = quant_f64(f[j]);
    }
    out
}

fn vec_f32(r: &Req) -> [i16; DIM] {
    let amount = r.transaction.amount as f32;
    let installments = r.transaction.installments as f32;
    let cust_avg = r.customer.avg_amount as f32;
    let km_home = r.terminal.km_from_home as f32;
    let merch_avg = r.merchant.avg_amount as f32;
    let tx24 = r.customer.tx_count_24h as f32;
    let req = r.transaction.requested_at.as_bytes();
    let hour = hour_of(req) as f32;
    let dow = weekday_mon0(req) as f32;

    let (mins, km_last) = match &r.last_transaction {
        Some(lt) => {
            let m = minutes_signed(req, lt.timestamp.as_bytes()) as f32;
            (
                (m / 1440.0).clamp(0.0, 1.0),
                (lt.km_from_current as f32 / 1000.0).clamp(0.0, 1.0),
            )
        }
        None => (-1.0, -1.0),
    };
    let avg_vs = if cust_avg > 0.0 {
        (amount / cust_avg / 10.0).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let f = [
        (amount / 10000.0).clamp(0.0, 1.0),
        (installments / 12.0).clamp(0.0, 1.0),
        avg_vs,
        hour / 23.0,
        dow / 6.0,
        mins,
        km_last,
        (km_home / 1000.0).clamp(0.0, 1.0),
        (tx24 / 20.0).clamp(0.0, 1.0),
        if r.terminal.is_online { 1.0 } else { 0.0 },
        if r.terminal.card_present { 1.0 } else { 0.0 },
        if known_contains(&r.customer.known_merchants, &r.merchant.id) {
            0.0
        } else {
            1.0
        },
        mcc_risk(&r.merchant.mcc) as f32,
        (merch_avg / 10000.0).clamp(0.0, 1.0),
    ];
    let mut out = [0i16; DIM];
    for j in 0..DIM {
        out[j] = quant_f32(f[j]);
    }
    out
}

// ---------------------------------------------------------------------------
// Exact brute-force k=5 NN, lowest-index tie-break. Returns fraud count in top5.
// ---------------------------------------------------------------------------

fn exact_fraud_count(q: &[i16; DIM], refs: &[i16], labels: &[u8]) -> u8 {
    // top[t] = (dist, orig_index, label)
    let mut top = [(i64::MAX, u32::MAX, 0u8); KNN_K];
    let mut worst = 0usize;
    let n = labels.len();
    for i in 0..n {
        let base = i * DIM;
        let worst_d = top[worst].0;
        let mut d: i64 = 0;
        let mut over = false;
        for j in 0..DIM {
            let diff = (q[j] as i32 - refs[base + j] as i32) as i64;
            d += diff * diff;
            if d > worst_d {
                over = true;
                break;
            }
        }
        if over {
            continue;
        }
        let id = i as u32;
        let cur = top[worst];
        let better = d < cur.0 || (d == cur.0 && id < cur.1);
        if !better {
            continue;
        }
        top[worst] = (d, id, labels[i]);
        let mut wi = 0;
        for t in 1..KNN_K {
            if top[t].0 > top[wi].0 || (top[t].0 == top[wi].0 && top[t].1 > top[wi].1) {
                wi = t;
            }
        }
        worst = wi;
    }
    top.iter().filter(|t| t.2 == 1).count() as u8
}

// ---------------------------------------------------------------------------
// Reference loading (streaming, quantize on the fly into flat i16)
// ---------------------------------------------------------------------------

struct RefCollector {
    flat: Vec<i16>,
    labels: Vec<u8>,
    f32_mismatch: usize,
}

#[derive(Deserialize)]
struct RefEntry {
    vector: [f64; DIM],
    label: String,
}

impl<'de> Visitor<'de> for RefCollector {
    type Value = (Vec<i16>, Vec<u8>, usize);
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "an array of reference entries")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        while let Some(e) = seq.next_element::<RefEntry>()? {
            for j in 0..DIM {
                let q64 = quant_f64(e.vector[j]);
                let q32 = quant_f32(e.vector[j] as f32);
                if q64 != q32 {
                    self.f32_mismatch += 1;
                }
                self.flat.push(q64);
            }
            self.labels.push(if e.label == "fraud" { 1 } else { 0 });
        }
        Ok((self.flat, self.labels, self.f32_mismatch))
    }
}

fn load_refs(path: &Path) -> std::io::Result<(Vec<i16>, Vec<u8>, usize)> {
    let file = File::open(path)?;
    let gz = GzDecoder::new(BufReader::with_capacity(1 << 20, file));
    let mut de = serde_json::Deserializer::from_reader(BufReader::with_capacity(1 << 20, gz));
    de.deserialize_seq(RefCollector {
        flat: Vec::with_capacity(3_100_000 * DIM),
        labels: Vec::with_capacity(3_100_000),
        f32_mismatch: 0,
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------

fn tally(name: &str, results: &[(bool, bool, bool)], elapsed: std::time::Duration) {
    let (mut fp, mut fn_, mut edge_total, mut edge_wrong) = (0usize, 0usize, 0usize, 0usize);
    for &(approved, expected, is_edge) in results {
        if is_edge {
            edge_total += 1;
        }
        if approved != expected {
            if is_edge {
                edge_wrong += 1;
            }
            // FP = legit denied (expected approved, we denied)
            // FN = fraud approved (expected denied, we approved)
            if expected {
                fp += 1;
            } else {
                fn_ += 1;
            }
        }
    }
    let e = fp + 3 * fn_;
    eprintln!(
        "[{name}] FP={fp} FN={fn_} weighted_E={e} edge_wrong={edge_wrong}/{edge_total}  ({elapsed:?})"
    );
}

// ---- oracle mode: exact brute-force over raw refs, f32 vs f64 features ----

fn run_oracle(entries: &[Entry], refs_path: &str) -> std::io::Result<()> {
    eprintln!("loading references from {refs_path} ...");
    let t = Instant::now();
    let (refs, labels, f32_mismatch) = load_refs(Path::new(refs_path))?;
    eprintln!(
        "  {} refs ({} fraud) in {:?}; ref f32-vs-f64 quant mismatches: {}",
        labels.len(),
        labels.iter().filter(|&&l| l == 1).count(),
        t.elapsed(),
        f32_mismatch
    );

    let reqs: Vec<(Req, bool, f64)> = entries
        .iter()
        .map(|e| {
            let r: Req = serde_json::from_value(e.request.clone()).expect("bad request");
            (r, e.expected_approved, e.expected_fraud_score)
        })
        .collect();

    let vec_diff = reqs
        .par_iter()
        .filter(|(r, _, _)| vec_f32(r) != vec_f64(r))
        .count();
    eprintln!("queries with f32 != f64 quantized vector: {vec_diff}");

    for (name, vectorize) in [
        ("exact + f32 features", vec_f32 as fn(&Req) -> [i16; DIM]),
        ("exact + f64 features", vec_f64 as fn(&Req) -> [i16; DIM]),
    ] {
        let t = Instant::now();
        let results: Vec<(bool, bool, bool)> = reqs
            .par_iter()
            .map(|(r, exp, score)| {
                let q = vectorize(r);
                let approved = exact_fraud_count(&q, &refs, &labels) < 3;
                (approved, *exp, (score - 0.6).abs() < 1e-9)
            })
            .collect();
        tally(name, &results, t.elapsed());
    }
    Ok(())
}

// ---- runtime mode: real api search path (json parse + vectorizer + ivf) ----

fn run_runtime(entries: &[Entry], index_path: &str) -> std::io::Result<()> {
    eprintln!("loading index from {index_path} ...");
    let ds = api::dataset::load(Path::new(index_path))?;
    eprintln!("  index n={} k={}", ds.n, ds.k);

    let bodies: Vec<(Vec<u8>, bool, bool)> = entries
        .iter()
        .map(|e| {
            let bytes = serde_json::to_vec(&e.request).expect("serialize");
            (bytes, e.expected_approved, (e.expected_fraud_score - 0.6).abs() < 1e-9)
        })
        .collect();

    // Pre-vectorize once so the timing isolates search cost (the p99 driver).
    let queries: Vec<([f32; DIM], bool, bool)> = bodies
        .iter()
        .map(|(bytes, exp, is_edge)| {
            let p = api::json::parse(bytes).expect("parse");
            (api::vectorizer::vectorize(&p), *exp, *is_edge)
        })
        .collect();

    for (name, exact) in [("ivf gated (current)", false), ("ivf exact (no gate)", true)] {
        let mut results = Vec::with_capacity(queries.len());
        let mut times_ns = Vec::with_capacity(queries.len());
        let t = Instant::now();
        for (q, exp, is_edge) in &queries {
            let t0 = Instant::now();
            let frauds = if exact {
                api::ivf::search_fraud_count_exact(q, ds)
            } else {
                api::ivf::search_fraud_count(q, ds, api::ivf::nprobe_default())
            };
            times_ns.push(t0.elapsed().as_nanos() as u64);
            results.push((frauds < 3, *exp, *is_edge));
        }
        let elapsed = t.elapsed();
        tally(name, &results, elapsed);
        report_compute(&mut times_ns);
    }
    Ok(())
}

fn report_compute(times_ns: &mut [u64]) {
    times_ns.sort_unstable();
    let n = times_ns.len();
    let pct = |p: f64| times_ns[((n as f64 * p) as usize).min(n - 1)] as f64 / 1000.0;
    let mean = times_ns.iter().sum::<u64>() as f64 / n as f64 / 1000.0;
    eprintln!(
        "    search compute µs: mean={:.2} p50={:.2} p90={:.2} p99={:.2} p99.9={:.2} max={:.2}",
        mean,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(0.999),
        *times_ns.last().unwrap() as f64 / 1000.0
    );
}

fn main() -> std::io::Result<()> {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "runtime".into());
    let refs_path = std::env::var("REFS").unwrap_or_else(|_| "resources/references.json.gz".into());
    let index_path = std::env::var("INDEX").unwrap_or_else(|_| "resources/index.bin".into());
    let test_path = std::env::var("TESTDATA").unwrap_or_else(|_| "test/test-data.json".into());

    eprintln!("loading test data from {test_path} ...");
    let t = Instant::now();
    let td: TestData = serde_json::from_reader(BufReader::new(File::open(&test_path)?))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    eprintln!("  {} entries in {:?}", td.entries.len(), t.elapsed());

    match mode.as_str() {
        "oracle" => run_oracle(&td.entries, &refs_path)?,
        _ => run_runtime(&td.entries, &index_path)?,
    }
    Ok(())
}
