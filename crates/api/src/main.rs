mod dataset;
mod http;
mod ivf;
mod json;
mod responses;
#[cfg(target_os = "linux")]
mod server;
mod vectorizer;

use std::path::PathBuf;
use std::time::Instant;

pub const DIM: usize = 14;

fn env_path(name: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| default.to_string()))
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(target_os = "linux")]
fn env_i32(name: &str, default: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() -> std::io::Result<()> {
    let index_path = env_path("INDEX_PATH", "resources/index.bin");
    let t = Instant::now();
    let ds = dataset::load(&index_path)?;
    eprintln!(
        "loaded {} in {:?}: n={} k={}",
        index_path.display(),
        t.elapsed(),
        ds.n,
        ds.k,
    );

    let mode = std::env::var("MODE").unwrap_or_default();
    if mode == "trace" {
        let nprobe = env_usize("NPROBE", ivf::nprobe_default());
        let data_path = std::env::var("TRACE_DATA")
            .unwrap_or_else(|_| "test/test-data.json".to_string());
        return run_trace(ds, nprobe, &data_path);
    }

    #[cfg(target_os = "linux")]
    {
        let cfg = server::Config {
            uds_path: std::env::var("UDS_PATH")
                .unwrap_or_else(|_| "/sockets/api.sock".to_string()),
            uds_mode: env_usize("UDS_MODE", 0o666) as u32,
            nprobe: env_usize("NPROBE", ivf::nprobe_default()),
            backlog: env_i32("BACKLOG", 4096),
        };
        return server::run(cfg, ds);
    }

    #[cfg(not(target_os = "linux"))]
    {
        if mode == "bench" || mode.is_empty() {
            bench(ds);
        } else {
            eprintln!(
                "server requires Linux io_uring; current OS = {} (use MODE=bench or MODE=trace)",
                std::env::consts::OS
            );
        }
        Ok(())
    }
}

fn run_trace(ds: &dataset::Dataset, nprobe: usize, data_path: &str) -> std::io::Result<()> {
    let bytes = std::fs::read(data_path)?;
    let entries_marker = br#""entries":["#;
    let pos = memchr::memmem::find(&bytes, entries_marker)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "entries key missing"))?;
    let mut i = pos + entries_marker.len();

    let mut total_ns_arr: Vec<u64> = Vec::with_capacity(60_000);
    let mut phase12_ns_arr: Vec<u64> = Vec::with_capacity(60_000);
    let mut phase3_ns_arr: Vec<u64> = Vec::with_capacity(60_000);
    let mut extra_scans_arr: Vec<u32> = Vec::with_capacity(60_000);
    let mut lb_checks_arr: Vec<u32> = Vec::with_capacity(60_000);
    let mut parsed_ok: u64 = 0;
    let mut parse_failed: u64 = 0;

    let req_marker = br#""request":"#;

    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            break;
        }
        let entry_start = i;
        let mut depth: i32 = 1;
        let mut in_str = false;
        let mut esc = false;
        i += 1;
        while i < bytes.len() && depth > 0 {
            let c = bytes[i];
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
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            i += 1;
        }
        let entry = &bytes[entry_start..i];

        let rp = match memchr::memmem::find(entry, req_marker) {
            Some(p) => p + req_marker.len(),
            None => continue,
        };
        let mut rs = rp;
        while rs < entry.len() && matches!(entry[rs], b' ' | b'\t' | b'\n' | b'\r') {
            rs += 1;
        }
        if rs >= entry.len() || entry[rs] != b'{' {
            continue;
        }
        let req_start = rs;
        let mut depth: i32 = 1;
        let mut in_str = false;
        let mut esc = false;
        rs += 1;
        while rs < entry.len() && depth > 0 {
            let c = entry[rs];
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
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            rs += 1;
        }
        let request = &entry[req_start..rs];

        match json::parse(request) {
            Some(p) => {
                let q = vectorizer::vectorize(&p);
                let (_count, tr) = ivf::search_fraud_count_traced(&q, ds, nprobe);
                total_ns_arr.push(tr.total_ns);
                phase12_ns_arr.push(tr.phase1_2_ns);
                phase3_ns_arr.push(tr.phase3_ns);
                extra_scans_arr.push(tr.phase3_scans_extra);
                lb_checks_arr.push(tr.phase3_lb_checks);
                parsed_ok += 1;
            }
            None => {
                parse_failed += 1;
            }
        }
    }

    eprintln!(
        "trace: nprobe={} k={} parsed_ok={} parse_failed={}",
        nprobe, ds.k, parsed_ok, parse_failed
    );

    print_pcts_ns("total       ", &mut total_ns_arr);
    print_pcts_ns("phase1+2 (centroid+nprobe)", &mut phase12_ns_arr);
    print_pcts_ns("phase3   (bbox escalation)", &mut phase3_ns_arr);
    print_pcts_u32("extra_scans (clusters scanned beyond nprobe)", &mut extra_scans_arr);
    print_pcts_u32("lb_checks   (clusters bbox-checked)", &mut lb_checks_arr);

    let total_extra: u64 = extra_scans_arr.iter().map(|&x| x as u64).sum();
    let with_extra = extra_scans_arr.iter().filter(|&&x| x > 0).count();
    let zero_extra = extra_scans_arr.iter().filter(|&&x| x == 0).count();
    eprintln!(
        "summary: requests_with_extra_scans={} (no_escalation={}) total_extra_scans={}",
        with_extra, zero_extra, total_extra
    );

    Ok(())
}

fn percentile_u64(v: &[u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let idx = ((v.len() as f64) * p).floor() as usize;
    v[idx.min(v.len() - 1)]
}

fn percentile_u32(v: &[u32], p: f64) -> u32 {
    if v.is_empty() {
        return 0;
    }
    let idx = ((v.len() as f64) * p).floor() as usize;
    v[idx.min(v.len() - 1)]
}

fn print_pcts_ns(label: &str, v: &mut Vec<u64>) {
    v.sort_unstable();
    let p50 = percentile_u64(v, 0.50);
    let p90 = percentile_u64(v, 0.90);
    let p95 = percentile_u64(v, 0.95);
    let p99 = percentile_u64(v, 0.99);
    let p999 = percentile_u64(v, 0.999);
    let max = *v.last().unwrap_or(&0);
    let avg = if v.is_empty() {
        0
    } else {
        v.iter().sum::<u64>() / v.len() as u64
    };
    eprintln!(
        "{}: avg={}µs p50={}µs p90={}µs p95={}µs p99={}µs p99.9={}µs max={}µs",
        label,
        avg / 1000,
        p50 / 1000,
        p90 / 1000,
        p95 / 1000,
        p99 / 1000,
        p999 / 1000,
        max / 1000
    );
}

fn print_pcts_u32(label: &str, v: &mut Vec<u32>) {
    v.sort_unstable();
    let p50 = percentile_u32(v, 0.50);
    let p90 = percentile_u32(v, 0.90);
    let p95 = percentile_u32(v, 0.95);
    let p99 = percentile_u32(v, 0.99);
    let p999 = percentile_u32(v, 0.999);
    let max = *v.last().unwrap_or(&0);
    let avg = if v.is_empty() {
        0u32
    } else {
        (v.iter().map(|&x| x as u64).sum::<u64>() / v.len() as u64) as u32
    };
    eprintln!(
        "{}: avg={} p50={} p90={} p95={} p99={} p99.9={} max={}",
        label, avg, p50, p90, p95, p99, p999, max
    );
}

#[cfg(not(target_os = "linux"))]
fn bench(ds: &dataset::Dataset) {
    let nprobe = env_usize("NPROBE", ivf::nprobe_default());

    let legit = br#"{"id":"x","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-003","MERC-016"]},"merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},"terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},"last_transaction":null}"#;
    let fraud = br#"{"id":"x","transaction":{"amount":9505.97,"installments":10,"requested_at":"2026-03-14T05:15:12Z"},"customer":{"avg_amount":81.28,"tx_count_24h":20,"known_merchants":["MERC-008","MERC-007","MERC-005"]},"merchant":{"id":"MERC-068","mcc":"7802","avg_amount":54.86},"terminal":{"is_online":false,"card_present":true,"km_from_home":952.27},"last_transaction":null}"#;

    for (name, body) in [("legit", legit.as_ref()), ("fraud", fraud.as_ref())] {
        let p = json::parse(body).unwrap();
        let q = vectorizer::vectorize(&p);
        let mut samples = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let t = Instant::now();
            let _ = std::hint::black_box(ivf::search_fraud_count(&q, ds, nprobe));
            samples.push(t.elapsed().as_nanos() as u64);
        }
        samples.sort_unstable();
        let p50 = samples[samples.len() / 2];
        let p99 = samples[samples.len() * 99 / 100];
        let max = *samples.last().unwrap();
        eprintln!(
            "{} bench (n=1000, nprobe={}): p50={}.{}µs p99={}.{}µs max={}.{}µs",
            name,
            nprobe,
            p50 / 1000,
            p50 % 1000 / 100,
            p99 / 1000,
            p99 % 1000 / 100,
            max / 1000,
            max % 1000 / 100
        );
    }
}
