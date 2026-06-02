#[cfg(target_os = "linux")]
mod ctrl;
#[cfg(target_os = "linux")]
mod server;

use std::path::PathBuf;
#[cfg(not(target_os = "linux"))]
use std::time::Instant;

use api::dataset;
#[cfg(not(target_os = "linux"))]
use api::ivf;
#[cfg(not(target_os = "linux"))]
use api::DIM;
#[cfg(not(target_os = "linux"))]
use api::{json, vectorizer};

fn env_path(name: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| default.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() -> std::io::Result<()> {
    let index_path = env_path("INDEX_PATH", "resources/index.bin");
    let ds = dataset::load(&index_path)?;
    eprintln!("loaded {}: n={} k={}", index_path.display(), ds.n, ds.k);

    #[cfg(target_os = "linux")]
    {
        let uds_mode = std::env::var("UDS_MODE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0o666u32);
        let cfg = server::Config {
            uds_path: std::env::var("UDS_PATH")
                .unwrap_or_else(|_| "/sockets/api.sock".to_string()),
            uds_mode,
            cpu_pin: std::env::var("RINHA_CPU").ok().and_then(|s| s.parse().ok()),
            search_mode: std::env::var("SEARCH").ok().and_then(|s| s.parse().ok()).unwrap_or(0),
        };
        return server::run(cfg, ds);
    }

    #[cfg(not(target_os = "linux"))]
    {
        bench(ds);
        Ok(())
    }
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
        let _ = DIM;
        eprintln!(
            "{} bench (n=1000): p50={}.{}µs p99={}.{}µs max={}.{}µs",
            name,
            p50 / 1000,
            p50 % 1000 / 100,
            p99 / 1000,
            p99 % 1000 / 100,
            max / 1000,
            max % 1000 / 100
        );
    }
}
