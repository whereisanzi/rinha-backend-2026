mod kmeans;
mod parse;
mod write;

use std::path::PathBuf;
use std::time::Instant;

pub const DIM: usize = 14;

const DEFAULT_K: usize = 512;
const DEFAULT_ITERS: usize = 10;
const DEFAULT_SEED: u64 = 0xdead_beef_cafe_babe;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <references.json.gz> <index.bin>",
            args.first().map(String::as_str).unwrap_or("build-index")
        );
        std::process::exit(2);
    }
    let in_path = PathBuf::from(&args[1]);
    let out_path = PathBuf::from(&args[2]);

    let k = env_usize("IVF_K", DEFAULT_K);
    let iters = env_usize("IVF_ITERS", DEFAULT_ITERS);
    let seed = std::env::var("IVF_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEED);

    let t0 = Instant::now();
    eprintln!("loading references from {}", in_path.display());
    let (vectors, labels) = parse::load(&in_path)?;
    eprintln!(
        "  {} vectors loaded in {:?} (mem={:.1} MB)",
        vectors.len(),
        t0.elapsed(),
        (vectors.len() * std::mem::size_of::<[f32; DIM]>()
            + labels.len() * std::mem::size_of::<u8>()) as f64
            / (1024.0 * 1024.0),
    );

    let t1 = Instant::now();
    let (centroids, assignments) = kmeans::train(&vectors, k, iters, seed);
    eprintln!("kmeans done in {:?}", t1.elapsed());

    let t2 = Instant::now();
    eprintln!("building index layout (k={}, n={})", k, vectors.len());
    let layout = write::build_layout(&vectors, &labels, &centroids, &assignments);
    eprintln!("  layout built in {:?}", t2.elapsed());

    let t3 = Instant::now();
    eprintln!("writing {}", out_path.display());
    write::write_index(&out_path, &layout)?;
    let meta = std::fs::metadata(&out_path)?;
    eprintln!(
        "  wrote {:.1} MB in {:?}",
        meta.len() as f64 / (1024.0 * 1024.0),
        t3.elapsed()
    );

    eprintln!("total: {:?}", t0.elapsed());
    Ok(())
}
