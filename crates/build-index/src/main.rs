mod parse;
mod write;

use std::path::PathBuf;
use std::time::Instant;

pub const DIM: usize = 14;

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
    eprintln!("building kd index (n={})", vectors.len());
    write::build_and_write(&vectors, &labels, &out_path)?;
    let meta = std::fs::metadata(&out_path)?;
    eprintln!(
        "  wrote {:.1} MB in {:?}",
        meta.len() as f64 / (1024.0 * 1024.0),
        t1.elapsed()
    );

    eprintln!("total: {:?}", t0.elapsed());
    Ok(())
}
