use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use crate::DIM;

const KMEANS_INIT_SAMPLE: usize = 65_536;

#[inline(always)]
fn dist_sq(a: &[f32; DIM], b: &[f32; DIM]) -> f32 {
    let mut s = 0.0f32;
    for j in 0..DIM {
        let d = a[j] - b[j];
        s += d * d;
    }
    s
}

#[inline(always)]
fn nearest_centroid(v: &[f32; DIM], centroids: &[[f32; DIM]]) -> u16 {
    let mut best_d = f32::INFINITY;
    let mut best_i = 0u16;
    for (i, c) in centroids.iter().enumerate() {
        let d = dist_sq(v, c);
        if d < best_d {
            best_d = d;
            best_i = i as u16;
        }
    }
    best_i
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_usize(&mut self, n: usize) -> usize {
        ((self.next_u64() >> 33) as usize) % n
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn kmeans_pp_init(vectors: &[[f32; DIM]], k: usize, seed: u64) -> Vec<[f32; DIM]> {
    let n = vectors.len();
    let mut rng = Lcg::new(seed);
    let sample_size = n.min(KMEANS_INIT_SAMPLE);
    let sample: Vec<usize> = (0..sample_size).map(|_| rng.next_usize(n)).collect();

    let mut centroids: Vec<[f32; DIM]> = Vec::with_capacity(k);
    centroids.push(vectors[sample[rng.next_usize(sample_size)]]);

    let mut min_dists = vec![f32::INFINITY; sample_size];
    for _ in 1..k {
        let last = *centroids.last().unwrap();
        for (i, &si) in sample.iter().enumerate() {
            let d = dist_sq(&vectors[si], &last);
            if d < min_dists[i] {
                min_dists[i] = d;
            }
        }
        let total: f64 = min_dists.iter().map(|&x| x as f64).sum();
        let r = rng.next_f64() * total;
        let mut cum = 0.0f64;
        let mut chosen = sample_size - 1;
        for (i, &d) in min_dists.iter().enumerate() {
            cum += d as f64;
            if cum >= r {
                chosen = i;
                break;
            }
        }
        centroids.push(vectors[sample[chosen]]);
    }
    centroids
}

fn assign_parallel(
    vectors: &[[f32; DIM]],
    centroids: &[[f32; DIM]],
    assignments: &mut [u16],
) -> usize {
    let n_threads = thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(4)
        .min(16);
    let chunk = (vectors.len() + n_threads - 1) / n_threads;
    let changed = AtomicUsize::new(0);

    thread::scope(|s| {
        for (vc, ac) in vectors.chunks(chunk).zip(assignments.chunks_mut(chunk)) {
            let changed = &changed;
            s.spawn(move || {
                let mut local = 0usize;
                for (v, a) in vc.iter().zip(ac.iter_mut()) {
                    let nb = nearest_centroid(v, centroids);
                    if nb != *a {
                        local += 1;
                        *a = nb;
                    }
                }
                changed.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    changed.load(Ordering::Relaxed)
}

fn update_centroids(vectors: &[[f32; DIM]], assignments: &[u16], centroids: &mut [[f32; DIM]]) {
    let k = centroids.len();
    let mut sums = vec![[0.0f64; DIM]; k];
    let mut counts = vec![0u32; k];
    for (v, &a) in vectors.iter().zip(assignments.iter()) {
        let ci = a as usize;
        counts[ci] += 1;
        for j in 0..DIM {
            sums[ci][j] += v[j] as f64;
        }
    }
    for i in 0..k {
        if counts[i] == 0 {
            continue;
        }
        let inv = 1.0 / counts[i] as f64;
        for j in 0..DIM {
            centroids[i][j] = (sums[i][j] * inv) as f32;
        }
    }
}

pub fn train(
    vectors: &[[f32; DIM]],
    k: usize,
    iters: usize,
    seed: u64,
) -> (Vec<[f32; DIM]>, Vec<u16>) {
    eprintln!("kmeans++ init (k={}, sample={})", k, KMEANS_INIT_SAMPLE);
    let t = Instant::now();
    let mut centroids = kmeans_pp_init(vectors, k, seed);
    eprintln!("  init done in {:?}", t.elapsed());

    let mut assignments = vec![u16::MAX; vectors.len()];
    for it in 0..iters {
        let t = Instant::now();
        let changed = assign_parallel(vectors, &centroids, &mut assignments);
        update_centroids(vectors, &assignments, &mut centroids);
        eprintln!(
            "  iter {:2}/{}: {:5.2}% changed in {:?}",
            it + 1,
            iters,
            changed as f64 / vectors.len() as f64 * 100.0,
            t.elapsed()
        );
        if changed * 1000 < vectors.len() {
            eprintln!("  early-stop: <0.1% changes");
            break;
        }
    }

    (centroids, assignments)
}
