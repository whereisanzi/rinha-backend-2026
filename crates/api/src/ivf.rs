use crate::DIM;
use crate::dataset::{Dataset, LANES, STORE_DIM};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::sync::LazyLock;

pub const FIX_SCALE: f32 = 10_000.0;
const K: usize = 5;
const STACK_CAP: usize = 128;
const MAX_PARTS: usize = 256;

static EARLY_LIMIT: LazyLock<i64> = LazyLock::new(|| {
    let milli: i64 = std::env::var("EARLY_DIST_MILLI")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(140);
    let v = (FIX_SCALE as i64) * milli / 1000;
    v * v
});

pub fn nprobe_default() -> usize {
    1
}

pub fn search_fraud_count(query: &[f32; DIM], ds: &Dataset, _nprobe: usize) -> u8 {
    search_fraud_count_exact(query, ds)
}

pub fn search_fraud_count_probe(query: &[f32; DIM], ds: &Dataset) -> u8 {
    search_fraud_count_exact(query, ds)
}

pub fn search_fraud_count_exact(query: &[f32; DIM], ds: &Dataset) -> u8 {
    let mut q = [0i16; STORE_DIM];
    for j in 0..DIM {
        q[j] = quantize_i16(query[j]);
    }
    search_q(&q, ds)
}

#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))]
pub fn quantize_i16(x: f32) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * FIX_SCALE;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

#[inline]
fn partition_key(v: &[i16; STORE_DIM]) -> u32 {
    let mut key = 0u32;
    if v[5] >= 0 {
        key |= 1 << 0;
    }
    if v[9] > 0 {
        key |= 1 << 1;
    }
    if v[10] > 0 {
        key |= 1 << 2;
    }
    if v[11] > 0 {
        key |= 1 << 3;
    }
    let mr = v[12];
    if mr <= 2047 {
    } else if mr <= 4095 {
        key |= 1 << 4;
    } else if mr <= 6143 {
        key |= 2 << 4;
    } else {
        key |= 3 << 4;
    }
    if v[2] > 4096 {
        key |= 1 << 6;
    }
    if v[8] > 2048 {
        key |= 1 << 7;
    }
    key
}

#[inline(always)]
fn early_done(best: &[i64; K]) -> bool {
    best[K - 1] <= *EARLY_LIMIT
}

#[inline(always)]
fn sum_labels(labels: &[u8; K]) -> u8 {
    let mut n = 0u8;
    for &l in labels {
        n += l;
    }
    n.min(5)
}

#[inline(always)]
fn insert_best(dist: i64, label: u8, dists: &mut [i64; K], labels: &mut [u8; K]) {
    if dist >= dists[K - 1] {
        return;
    }
    let mut pos = K - 1;
    while pos > 0 && dist < dists[pos - 1] {
        dists[pos] = dists[pos - 1];
        labels[pos] = labels[pos - 1];
        pos -= 1;
    }
    dists[pos] = dist;
    labels[pos] = label;
}

#[inline(always)]
fn lower_bound_dim(q: i16, lo: i16, hi: i16) -> i64 {
    let diff = if q < lo {
        lo as i64 - q as i64
    } else if q > hi {
        q as i64 - hi as i64
    } else {
        0
    };
    diff * diff
}

#[inline]
fn lower_bound(q: &[i16; STORE_DIM], min: &[i16], max: &[i16], base: usize) -> i64 {
    let mut acc = 0i64;
    for d in 0..DIM {
        acc += lower_bound_dim(q[d], min[base + d], max[base + d]);
    }
    acc
}

fn search_q(q: &[i16; STORE_DIM], ds: &Dataset) -> u8 {
    let mut best_dists = [i64::MAX; K];
    let mut best_labels = [0u8; K];

    let key = partition_key(q);
    let primary = ds.part_by_key[(key & 0xff) as usize];
    if primary >= 0 {
        let root = ds.part_roots[primary as usize];
        if search_node(ds, root, 0, q, &mut best_dists, &mut best_labels) {
            return sum_labels(&best_labels);
        }
    }

    let mut probes = [(0i32, 0i64); MAX_PARTS];
    let mut n = 0usize;
    for p in 0..ds.k as i32 {
        if p == primary {
            continue;
        }
        let base = p as usize * STORE_DIM;
        let lb = lower_bound(q, ds.part_min, ds.part_max, base);
        if lb >= best_dists[K - 1] {
            continue;
        }
        probes[n] = (p, lb);
        n += 1;
    }
    probes[..n].sort_unstable_by_key(|&(_, lb)| lb);

    for &(part_idx, lb) in &probes[..n] {
        if lb >= best_dists[K - 1] {
            break;
        }
        let root = ds.part_roots[part_idx as usize];
        if search_node(ds, root, lb, q, &mut best_dists, &mut best_labels) {
            break;
        }
    }

    sum_labels(&best_labels)
}

fn search_node(
    ds: &Dataset,
    root: i32,
    root_bound: i64,
    q: &[i16; STORE_DIM],
    best_dists: &mut [i64; K],
    best_labels: &mut [u8; K],
) -> bool {
    if root < 0 || root as usize >= ds.node_left.len() {
        return false;
    }

    let mut stack_node = [0i32; STACK_CAP];
    let mut stack_bound = [0i64; STACK_CAP];
    let mut sp = 0usize;
    let mut current = root;
    let mut current_bound = root_bound;

    loop {
        if current_bound < best_dists[K - 1] {
            let ci = current as usize;
            let left = ds.node_left[ci];
            if left < 0 {
                let start = ds.node_start[ci];
                let len = ds.node_len[ci];
                if scan_leaf(ds, start, len, q, best_dists, best_labels) {
                    return true;
                }
            } else {
                let right = ds.node_right[ci];
                let lbase = left as usize * STORE_DIM;
                let rbase = right as usize * STORE_DIM;
                let lb = lower_bound(q, ds.node_min, ds.node_max, lbase);
                let rb = lower_bound(q, ds.node_min, ds.node_max, rbase);
                let (near, near_b, far, far_b) = if lb <= rb {
                    (left, lb, right, rb)
                } else {
                    (right, rb, left, lb)
                };
                if far_b < best_dists[K - 1] && sp < STACK_CAP {
                    stack_node[sp] = far;
                    stack_bound[sp] = far_b;
                    sp += 1;
                }
                current = near;
                current_bound = near_b;
                continue;
            }
        }

        if sp == 0 {
            break;
        }
        sp -= 1;
        current = stack_node[sp];
        current_bound = stack_bound[sp];
    }
    early_done(best_dists)
}

#[inline]
fn scan_leaf(
    ds: &Dataset,
    start_block: i32,
    len: i32,
    q: &[i16; STORE_DIM],
    best_dists: &mut [i64; K],
    best_labels: &mut [u8; K],
) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { scan_leaf_avx2(ds, start_block, len, q, best_dists, best_labels) };
        }
    }
    scan_leaf_scalar(ds, start_block, len, q, best_dists, best_labels)
}

fn scan_leaf_scalar(
    ds: &Dataset,
    start_block: i32,
    len: i32,
    q: &[i16; STORE_DIM],
    best_dists: &mut [i64; K],
    best_labels: &mut [u8; K],
) -> bool {
    let total_len = len as usize;
    let blocks = total_len.div_ceil(LANES);
    for b in 0..blocks {
        let block_idx = start_block as usize + b;
        let block_off = block_idx * DIM * LANES;
        let lane_count = (total_len - b * LANES).min(LANES);
        for lane in 0..lane_count {
            let mut dist = 0i64;
            for d in 0..DIM {
                let off = (d / 2) * LANES * 2 + lane * 2 + (d & 1);
                let v = ds.blocks[block_off + off] as i64;
                let diff = v - q[d] as i64;
                dist += diff * diff;
            }
            if dist < best_dists[K - 1] {
                let label = ds.labels[block_idx * LANES + lane];
                insert_best(dist, label, best_dists, best_labels);
            }
        }
        if early_done(best_dists) {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_leaf_avx2(
    ds: &Dataset,
    start_block: i32,
    len: i32,
    q: &[i16; STORE_DIM],
    best_dists: &mut [i64; K],
    best_labels: &mut [u8; K],
) -> bool {
    let total_len = len as usize;
    let blocks = total_len.div_ceil(LANES);
    let pairs = DIM / 2;

    let mut q_pairs = [_mm256_setzero_si256(); 7];
    for p in 0..pairs {
        let lo = q[p * 2] as u16 as u32;
        let hi = q[p * 2 + 1] as u16 as u32;
        q_pairs[p] = _mm256_set1_epi32((lo | (hi << 16)) as i32);
    }

    let vectors = ds.blocks.as_ptr();
    let labels_ptr = ds.labels.as_ptr();
    let mut vals = [0u32; LANES];

    for b in 0..blocks {
        let block_idx = start_block as usize + b;
        let base = vectors.add(block_idx * DIM * LANES);
        let mut acc = _mm256_setzero_si256();
        for p in 0..pairs {
            let packed = _mm256_loadu_si256(base.add(p * LANES * 2) as *const __m256i);
            let diff = _mm256_sub_epi16(q_pairs[p], packed);
            acc = _mm256_add_epi32(acc, _mm256_madd_epi16(diff, diff));
        }
        _mm256_storeu_si256(vals.as_mut_ptr() as *mut __m256i, acc);

        let labels_base = block_idx * LANES;
        let lane_count = (total_len - b * LANES).min(LANES);
        for lane in 0..lane_count {
            let dist = vals[lane] as i64;
            if dist < best_dists[K - 1] {
                let label = *labels_ptr.add(labels_base + lane);
                insert_best(dist, label, best_dists, best_labels);
            }
        }
        if early_done(best_dists) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_clamps_and_scales() {
        assert_eq!(quantize_i16(0.0), 0);
        assert_eq!(quantize_i16(1.0), 10_000);
        assert_eq!(quantize_i16(-1.0), -10_000);
        assert_eq!(quantize_i16(0.5), 5_000);
        assert_eq!(quantize_i16(2.0), 10_000);
        assert_eq!(quantize_i16(-2.0), -10_000);
        assert_eq!(quantize_i16(0.00004), 0);
        assert_eq!(quantize_i16(0.00005), 1);
        assert_eq!(quantize_i16(-0.00005), -1);
    }

    #[test]
    fn partition_key_bits() {
        let mut v = [0i16; STORE_DIM];
        assert_eq!(partition_key(&v), 1);
        v[5] = -1;
        assert_eq!(partition_key(&v), 0);
        v[9] = 1;
        assert_eq!(partition_key(&v), 1 << 1);
        v = [0i16; STORE_DIM];
        v[12] = 3000;
        assert_eq!(partition_key(&v) & (3 << 4), 1 << 4);
        v[12] = 5000;
        assert_eq!(partition_key(&v) & (3 << 4), 2 << 4);
        v[12] = 7000;
        assert_eq!(partition_key(&v) & (3 << 4), 3 << 4);
    }
}
