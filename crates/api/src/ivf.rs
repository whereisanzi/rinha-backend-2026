use crate::DIM;
use crate::dataset::{BLOCK_SIZE, BLOCK_STRIDE, Dataset};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::sync::LazyLock;

const NPROBE_DEFAULT: usize = 8;
pub const FIX_SCALE: f32 = 10_000.0;
const MAX_K: usize = 8192;
const BITSET_WORDS: usize = (MAX_K + 63) / 64;
const MAX_PROBE: usize = 256;
const REPAIR_MIN: u8 = 2;
const REPAIR_MAX: u8 = 3;

static FAST_NPROBE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("FAST_NPROBE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .clamp(1, MAX_PROBE)
});

static EARLY_LIMIT: LazyLock<i64> = LazyLock::new(|| {
    let milli: i64 = std::env::var("EARLY_DIST_MILLI")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if milli <= 0 {
        i64::MIN
    } else {
        let v = (FIX_SCALE as i64) * milli / 1000;
        v * v
    }
});

#[inline]
fn early_done(top5: &[Top5; 5], worst_idx: usize) -> bool {
    top5[worst_idx].dist <= *EARLY_LIMIT
}

#[inline(always)]
fn bitset_set(bs: &mut [u64; BITSET_WORDS], i: usize) {
    bs[i >> 6] |= 1u64 << (i & 63);
}

#[inline(always)]
fn bitset_get(bs: &[u64; BITSET_WORDS], i: usize) -> bool {
    (bs[i >> 6] >> (i & 63)) & 1 == 1
}

#[derive(Clone, Copy, Debug)]
struct Top5 {
    dist: i64,
    label: u8,
    orig_id: u32,
}

const SENTINEL: Top5 = Top5 {
    dist: i64::MAX,
    label: 0,
    orig_id: u32::MAX,
};

pub fn search_fraud_count(query: &[f32; DIM], ds: &Dataset, _nprobe: usize) -> u8 {
    search_impl(query, ds, true)
}

pub fn search_fraud_count_exact(query: &[f32; DIM], ds: &Dataset) -> u8 {
    search_impl(query, ds, false)
}

pub fn search_fraud_count_probe(query: &[f32; DIM], ds: &Dataset) -> u8 {
    let mut q_i16 = [0i16; DIM];
    for j in 0..DIM {
        q_i16[j] = quantize_i16(query[j]);
    }
    let mut cdists = [u32::MAX; MAX_K];
    let k = ds.k.min(MAX_K);
    let k_pad = ds.k_pad.min(MAX_K);
    compute_centroid_dists_i16(&q_i16, ds, &mut cdists, k_pad);

    let nprobe = (*FAST_NPROBE).min(k);
    let mut probe_buf = [0usize; MAX_PROBE];
    top_n_centroids(&cdists[..k], &mut probe_buf[..nprobe]);

    let mut top5 = [SENTINEL; 5];
    let mut worst_idx = 0usize;
    let mut scanned = [0u64; BITSET_WORDS];
    for &c in probe_buf[..nprobe].iter() {
        if !bitset_get(&scanned, c) {
            bitset_set(&mut scanned, c);
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }
    top5.iter().map(|e| e.label as u8).sum::<u8>().min(5)
}

#[inline]
fn search_impl(query: &[f32; DIM], ds: &Dataset, gated: bool) -> u8 {
    let mut q_i16 = [0i16; DIM];
    for j in 0..DIM {
        q_i16[j] = quantize_i16(query[j]);
    }

    let mut cdists = [u32::MAX; MAX_K];
    let k = ds.k.min(MAX_K);
    let k_pad = ds.k_pad.min(MAX_K);
    compute_centroid_dists_i16(&q_i16, ds, &mut cdists, k_pad);

    let nprobe = (*FAST_NPROBE).min(k);
    let mut probe_buf = [0usize; MAX_PROBE];
    top_n_centroids(&cdists[..k], &mut probe_buf[..nprobe]);

    let mut top5 = [SENTINEL; 5];
    let mut worst_idx = 0usize;
    let mut scanned = [0u64; BITSET_WORDS];

    for &c in probe_buf[..nprobe].iter() {
        if !bitset_get(&scanned, c) {
            bitset_set(&mut scanned, c);
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
            if early_done(&top5, worst_idx) {
                return top5.iter().map(|e| e.label as u8).sum::<u8>().min(5);
            }
        }
    }

    if gated {
        let fast_count: u8 = top5.iter().map(|e| e.label as u8).sum();
        if fast_count < REPAIR_MIN || fast_count > REPAIR_MAX {
            return fast_count.min(5);
        }
    }

    for c in 0..k {
        if bitset_get(&scanned, c) {
            continue;
        }
        let lb = bbox_lower_bound(&q_i16, ds, c);
        if lb <= top5[worst_idx].dist {
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    let fraud_count: u8 = top5.iter().map(|e| e.label as u8).sum();
    fraud_count.min(5)
}

#[inline]
fn bbox_lower_bound(q: &[i16; DIM], ds: &Dataset, c: usize) -> i64 {
    let base = c * DIM;
    let mut s: i64 = 0;
    for j in 0..DIM {
        let qv = q[j] as i32;
        let lo = ds.bbox_min[base + j] as i32;
        let hi = ds.bbox_max[base + j] as i32;
        let d = if qv < lo {
            lo - qv
        } else if qv > hi {
            qv - hi
        } else {
            0
        };
        s += (d as i64) * (d as i64);
    }
    s
}

fn top_n_centroids(dists: &[u32], out: &mut [usize]) {
    let n = out.len();
    let mut top_d = [u32::MAX; MAX_PROBE];
    for (c, &d) in dists.iter().enumerate() {
        if d < top_d[n - 1] {
            let mut pos = n - 1;
            while pos > 0 && d < top_d[pos - 1] {
                pos -= 1;
            }
            let mut i = n - 1;
            while i > pos {
                top_d[i] = top_d[i - 1];
                out[i] = out[i - 1];
                i -= 1;
            }
            top_d[pos] = d;
            out[pos] = c;
        }
    }
}

#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))]
pub fn quantize_i16(x: f32) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * FIX_SCALE;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

fn compute_centroid_dists_i16(
    query: &[i16; DIM],
    ds: &Dataset,
    out: &mut [u32; MAX_K],
    k_pad: usize,
) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { compute_centroid_dists_i16_avx2(query, ds, out, k_pad) };
            return;
        }
    }
    compute_centroid_dists_i16_scalar(query, ds, out, k_pad);
}

fn compute_centroid_dists_i16_scalar(
    query: &[i16; DIM],
    ds: &Dataset,
    out: &mut [u32; MAX_K],
    k_pad: usize,
) {
    let kp = k_pad;
    for c in 0..ds.k {
        let mut s: u32 = 0;
        for j in 0..DIM {
            let q = query[j] as i32;
            let v = ds.centroids_soa_i16[j * kp + c] as i32;
            let d = q - v;
            s = s.wrapping_add((d * d) as u32);
        }
        out[c] = s;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn compute_centroid_dists_i16_avx2(
    query: &[i16; DIM],
    ds: &Dataset,
    out: &mut [u32; MAX_K],
    k_pad: usize,
) {
    let cp = ds.centroids_soa_i16.as_ptr();
    let op = out.as_mut_ptr() as *mut __m256i;

    let mut c = 0usize;
    while c + 8 <= k_pad {
        let mut acc = _mm256_setzero_si256();
        let mut j = 0usize;
        while j + 2 <= DIM {
            let r0 = _mm_loadu_si128(cp.add(j * k_pad + c) as *const __m128i);
            let r1 = _mm_loadu_si128(cp.add((j + 1) * k_pad + c) as *const __m128i);
            let q0 = _mm_set1_epi16(query[j]);
            let q1 = _mm_set1_epi16(query[j + 1]);
            let d0 = _mm_sub_epi16(q0, r0);
            let d1 = _mm_sub_epi16(q1, r1);
            let lo = _mm_unpacklo_epi16(d0, d1);
            let hi = _mm_unpackhi_epi16(d0, d1);
            let pairs = _mm256_set_m128i(hi, lo);
            acc = _mm256_add_epi32(acc, _mm256_madd_epi16(pairs, pairs));
            j += 2;
        }
        while j < DIM {
            let r = _mm_loadu_si128(cp.add(j * k_pad + c) as *const __m128i);
            let q = _mm_set1_epi16(query[j]);
            let d = _mm_sub_epi16(q, r);
            let d_lo = _mm256_cvtepi16_epi32(d);
            let sq = _mm256_mullo_epi32(d_lo, d_lo);
            acc = _mm256_add_epi32(acc, sq);
            j += 1;
        }
        _mm256_storeu_si256(op.add(c / 8), acc);
        c += 8;
    }
}

fn scan_cluster(
    c: usize,
    q: &[i16; DIM],
    ds: &Dataset,
    top5: &mut [Top5; 5],
    worst_idx: &mut usize,
) {
    let start = ds.offsets[c] as usize;
    let end = ds.offsets[c + 1] as usize;
    if start >= end {
        return;
    }
    let block_start = ds.block_offsets[c] as usize;
    let block_end = ds.block_offsets[c + 1] as usize;
    let cluster_size = end - start;

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                scan_cluster_avx2(
                    block_start,
                    block_end,
                    start,
                    cluster_size,
                    q,
                    ds,
                    top5,
                    worst_idx,
                );
            }
            return;
        }
    }
    scan_cluster_scalar(
        block_start,
        block_end,
        start,
        cluster_size,
        q,
        ds,
        top5,
        worst_idx,
    );
}

fn scan_cluster_scalar(
    block_start: usize,
    block_end: usize,
    vec_start: usize,
    cluster_size: usize,
    q: &[i16; DIM],
    ds: &Dataset,
    top5: &mut [Top5; 5],
    worst_idx: &mut usize,
) {
    for (block_local, block_idx) in (block_start..block_end).enumerate() {
        let block_base = block_idx * BLOCK_STRIDE;
        let lanes_in_block = (cluster_size - block_local * BLOCK_SIZE).min(BLOCK_SIZE);
        for lane in 0..lanes_in_block {
            let mut d: i64 = 0;
            for j in 0..DIM {
                let qv = q[j] as i32;
                let v = ds.blocks[block_base + j * BLOCK_SIZE + lane] as i32;
                let diff = qv - v;
                d += (diff as i64) * (diff as i64);
                if d > top5[*worst_idx].dist {
                    break;
                }
            }
            let global = vec_start + block_local * BLOCK_SIZE + lane;
            try_insert_top5(top5, worst_idx, d, ds.labels[global], ds.orig_ids[global]);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_cluster_avx2(
    block_start: usize,
    block_end: usize,
    vec_start: usize,
    cluster_size: usize,
    q: &[i16; DIM],
    ds: &Dataset,
    top5: &mut [Top5; 5],
    worst_idx: &mut usize,
) {

    let mut q_pairs = [_mm256_setzero_si256(); DIM / 2];
    for p in 0..(DIM / 2) {
        let a = _mm_set1_epi16(q[2 * p]);
        let b = _mm_set1_epi16(q[2 * p + 1]);
        let lo = _mm_unpacklo_epi16(a, b);

        q_pairs[p] = _mm256_broadcastsi128_si256(lo);
    }

    let blocks_ptr = ds.blocks.as_ptr();
    let mut dists = [0i64; 8];
    let num_blocks = block_end - block_start;

    const EARLY_PAIR: usize = 4;

    for block_local in 0..num_blocks {
        let block_idx = block_start + block_local;
        let block_ptr = blocks_ptr.add(block_idx * BLOCK_STRIDE);

        if block_local + 1 < num_blocks {
            let next = blocks_ptr.add((block_idx + 1) * BLOCK_STRIDE);
            _mm_prefetch(next as *const i8, _MM_HINT_T0);
            _mm_prefetch(next.add(64) as *const i8, _MM_HINT_T0);
            _mm_prefetch(next.add(112) as *const i8, _MM_HINT_T0);
        }

        let mut acc_lo = _mm256_setzero_si256();
        let mut acc_hi = _mm256_setzero_si256();

        let lanes_in_block = (cluster_size - block_local * BLOCK_SIZE).min(BLOCK_SIZE);
        let worst = top5[*worst_idx].dist;

        for p in 0..EARLY_PAIR {
            accumulate_pair_avx2(block_ptr, q_pairs[p], 2 * p, &mut acc_lo, &mut acc_hi);
        }
        if !any_below_avx2(acc_lo, acc_hi, &mut dists, lanes_in_block, worst) {
            continue;
        }

        for p in EARLY_PAIR..(DIM / 2) {
            accumulate_pair_avx2(block_ptr, q_pairs[p], 2 * p, &mut acc_lo, &mut acc_hi);
        }

        _mm256_storeu_si256(dists.as_mut_ptr() as *mut __m256i, acc_lo);
        _mm256_storeu_si256((dists.as_mut_ptr() as *mut __m256i).add(1), acc_hi);
        for lane in 0..lanes_in_block {
            let global = vec_start + block_local * BLOCK_SIZE + lane;
            try_insert_top5(
                top5,
                worst_idx,
                dists[lane],
                ds.labels[global],
                ds.orig_ids[global],
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn accumulate_pair_avx2(
    block_ptr: *const i16,
    q_pair: __m256i,
    j: usize,
    acc_lo: &mut __m256i,
    acc_hi: &mut __m256i,
) {
    let r0 = _mm_loadu_si128(block_ptr.add(j * BLOCK_SIZE) as *const __m128i);
    let r1 = _mm_loadu_si128(block_ptr.add((j + 1) * BLOCK_SIZE) as *const __m128i);

    let inter_lo = _mm_unpacklo_epi16(r0, r1);
    let inter_hi = _mm_unpackhi_epi16(r0, r1);
    let v_pair = _mm256_set_m128i(inter_hi, inter_lo);

    let diff = _mm256_sub_epi16(q_pair, v_pair);

    let sq = _mm256_madd_epi16(diff, diff);

    let lo = _mm256_castsi256_si128(sq);
    let hi = _mm256_extracti128_si256(sq, 1);
    *acc_lo = _mm256_add_epi64(*acc_lo, _mm256_cvtepi32_epi64(lo));
    *acc_hi = _mm256_add_epi64(*acc_hi, _mm256_cvtepi32_epi64(hi));
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn any_below_avx2(
    acc_lo: __m256i,
    acc_hi: __m256i,
    dists: &mut [i64; 8],
    lanes_in_block: usize,
    worst: i64,
) -> bool {
    _mm256_storeu_si256(dists.as_mut_ptr() as *mut __m256i, acc_lo);
    _mm256_storeu_si256((dists.as_mut_ptr() as *mut __m256i).add(1), acc_hi);
    for &d in dists.iter().take(lanes_in_block) {
        if d < worst {
            return true;
        }
    }
    false
}

#[inline(always)]
fn try_insert_top5(top5: &mut [Top5; 5], worst_idx: &mut usize, d: i64, label: u8, orig_id: u32) {
    let worst = top5[*worst_idx];
    let better = d < worst.dist || (d == worst.dist && orig_id < worst.orig_id);
    if !better {
        return;
    }
    top5[*worst_idx] = Top5 {
        dist: d,
        label,
        orig_id,
    };

    let mut wi = 0;
    for i in 1..5 {
        let a = top5[i];
        let b = top5[wi];
        if a.dist > b.dist || (a.dist == b.dist && a.orig_id > b.orig_id) {
            wi = i;
        }
    }
    *worst_idx = wi;
}

pub fn nprobe_default() -> usize {
    NPROBE_DEFAULT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::Dataset;

    fn make_synthetic_dataset(
        clusters: &[(Vec<[i16; DIM]>, Vec<u8>, Vec<u32>)],
        centroids_f32: &[[f32; DIM]],
    ) -> &'static Dataset {
        let k = clusters.len();
        assert_eq!(centroids_f32.len(), k);
        let n: usize = clusters.iter().map(|(v, _, _)| v.len()).sum();

        let mut offsets = Vec::with_capacity(k + 1);
        offsets.push(0u32);
        let mut acc = 0u32;
        for (v, _, _) in clusters {
            acc += v.len() as u32;
            offsets.push(acc);
        }

        let mut block_offsets = Vec::with_capacity(k + 1);
        block_offsets.push(0u32);
        let mut bacc = 0u32;
        for (v, _, _) in clusters {
            bacc += ((v.len() + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32;
            block_offsets.push(bacc);
        }
        let total_blocks = bacc as usize;

        let mut blocks = vec![i16::MAX; total_blocks * BLOCK_STRIDE];
        let mut labels = Vec::with_capacity(n);
        let mut orig_ids = Vec::with_capacity(n);
        let mut bbox_min = vec![i16::MAX; k * DIM];
        let mut bbox_max = vec![i16::MIN; k * DIM];

        for (c, (vecs, lbls, ids)) in clusters.iter().enumerate() {
            let block_base_global = block_offsets[c] as usize;
            for (idx, v) in vecs.iter().enumerate() {
                let block_local = idx / BLOCK_SIZE;
                let lane = idx % BLOCK_SIZE;
                let block_base = (block_base_global + block_local) * BLOCK_STRIDE;
                for j in 0..DIM {
                    blocks[block_base + j * BLOCK_SIZE + lane] = v[j];
                    let bi = c * DIM + j;
                    if v[j] < bbox_min[bi] {
                        bbox_min[bi] = v[j];
                    }
                    if v[j] > bbox_max[bi] {
                        bbox_max[bi] = v[j];
                    }
                }
                labels.push(lbls[idx]);
                orig_ids.push(ids[idx]);
            }
        }

        let mut centroids = Vec::with_capacity(k * DIM);
        for c in centroids_f32 {
            centroids.extend_from_slice(c);
        }

        let k_pad = (k + 7) & !7;
        let mut centroids_soa = vec![f32::INFINITY; DIM * k_pad];
        let mut centroids_soa_i16 = vec![i16::MAX; DIM * k_pad];
        for c in 0..k {
            for j in 0..DIM {
                let v = centroids[c * DIM + j];
                centroids_soa[j * k_pad + c] = v;
                let clamped = v.clamp(-1.0, 1.0);
                let s = clamped * FIX_SCALE;
                let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
                centroids_soa_i16[j * k_pad + c] = r as i16;
            }
        }

        let ds = Dataset {
            n,
            k,
            k_pad,
            scale: FIX_SCALE,
            centroids: Vec::leak(centroids),
            centroids_soa: Vec::leak(centroids_soa),
            centroids_soa_i16: Vec::leak(centroids_soa_i16),
            bbox_min: Vec::leak(bbox_min),
            bbox_max: Vec::leak(bbox_max),
            offsets: Vec::leak(offsets),
            block_offsets: Vec::leak(block_offsets),
            blocks: Vec::leak(blocks),
            labels: Vec::leak(labels),
            orig_ids: Vec::leak(orig_ids),
        };
        Box::leak(Box::new(ds))
    }

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
    fn end_to_end_picks_correct_neighbours() {
        let mut c0 = Vec::new();
        for i in 0..5 {
            let mut v = [0i16; DIM];
            v[0] = i;
            c0.push(v);
        }
        let mut c1 = Vec::new();
        for i in 0..10 {
            let mut v = [0i16; DIM];
            v[0] = 1000 + i;
            c1.push(v);
        }
        let ds = make_synthetic_dataset(
            &[
                (c0, vec![1u8; 5], (0..5u32).collect()),
                (c1, vec![0u8; 10], (5..15u32).collect()),
            ],
            &[[0.0; DIM], {
                let mut c = [0.0f32; DIM];
                c[0] = 0.1;
                c
            }],
        );

        let q = [0.0f32; DIM];
        assert_eq!(search_fraud_count(&q, ds, 1), 5);

        let mut q2 = [0.0f32; DIM];
        q2[0] = 0.1;
        assert_eq!(search_fraud_count(&q2, ds, 1), 0);
    }

    #[test]
    fn fast_then_full_escalates_for_borderline() {
        let mut c0 = Vec::new();
        for i in 0..3 {
            let mut v = [0i16; DIM];
            v[0] = i;
            c0.push(v);
        }
        let mut c1 = Vec::new();
        for i in 0..2 {
            let mut v = [0i16; DIM];
            v[0] = i;
            c1.push(v);
        }
        let ds = make_synthetic_dataset(
            &[
                (c0, vec![1u8; 3], (0..3u32).collect()),
                (c1, vec![0u8; 2], (3..5u32).collect()),
            ],
            &[[0.0; DIM], [0.0; DIM]],
        );

        let q = [0.0f32; DIM];
        let count = search_fraud_count(&q, ds, 8);
        assert_eq!(count, 3);
    }
}
