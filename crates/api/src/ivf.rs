use crate::DIM;
use crate::dataset::Dataset;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const NPROBE_DEFAULT: usize = 8;
pub const FIX_SCALE: f32 = 10_000.0;
const MAX_K: usize = 4096;
const BITSET_WORDS: usize = (MAX_K + 63) / 64;
const FAST_NPROBE: usize = 8;
#[cfg(target_arch = "x86_64")]
const EARLY_TERM_DIM: usize = 8;

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
    let mut cdists = [f32::INFINITY; MAX_K];
    let k = ds.k.min(MAX_K);
    let k_pad = ds.k_pad.min(MAX_K);
    compute_centroid_dists(query, ds, &mut cdists, k_pad);

    let fast_probes = top_n_centroids::<FAST_NPROBE>(&cdists[..k]);

    let mut top5 = [SENTINEL; 5];
    let mut worst_idx = 0usize;
    let mut scanned = [0u64; BITSET_WORDS];

    let mut q_i16 = [0i16; DIM];
    for j in 0..DIM {
        q_i16[j] = quantize_i16(query[j]);
    }

    for &c in fast_probes.iter() {
        if !bitset_get(&scanned, c) {
            bitset_set(&mut scanned, c);
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    let fast_count: u8 = top5.iter().map(|e| e.label as u8).sum();
    if fast_count != 2 && fast_count != 3 {
        return fast_count.min(5);
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

fn top_n_centroids<const N: usize>(dists: &[f32]) -> [usize; N] {
    let mut top_d = [f32::INFINITY; N];
    let mut top_i = [0usize; N];
    for (c, &d) in dists.iter().enumerate() {
        if d < top_d[N - 1] {
            let mut pos = N - 1;
            while pos > 0 && d < top_d[pos - 1] {
                pos -= 1;
            }
            let mut i = N - 1;
            while i > pos {
                top_d[i] = top_d[i - 1];
                top_i[i] = top_i[i - 1];
                i -= 1;
            }
            top_d[pos] = d;
            top_i[pos] = c;
        }
    }
    top_i
}

#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))]
pub fn quantize_i16(x: f32) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * FIX_SCALE;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

fn compute_centroid_dists(query: &[f32; DIM], ds: &Dataset, out: &mut [f32; MAX_K], k_pad: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
            unsafe { compute_centroid_dists_avx2(query, ds, out, k_pad) };
            return;
        }
    }
    compute_centroid_dists_scalar(query, ds, out, k_pad);
}

fn compute_centroid_dists_scalar(
    query: &[f32; DIM],
    ds: &Dataset,
    out: &mut [f32; MAX_K],
    k_pad: usize,
) {
    let kp = k_pad;
    for c in 0..ds.k {
        let mut s = 0.0f32;
        for j in 0..DIM {
            let d = query[j] - ds.centroids_soa[j * kp + c];
            s += d * d;
        }
        out[c] = s;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn compute_centroid_dists_avx2(
    query: &[f32; DIM],
    ds: &Dataset,
    out: &mut [f32; MAX_K],
    k_pad: usize,
) {
    let cp = ds.centroids_soa.as_ptr();
    let op = out.as_mut_ptr();

    let qd0 = _mm256_set1_ps(query[0]);
    let mut c = 0usize;
    while c + 8 <= k_pad {
        let cv = _mm256_loadu_ps(cp.add(c));
        let d = _mm256_sub_ps(cv, qd0);
        _mm256_storeu_ps(op.add(c), _mm256_mul_ps(d, d));
        c += 8;
    }

    for j in 1..DIM {
        let base = j * k_pad;
        let qd = _mm256_set1_ps(query[j]);
        let mut c = 0usize;
        while c + 8 <= k_pad {
            let cv = _mm256_loadu_ps(cp.add(base + c));
            let d = _mm256_sub_ps(cv, qd);
            let prev = _mm256_loadu_ps(op.add(c));
            _mm256_storeu_ps(op.add(c), _mm256_fmadd_ps(d, d, prev));
            c += 8;
        }
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

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                scan_cluster_avx2(start, end, q, ds, top5, worst_idx);
            }
            return;
        }
    }
    scan_cluster_scalar(start, end, q, ds, top5, worst_idx);
}

fn scan_cluster_scalar(
    start: usize,
    end: usize,
    q: &[i16; DIM],
    ds: &Dataset,
    top5: &mut [Top5; 5],
    worst_idx: &mut usize,
) {
    for i in start..end {
        let mut d: i64 = 0;
        for j in 0..DIM {
            let qv = q[j] as i32;
            let v = ds.dims[j][i] as i32;
            let diff = qv - v;
            d += (diff as i64) * (diff as i64);
            if d > top5[*worst_idx].dist {
                break;
            }
        }
        try_insert_top5(top5, worst_idx, d, ds.labels[i], ds.orig_ids[i]);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_cluster_avx2(
    start: usize,
    end: usize,
    q: &[i16; DIM],
    ds: &Dataset,
    top5: &mut [Top5; 5],
    worst_idx: &mut usize,
) {
    let mut q_i32 = [_mm256_setzero_si256(); DIM];
    for j in 0..DIM {
        q_i32[j] = _mm256_set1_epi32(q[j] as i32);
    }

    let mut i = start;
    let mut dists = [0i64; 8];
    while i + 8 <= end {
        let prefetch_off = i + 16;
        if prefetch_off + 8 <= end {
            for j in 0..DIM {
                _mm_prefetch(
                    ds.dims[j].as_ptr().add(prefetch_off) as *const i8,
                    _MM_HINT_T0,
                );
            }
        }

        let mut acc_lo = _mm256_setzero_si256();
        let mut acc_hi = _mm256_setzero_si256();

        for j in 0..EARLY_TERM_DIM {
            let raw = _mm_loadu_si128(ds.dims[j].as_ptr().add(i) as *const __m128i);
            let v = _mm256_cvtepi16_epi32(raw);
            let diff = _mm256_sub_epi32(v, q_i32[j]);
            let sq = _mm256_mullo_epi32(diff, diff);
            let lo = _mm256_castsi256_si128(sq);
            let hi = _mm256_extracti128_si256(sq, 1);
            acc_lo = _mm256_add_epi64(acc_lo, _mm256_cvtepi32_epi64(lo));
            acc_hi = _mm256_add_epi64(acc_hi, _mm256_cvtepi32_epi64(hi));
        }

        _mm256_storeu_si256(dists.as_mut_ptr() as *mut __m256i, acc_lo);
        _mm256_storeu_si256((dists.as_mut_ptr() as *mut __m256i).add(1), acc_hi);
        let worst = top5[*worst_idx].dist;
        let mut any_below = false;
        for d in dists.iter() {
            if *d < worst {
                any_below = true;
                break;
            }
        }
        if !any_below {
            i += 8;
            continue;
        }

        for j in EARLY_TERM_DIM..DIM {
            let raw = _mm_loadu_si128(ds.dims[j].as_ptr().add(i) as *const __m128i);
            let v = _mm256_cvtepi16_epi32(raw);
            let diff = _mm256_sub_epi32(v, q_i32[j]);
            let sq = _mm256_mullo_epi32(diff, diff);
            let lo = _mm256_castsi256_si128(sq);
            let hi = _mm256_extracti128_si256(sq, 1);
            acc_lo = _mm256_add_epi64(acc_lo, _mm256_cvtepi32_epi64(lo));
            acc_hi = _mm256_add_epi64(acc_hi, _mm256_cvtepi32_epi64(hi));
        }

        _mm256_storeu_si256(dists.as_mut_ptr() as *mut __m256i, acc_lo);
        _mm256_storeu_si256((dists.as_mut_ptr() as *mut __m256i).add(1), acc_hi);
        for lane in 0..8 {
            let global = i + lane;
            try_insert_top5(
                top5,
                worst_idx,
                dists[lane],
                ds.labels[global],
                ds.orig_ids[global],
            );
        }

        i += 8;
    }

    if i < end {
        scan_cluster_scalar(i, end, q, ds, top5, worst_idx);
    }
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

        let mut dims_storage: Vec<Vec<i16>> = (0..DIM).map(|_| Vec::with_capacity(n)).collect();
        let mut labels = Vec::with_capacity(n);
        let mut orig_ids = Vec::with_capacity(n);
        let mut bbox_min = vec![i16::MAX; k * DIM];
        let mut bbox_max = vec![i16::MIN; k * DIM];

        for (c, (vecs, lbls, ids)) in clusters.iter().enumerate() {
            for (idx, v) in vecs.iter().enumerate() {
                for j in 0..DIM {
                    dims_storage[j].push(v[j]);
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
        for c in 0..k {
            for j in 0..DIM {
                centroids_soa[j * k_pad + c] = centroids[c * DIM + j];
            }
        }

        let dims: [&'static [i16]; DIM] = std::array::from_fn(|j| {
            let leaked: &'static [i16] = Vec::leak(std::mem::take(&mut dims_storage[j]));
            leaked
        });

        let ds = Dataset {
            n,
            k,
            k_pad,
            scale: FIX_SCALE,
            centroids: Vec::leak(centroids),
            centroids_soa: Vec::leak(centroids_soa),
            bbox_min: Vec::leak(bbox_min),
            bbox_max: Vec::leak(bbox_max),
            offsets: Vec::leak(offsets),
            dims,
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
