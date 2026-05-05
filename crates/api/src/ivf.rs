use crate::DIM;
use crate::dataset::Dataset;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const NPROBE_DEFAULT: usize = 8;
pub const FIX_SCALE: f32 = 10_000.0;
const MAX_K: usize = 4096;
const BITSET_WORDS: usize = (MAX_K + 63) / 64;

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

pub fn search_fraud_count(query: &[f32; DIM], ds: &Dataset, nprobe: usize) -> u8 {
    let mut q_i16 = [0i16; DIM];
    for j in 0..DIM {
        q_i16[j] = quantize_i16(query[j]);
    }

    let nprobe = nprobe.clamp(1, ds.k);
    let mut probes = [0usize; 64];
    let mut probe_d = [f32::INFINITY; 64];
    let n = nprobe.min(probes.len());
    for c in 0..ds.k {
        let d = centroid_dist_sq(query, ds, c);
        if d < probe_d[n - 1] {

            let mut pos = n - 1;
            while pos > 0 && d < probe_d[pos - 1] {
                pos -= 1;
            }

            let mut i = n - 1;
            while i > pos {
                probe_d[i] = probe_d[i - 1];
                probes[i] = probes[i - 1];
                i -= 1;
            }
            probe_d[pos] = d;
            probes[pos] = c;
        }
    }

    let mut top5 = [SENTINEL; 5];
    let mut worst_idx = 0usize;

    let mut scanned = [0u64; BITSET_WORDS];

    for &c in probes[..n].iter() {
        if !bitset_get(&scanned, c) {
            bitset_set(&mut scanned, c);
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    for c in 0..ds.k {
        if bitset_get(&scanned, c) {
            continue;
        }
        let lb = bbox_lower_bound(&q_i16, ds, c);
        if lb <= top5[worst_idx].dist {
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    let fraud_count = top5.iter().map(|e| e.label as u8).sum::<u8>();
    fraud_count.min(5)
}

#[inline(always)]
pub fn quantize_i16(x: f32) -> i16 {
    let x = x.clamp(-1.0, 1.0);
    let s = x * FIX_SCALE;
    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

#[inline]
fn centroid_dist_sq(query: &[f32; DIM], ds: &Dataset, c: usize) -> f32 {
    let base = c * DIM;
    let mut s = 0.0f32;
    for j in 0..DIM {
        let d = query[j] - ds.centroids[base + j];
        s += d * d;
    }
    s
}

#[inline]
fn bbox_lower_bound(q: &[i16; DIM], ds: &Dataset, c: usize) -> i64 {
    let base = c * DIM;
    let mn = &ds.bbox_min[base..base + DIM];
    let mx = &ds.bbox_max[base..base + DIM];
    let mut s: i64 = 0;
    for j in 0..DIM {
        let qv = q[j] as i32;
        let lo = mn[j] as i32;
        let hi = mx[j] as i32;
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
        let mut acc_lo = _mm256_setzero_si256();
        let mut acc_hi = _mm256_setzero_si256();

        for j in 0..DIM {

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

#[derive(Default, Clone, Copy, Debug)]
pub struct SearchTrace {
    pub phase3_lb_checks: u32,
    pub phase3_scans_extra: u32,
    pub phase1_2_ns: u64,
    pub phase3_ns: u64,
    pub total_ns: u64,
}

pub fn search_fraud_count_traced(
    query: &[f32; DIM],
    ds: &Dataset,
    nprobe: usize,
) -> (u8, SearchTrace) {
    let t_total = std::time::Instant::now();
    let t_p12 = std::time::Instant::now();

    let mut q_i16 = [0i16; DIM];
    for j in 0..DIM {
        q_i16[j] = quantize_i16(query[j]);
    }

    let nprobe = nprobe.clamp(1, ds.k);
    let mut probes = [0usize; 64];
    let mut probe_d = [f32::INFINITY; 64];
    let n = nprobe.min(probes.len());
    for c in 0..ds.k {
        let d = centroid_dist_sq(query, ds, c);
        if d < probe_d[n - 1] {
            let mut pos = n - 1;
            while pos > 0 && d < probe_d[pos - 1] {
                pos -= 1;
            }
            let mut i = n - 1;
            while i > pos {
                probe_d[i] = probe_d[i - 1];
                probes[i] = probes[i - 1];
                i -= 1;
            }
            probe_d[pos] = d;
            probes[pos] = c;
        }
    }

    let mut top5 = [SENTINEL; 5];
    let mut worst_idx = 0usize;
    let mut scanned = [0u64; BITSET_WORDS];

    for &c in probes[..n].iter() {
        if !bitset_get(&scanned, c) {
            bitset_set(&mut scanned, c);
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    let phase1_2_ns = t_p12.elapsed().as_nanos() as u64;
    let t_p3 = std::time::Instant::now();

    let mut lb_checks: u32 = 0;
    let mut scans_extra: u32 = 0;
    for c in 0..ds.k {
        if bitset_get(&scanned, c) {
            continue;
        }
        lb_checks += 1;
        let lb = bbox_lower_bound(&q_i16, ds, c);
        if lb <= top5[worst_idx].dist {
            scans_extra += 1;
            scan_cluster(c, &q_i16, ds, &mut top5, &mut worst_idx);
        }
    }

    let phase3_ns = t_p3.elapsed().as_nanos() as u64;
    let total_ns = t_total.elapsed().as_nanos() as u64;

    let fraud_count = top5.iter().map(|e| e.label as u8).sum::<u8>();
    (
        fraud_count.min(5),
        SearchTrace {
            phase3_lb_checks: lb_checks,
            phase3_scans_extra: scans_extra,
            phase1_2_ns,
            phase3_ns,
            total_ns,
        },
    )
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

        let dims: [&'static [i16]; DIM] = std::array::from_fn(|j| {
            let leaked: &'static [i16] = Vec::leak(std::mem::take(&mut dims_storage[j]));
            leaked
        });

        let ds = Dataset {
            n,
            k,
            scale: FIX_SCALE,
            centroids: Vec::leak(centroids),
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
    fn bbox_lb_zero_inside() {

        let mut vecs = Vec::new();
        let mut v = [0i16; DIM];
        for j in 0..DIM {
            v[j] = -100;
        }
        vecs.push(v);
        for j in 0..DIM {
            v[j] = 100;
        }
        vecs.push(v);
        let labels = vec![0u8, 0u8];
        let ids = vec![0u32, 1u32];
        let ds = make_synthetic_dataset(
            &[(vecs, labels, ids)],
            &[[0.0; DIM]],
        );

        let q = [0i16; DIM];
        assert_eq!(bbox_lower_bound(&q, ds, 0), 0);

        let mut q2 = [0i16; DIM];
        q2[0] = 200;
        assert_eq!(bbox_lower_bound(&q2, ds, 0), 100 * 100);
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
    fn exact_recall_finds_better_in_skipped_cluster() {

        let mut c0 = Vec::new();
        for i in 0..5 {
            let mut v = [0i16; DIM];
            v[0] = 5000 + i;
            c0.push(v);
        }
        let mut c1 = Vec::new();
        for i in 0..5 {
            let mut v = [0i16; DIM];
            v[0] = i;
            c1.push(v);
        }
        let ds = make_synthetic_dataset(
            &[
                (c0, vec![0u8; 5], (0..5u32).collect()),
                (c1, vec![1u8; 5], (5..10u32).collect()),
            ],

            &[
                {
                    let mut c = [0.0f32; DIM];
                    c[0] = 0.0;
                    c
                },
                {
                    let mut c = [0.0f32; DIM];
                    c[0] = 10.0;
                    c
                },
            ],
        );

        let q = [0.0f32; DIM];

        assert_eq!(search_fraud_count(&q, ds, 1), 5);
    }
}
