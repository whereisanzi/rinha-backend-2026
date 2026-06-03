use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::DIM;

pub const MAGIC: &[u8; 8] = b"DFKDP001";
pub const VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 44;
pub const STORE_DIM: usize = 16;
pub const LANES: usize = 8;
pub const SCALE: i32 = 10_000;
pub const FIX_SCALE: f32 = 10_000.0;
pub const DEFAULT_LEAF_SIZE: usize = 128;
const PAD_VALUE: i16 = i16::MAX;

#[inline(always)]
fn quantize(x: f32) -> i16 {
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

#[derive(Clone, Copy)]
struct BuildNode {
    left: i32,
    right: i32,
    start: i32,
    len: i32,
    min: [i16; STORE_DIM],
    max: [i16; STORE_DIM],
}

struct PartitionRoot {
    key: u32,
    root: i32,
}

fn leaf_size() -> usize {
    std::env::var("KD_LEAF_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| (LANES..=1024).contains(&v))
        .unwrap_or(DEFAULT_LEAF_SIZE)
}

fn bounds(vectors: &[[i16; STORE_DIM]], indices: &[usize]) -> ([i16; STORE_DIM], [i16; STORE_DIM]) {
    let mut lo = [i16::MAX; STORE_DIM];
    let mut hi = [i16::MIN; STORE_DIM];
    for &i in indices {
        let v = &vectors[i];
        for d in 0..STORE_DIM {
            if v[d] < lo[d] {
                lo[d] = v[d];
            }
            if v[d] > hi[d] {
                hi[d] = v[d];
            }
        }
    }
    (lo, hi)
}

fn widest_dim(lo: &[i16; STORE_DIM], hi: &[i16; STORE_DIM]) -> usize {
    let mut best = 0usize;
    let mut best_w = i32::MIN;
    for d in 0..DIM {
        let w = hi[d] as i32 - lo[d] as i32;
        if w > best_w {
            best_w = w;
            best = d;
        }
    }
    best
}

fn build_tree(
    vectors: &[[i16; STORE_DIM]],
    labels: &[u8],
    indices: &[usize],
    leaf: usize,
    blocks: &mut Vec<([i16; STORE_DIM], u8)>,
    nodes: &mut Vec<BuildNode>,
) -> usize {
    let (lo, hi) = bounds(vectors, indices);
    let node_idx = nodes.len();
    nodes.push(BuildNode {
        left: -1,
        right: -1,
        start: 0,
        len: indices.len() as i32,
        min: lo,
        max: hi,
    });

    if indices.len() <= leaf {
        let start_slot = blocks.len() as i32;
        for &i in indices {
            blocks.push((vectors[i], labels[i]));
        }
        while blocks.len() % LANES != 0 {
            blocks.push(([PAD_VALUE; STORE_DIM], 0));
        }
        let node = &mut nodes[node_idx];
        node.start = start_slot;
        node.len = indices.len() as i32;
        return node_idx;
    }

    let split_dim = widest_dim(&lo, &hi);
    let mut sorted = indices.to_vec();
    sorted.sort_unstable_by_key(|&i| vectors[i][split_dim]);
    let mid = sorted.len() / 2;
    let (left_idx, right_idx) = sorted.split_at(mid);

    let left = build_tree(vectors, labels, left_idx, leaf, blocks, nodes);
    let right = build_tree(vectors, labels, right_idx, leaf, blocks, nodes);

    let left_start = nodes[left].start;
    let total_len = nodes[left].len + nodes[right].len;
    let node = &mut nodes[node_idx];
    node.left = left as i32;
    node.right = right as i32;
    node.start = left_start;
    node.len = total_len;
    node_idx
}

pub fn build_and_write(vectors_f32: &[[f32; DIM]], labels: &[u8], path: &Path) -> std::io::Result<()> {
    assert!(!vectors_f32.is_empty());
    assert_eq!(vectors_f32.len(), labels.len());

    let mut vectors: Vec<[i16; STORE_DIM]> = Vec::with_capacity(vectors_f32.len());
    for v in vectors_f32 {
        let mut q = [0i16; STORE_DIM];
        for d in 0..DIM {
            q[d] = quantize(v[d]);
        }
        vectors.push(q);
    }

    let leaf = leaf_size();
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); 256];
    for (i, v) in vectors.iter().enumerate() {
        buckets[partition_key(v) as usize].push(i);
    }

    let mut nodes: Vec<BuildNode> = Vec::new();
    let mut blocks: Vec<([i16; STORE_DIM], u8)> = Vec::with_capacity(vectors.len() + LANES);
    let mut roots: Vec<PartitionRoot> = Vec::new();

    for (key, indices) in buckets.iter().enumerate() {
        if indices.is_empty() {
            continue;
        }
        let root = build_tree(&vectors, labels, indices, leaf, &mut blocks, &mut nodes);
        roots.push(PartitionRoot {
            key: key as u32,
            root: root as i32,
        });
    }

    assert_eq!(blocks.len() % LANES, 0);
    let block_count = blocks.len() / LANES;
    let part_count = roots.len();
    let node_count = nodes.len();

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(DIM as u32).to_le_bytes());
    out.extend_from_slice(&(STORE_DIM as u32).to_le_bytes());
    out.extend_from_slice(&(SCALE as u32).to_le_bytes());
    out.extend_from_slice(&(vectors.len() as u32).to_le_bytes());
    out.extend_from_slice(&(part_count as u32).to_le_bytes());
    out.extend_from_slice(&(node_count as u32).to_le_bytes());
    out.extend_from_slice(&(block_count as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_SIZE);

    for r in &roots {
        out.extend_from_slice(&r.key.to_le_bytes());
    }
    for r in &roots {
        out.extend_from_slice(&r.root.to_le_bytes());
    }
    for r in &roots {
        write_qv(&mut out, &nodes[r.root as usize].min);
    }
    for r in &roots {
        write_qv(&mut out, &nodes[r.root as usize].max);
    }

    for n in &nodes {
        out.extend_from_slice(&n.left.to_le_bytes());
    }
    for n in &nodes {
        out.extend_from_slice(&n.right.to_le_bytes());
    }
    for n in &nodes {
        let start = if n.left < 0 {
            n.start / LANES as i32
        } else {
            n.start
        };
        out.extend_from_slice(&start.to_le_bytes());
    }
    for n in &nodes {
        out.extend_from_slice(&n.len.to_le_bytes());
    }
    for n in &nodes {
        write_qv(&mut out, &n.min);
    }
    for n in &nodes {
        write_qv(&mut out, &n.max);
    }

    for b in 0..block_count {
        let mut block = [0i16; DIM * LANES];
        for d in 0..DIM {
            for lane in 0..LANES {
                let off = (d / 2) * LANES * 2 + lane * 2 + (d & 1);
                block[off] = blocks[b * LANES + lane].0[d];
            }
        }
        for v in block {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    for b in 0..block_count {
        for lane in 0..LANES {
            out.push(blocks[b * LANES + lane].1);
        }
    }

    let mut f = BufWriter::with_capacity(8 << 20, File::create(path)?);
    f.write_all(&out)?;
    f.flush()?;
    Ok(())
}

fn write_qv(out: &mut Vec<u8>, v: &[i16; STORE_DIM]) {
    for i in 0..STORE_DIM {
        out.extend_from_slice(&v[i].to_le_bytes());
    }
}
