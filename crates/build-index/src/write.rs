use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::DIM;

pub const MAGIC: &[u8; 4] = b"RIVF";
pub const VERSION: u32 = 2;
pub const FIX_SCALE: f32 = 10_000.0;
pub const BLOCK_SIZE: usize = 8;
pub const BLOCK_STRIDE: usize = DIM * BLOCK_SIZE;
const PAD_VALUE: i16 = i16::MAX;

#[inline(always)]
fn quantize(x: f32) -> i16 {

    let x = x.clamp(-1.0, 1.0);
    let s = x * FIX_SCALE;

    let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
    r as i16
}

pub struct Layout {
    pub n: usize,
    pub k: usize,
    pub centroids: Vec<f32>,
    pub bbox_min: Vec<i16>,
    pub bbox_max: Vec<i16>,
    pub offsets: Vec<u32>,
    pub block_offsets: Vec<u32>,
    pub blocks: Vec<i16>,
    pub labels: Vec<u8>,
    pub orig_ids: Vec<u32>,
}

pub fn build_layout(
    vectors: &[[f32; DIM]],
    labels_in: &[u8],
    centroids_in: &[[f32; DIM]],
    assignments: &[u16],
) -> Layout {
    let n = vectors.len();
    let k = centroids_in.len();
    assert_eq!(labels_in.len(), n);
    assert_eq!(assignments.len(), n);

    let mut counts = vec![0u32; k];
    for &a in assignments {
        counts[a as usize] += 1;
    }
    let mut offsets = vec![0u32; k + 1];
    for c in 0..k {
        offsets[c + 1] = offsets[c] + counts[c];
    }
    debug_assert_eq!(offsets[k] as usize, n);

    let mut block_offsets = vec![0u32; k + 1];
    for c in 0..k {
        let blocks_c = (counts[c] as usize + BLOCK_SIZE - 1) / BLOCK_SIZE;
        block_offsets[c + 1] = block_offsets[c] + blocks_c as u32;
    }
    let total_blocks = block_offsets[k] as usize;

    let mut blocks = vec![PAD_VALUE; total_blocks * BLOCK_STRIDE];
    let mut labels = vec![0u8; n];
    let mut orig_ids = vec![0u32; n];

    let mut bbox_min = vec![i16::MAX; k * DIM];
    let mut bbox_max = vec![i16::MIN; k * DIM];

    let mut write_pos = offsets[..k].to_vec();

    for (i, v) in vectors.iter().enumerate() {
        let c = assignments[i] as usize;
        let pos = write_pos[c] as usize;
        write_pos[c] += 1;
        labels[pos] = labels_in[i];
        orig_ids[pos] = i as u32;

        let pos_in_cluster = pos - offsets[c] as usize;
        let block_local = pos_in_cluster / BLOCK_SIZE;
        let lane = pos_in_cluster % BLOCK_SIZE;
        let block_global = block_offsets[c] as usize + block_local;
        let block_base = block_global * BLOCK_STRIDE;

        for j in 0..DIM {
            let q = quantize(v[j]);
            blocks[block_base + j * BLOCK_SIZE + lane] = q;
            let bi = c * DIM + j;
            if q < bbox_min[bi] {
                bbox_min[bi] = q;
            }
            if q > bbox_max[bi] {
                bbox_max[bi] = q;
            }
        }
    }

    for c in 0..k {
        if counts[c] == 0 {
            for j in 0..DIM {
                bbox_min[c * DIM + j] = 0;
                bbox_max[c * DIM + j] = 0;
            }
        }
    }

    let mut centroids = vec![0.0f32; k * DIM];
    for c in 0..k {
        for j in 0..DIM {
            centroids[c * DIM + j] = centroids_in[c][j];
        }
    }

    Layout {
        n,
        k,
        centroids,
        bbox_min,
        bbox_max,
        offsets,
        block_offsets,
        blocks,
        labels,
        orig_ids,
    }
}

pub fn write_index(path: &Path, l: &Layout) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::with_capacity(1 << 20, f);

    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    w.write_all(&(l.n as u32).to_le_bytes())?;
    w.write_all(&(l.k as u32).to_le_bytes())?;
    w.write_all(&(DIM as u32).to_le_bytes())?;
    w.write_all(&FIX_SCALE.to_le_bytes())?;
    w.write_all(&[0u8; 8])?;

    write_f32s(&mut w, &l.centroids)?;
    write_i16s(&mut w, &l.bbox_min)?;
    write_i16s(&mut w, &l.bbox_max)?;
    for o in &l.offsets {
        w.write_all(&o.to_le_bytes())?;
    }
    for o in &l.block_offsets {
        w.write_all(&o.to_le_bytes())?;
    }
    write_i16s(&mut w, &l.blocks)?;
    w.write_all(&l.labels)?;
    for id in &l.orig_ids {
        w.write_all(&id.to_le_bytes())?;
    }
    w.flush()?;
    Ok(())
}

fn write_f32s<W: Write>(w: &mut W, data: &[f32]) -> std::io::Result<()> {
    let bytes =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 4) };
    w.write_all(bytes)
}

fn write_i16s<W: Write>(w: &mut W, data: &[i16]) -> std::io::Result<()> {
    let bytes =
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2) };
    w.write_all(bytes)
}
