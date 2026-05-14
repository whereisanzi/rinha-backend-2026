use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::slice;

use crate::DIM;

pub const MAGIC: &[u8; 4] = b"RIVF";
pub const VERSION: u32 = 2;
pub const HEADER_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 8;
pub const BLOCK_STRIDE: usize = DIM * BLOCK_SIZE;

const MAP_POPULATE: libc::c_int = 0;

pub struct Dataset {
    pub n: usize,
    pub k: usize,
    pub k_pad: usize,
    #[allow(dead_code)]
    pub scale: f32,
    #[allow(dead_code)]
    pub centroids: &'static [f32],
    #[allow(dead_code)]
    pub centroids_soa: &'static [f32],
    pub centroids_soa_i16: &'static [i16],
    pub bbox_min: &'static [i16],
    pub bbox_max: &'static [i16],
    pub offsets: &'static [u32],
    pub block_offsets: &'static [u32],
    pub blocks: &'static [i16],
    pub labels: &'static [u8],
    pub orig_ids: &'static [u32],
}

pub fn load(path: &Path) -> std::io::Result<&'static Dataset> {
    let file = OpenOptions::new().read(true).open(path)?;
    let len = file.metadata()?.len() as usize;
    if len == 0 {
        return Err(io_err("empty index file"));
    }

    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE | MAP_POPULATE,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    unsafe {
        libc::madvise(ptr, len, libc::MADV_RANDOM);
    }

    let bytes: &'static [u8] = unsafe { slice::from_raw_parts(ptr as *const u8, len) };

    if bytes.len() < HEADER_SIZE {
        return Err(io_err("index file smaller than header"));
    }
    if &bytes[0..4] != MAGIC {
        return Err(io_err("bad magic"));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(io_err("bad version"));
    }
    let n = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let k = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let d = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let scale = f32::from_le_bytes(bytes[20..24].try_into().unwrap());
    if d != DIM {
        return Err(io_err("dim mismatch"));
    }

    let mut off = HEADER_SIZE;

    let centroids_bytes = k * DIM * 4;
    let centroids = unsafe { slice_typed::<f32>(bytes, off, k * DIM) };
    off += centroids_bytes;

    let bbox_bytes = k * DIM * 2;
    let bbox_min = unsafe { slice_typed::<i16>(bytes, off, k * DIM) };
    off += bbox_bytes;
    let bbox_max = unsafe { slice_typed::<i16>(bytes, off, k * DIM) };
    off += bbox_bytes;

    let offsets_bytes = (k + 1) * 4;
    let offsets = unsafe { slice_typed::<u32>(bytes, off, k + 1) };
    off += offsets_bytes;

    let block_offsets = unsafe { slice_typed::<u32>(bytes, off, k + 1) };
    off += offsets_bytes;
    let total_blocks = block_offsets[k] as usize;

    let blocks_count = total_blocks * BLOCK_STRIDE;
    let blocks = unsafe { slice_typed::<i16>(bytes, off, blocks_count) };
    off += blocks_count * 2;

    let labels = &bytes[off..off + n];
    off += n;

    let orig_ids = unsafe { slice_typed::<u32>(bytes, off, n) };
    off += n * 4;

    if off != bytes.len() {
        return Err(io_err("index file has unexpected trailing data"));
    }
    if offsets[k] as usize != n {
        return Err(io_err("offsets[k] != n"));
    }

    let k_pad = (k + 7) & !7;
    let mut centroids_soa_vec = vec![0.0f32; DIM * k_pad];
    for c in 0..k {
        for j in 0..DIM {
            centroids_soa_vec[j * k_pad + c] = centroids[c * DIM + j];
        }
    }
    for c in k..k_pad {
        for j in 0..DIM {
            centroids_soa_vec[j * k_pad + c] = f32::INFINITY;
        }
    }
    let centroids_soa: &'static [f32] = Vec::leak(centroids_soa_vec);

    let mut centroids_soa_i16_vec = vec![i16::MAX; DIM * k_pad];
    for c in 0..k {
        for j in 0..DIM {
            let v = centroids[c * DIM + j];
            let clamped = v.clamp(-1.0, 1.0);
            let s = clamped * scale;
            let r = if s >= 0.0 { s + 0.5 } else { s - 0.5 };
            centroids_soa_i16_vec[j * k_pad + c] = r as i16;
        }
    }
    let centroids_soa_i16: &'static [i16] = Vec::leak(centroids_soa_i16_vec);

    let ds = Box::leak(Box::new(Dataset {
        n,
        k,
        k_pad,
        scale,
        centroids,
        centroids_soa,
        centroids_soa_i16,
        bbox_min,
        bbox_max,
        offsets,
        block_offsets,
        blocks,
        labels,
        orig_ids,
    }));
    Ok(ds)
}

#[inline]
unsafe fn slice_typed<T>(bytes: &'static [u8], byte_offset: usize, count: usize) -> &'static [T] {
    let p = bytes.as_ptr().add(byte_offset) as *const T;
    debug_assert_eq!(p as usize % std::mem::align_of::<T>(), 0, "misaligned slice");
    slice::from_raw_parts(p, count)
}

fn io_err(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}
