use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::slice;

use crate::DIM;

pub const MAGIC: &[u8; 8] = b"DFKDP001";
pub const VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 44;
pub const STORE_DIM: usize = 16;
pub const LANES: usize = 8;
pub const BLOCK_I16: usize = DIM * LANES;
pub const BLOCK_BYTES: usize = BLOCK_I16 * 2;
pub const PART_SIZE: usize = 8 + STORE_DIM * 4;
pub const NODE_SIZE: usize = 16 + STORE_DIM * 4;
pub const SCALE: i32 = 10_000;

#[cfg(target_os = "linux")]
const MAP_POPULATE: libc::c_int = 0x8000;
#[cfg(not(target_os = "linux"))]
const MAP_POPULATE: libc::c_int = 0;

#[cfg(target_os = "linux")]
const MADV_HUGEPAGE: libc::c_int = 14;
#[cfg(target_os = "linux")]
const MADV_WILLNEED: libc::c_int = 3;

pub struct Dataset {
    pub n: usize,
    pub k: usize,
    pub part_keys: &'static [u32],
    pub part_roots: &'static [i32],
    pub part_min: &'static [i16],
    pub part_max: &'static [i16],
    pub node_left: &'static [i32],
    pub node_right: &'static [i32],
    pub node_start: &'static [i32],
    pub node_len: &'static [i32],
    pub node_min: &'static [i16],
    pub node_max: &'static [i16],
    pub blocks: &'static [i16],
    pub labels: &'static [u8],
    pub part_by_key: [i32; 256],
}

pub fn load(path: &Path) -> std::io::Result<&'static Dataset> {
    let file = OpenOptions::new().read(true).open(path)?;
    let len = file.metadata()?.len() as usize;
    if len < HEADER_SIZE {
        return Err(io_err("index file smaller than header"));
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

    #[cfg(target_os = "linux")]
    unsafe {
        libc::madvise(ptr, len, MADV_WILLNEED);
        libc::madvise(ptr, len, MADV_HUGEPAGE);
        let _ = libc::mlock(ptr, len);
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        libc::madvise(ptr, len, libc::MADV_RANDOM);
    }

    let bytes: &'static [u8] = unsafe { slice::from_raw_parts(ptr as *const u8, len) };

    if &bytes[0..8] != MAGIC {
        return Err(io_err("bad magic"));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(io_err("bad version"));
    }
    let dim = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let store_dim = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let scale = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as i32;
    if dim != DIM || store_dim != STORE_DIM || scale != SCALE {
        return Err(io_err("dim/scale mismatch"));
    }
    let n = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
    let part_count = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    let node_count = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    let block_count = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;

    let mut off = HEADER_SIZE;

    let part_keys = unsafe { slice_typed::<u32>(bytes, off, part_count) };
    off += part_count * 4;
    let part_roots = unsafe { slice_typed::<i32>(bytes, off, part_count) };
    off += part_count * 4;
    let part_min = unsafe { slice_typed::<i16>(bytes, off, part_count * STORE_DIM) };
    off += part_count * STORE_DIM * 2;
    let part_max = unsafe { slice_typed::<i16>(bytes, off, part_count * STORE_DIM) };
    off += part_count * STORE_DIM * 2;

    let node_left = unsafe { slice_typed::<i32>(bytes, off, node_count) };
    off += node_count * 4;
    let node_right = unsafe { slice_typed::<i32>(bytes, off, node_count) };
    off += node_count * 4;
    let node_start = unsafe { slice_typed::<i32>(bytes, off, node_count) };
    off += node_count * 4;
    let node_len = unsafe { slice_typed::<i32>(bytes, off, node_count) };
    off += node_count * 4;
    let node_min = unsafe { slice_typed::<i16>(bytes, off, node_count * STORE_DIM) };
    off += node_count * STORE_DIM * 2;
    let node_max = unsafe { slice_typed::<i16>(bytes, off, node_count * STORE_DIM) };
    off += node_count * STORE_DIM * 2;

    let blocks = unsafe { slice_typed::<i16>(bytes, off, block_count * BLOCK_I16) };
    off += block_count * BLOCK_BYTES;
    let labels = &bytes[off..off + block_count * LANES];
    off += block_count * LANES;

    if off != bytes.len() {
        return Err(io_err("index file has unexpected trailing data"));
    }

    let mut part_by_key = [-1i32; 256];
    for (i, &key) in part_keys.iter().enumerate() {
        if (key as usize) < 256 {
            part_by_key[key as usize] = i as i32;
        }
    }

    let ds = Box::leak(Box::new(Dataset {
        n,
        k: part_count,
        part_keys,
        part_roots,
        part_min,
        part_max,
        node_left,
        node_right,
        node_start,
        node_len,
        node_min,
        node_max,
        blocks,
        labels,
        part_by_key,
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
