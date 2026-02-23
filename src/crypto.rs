use sha1::{Digest, Sha1};

pub const CHUNK_SIZE: usize = 64 * 1024;

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub fn sha1_of_u32_slice(values: &[u32]) -> [u8; 20] {
    let mut h = Sha1::new();
    for &v in values {
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}
