use std::io::{Read, Seek, SeekFrom};

use crate::error::Error;

const PAK_MAGIC: u32 = 0x5A6F12E1;

/// Minimal pak file footer, containing only the fields needed for sig
/// generation and verification.
#[derive(Debug, Clone)]
pub struct PakFooter {
    /// Pak format version.
    pub version: i32,
    /// Byte offset of the primary index within the pak file.
    pub index_offset: i64,
    /// Byte length of the primary index.
    pub index_size: i64,
    /// SHA1 hash of the raw primary index data, as stored in the footer.
    pub index_hash: [u8; 20],
    /// Whether the primary index is AES-encrypted.
    pub encrypted_index: bool,
}

impl PakFooter {
    /// Read and parse the pak footer from a seekable reader.
    ///
    /// Tries a set of known footer sizes to handle multiple pak format
    /// versions (UE 4.20–4.27).
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self, Error> {
        // Candidate footer sizes (bytes from end of file):
        //   v8+ (FNameBasedCompressionMethod): 16+1+4+4+8+8+20+160 = 221
        //   v9  (FrozenIndex, extra bool):      221+1              = 222
        //   v7  (EncryptionKeyGuid, no methods): 16+1+4+4+8+8+20  =  61
        //   v3-6 (no guid, no methods):          1+4+4+8+8+20     =  45
        const CANDIDATES: &[usize] = &[221, 222, 61, 45];

        let file_len = reader.seek(SeekFrom::End(0))?;

        for &footer_size in CANDIDATES {
            if file_len < footer_size as u64 {
                continue;
            }

            reader.seek(SeekFrom::End(-(footer_size as i64)))?;
            let mut buf = vec![0u8; footer_size];
            reader.read_exact(&mut buf)?;

            if let Some(footer) = try_parse_footer(&buf) {
                return Ok(footer);
            }
        }

        Err(Error::InvalidPak("pak footer magic not found".into()))
    }
}

fn try_parse_footer(buf: &[u8]) -> Option<PakFooter> {
    for i in 0..buf.len().saturating_sub(3) {
        let magic = u32::from_le_bytes(buf[i..i + 4].try_into().ok()?);
        if magic != PAK_MAGIC {
            continue;
        }

        let remaining = buf.len() - i;
        if remaining < 4 + 4 + 8 + 8 + 20 {
            continue;
        }

        let version = i32::from_le_bytes(buf[i + 4..i + 8].try_into().ok()?);
        let index_offset = i64::from_le_bytes(buf[i + 8..i + 16].try_into().ok()?);
        let index_size = i64::from_le_bytes(buf[i + 16..i + 24].try_into().ok()?);
        let mut index_hash = [0u8; 20];
        index_hash.copy_from_slice(&buf[i + 24..i + 44]);

        // bEncryptedIndex should be at buf[i - 1], one byte before magic
        let encrypted_index = i > 0 && buf[i - 1] != 0;

        return Some(PakFooter {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted_index,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_footer_buf(
        version: i32,
        index_offset: i64,
        index_size: i64,
        hash: [u8; 20],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // EncryptionKeyGuid (16 bytes)
        buf.extend_from_slice(&[0u8; 16]);
        // bEncryptedIndex (1 byte)
        buf.push(0);
        // Magic
        buf.extend_from_slice(&PAK_MAGIC.to_le_bytes());
        // Version
        buf.extend_from_slice(&version.to_le_bytes());
        // IndexOffset
        buf.extend_from_slice(&index_offset.to_le_bytes());
        // IndexSize
        buf.extend_from_slice(&index_size.to_le_bytes());
        // IndexHash
        buf.extend_from_slice(&hash);
        // CompressionMethods (160 bytes)
        buf.extend_from_slice(&[0u8; 160]);
        buf
    }

    #[test]
    fn round_trip_footer() {
        let hash = [0xABu8; 20];
        let buf = make_footer_buf(11, 12345, 6789, hash);
        let footer = PakFooter::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(footer.version, 11);
        assert_eq!(footer.index_offset, 12345);
        assert_eq!(footer.index_size, 6789);
        assert_eq!(footer.index_hash, hash);
    }
}
