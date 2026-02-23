use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

use crate::{
    crypto::{self, CHUNK_SIZE},
    error::Error,
    key::SigningKey,
    pak::PakFooter,
};

pub(crate) const SIG_MAGIC: u32 = 0x73832DAA;
pub(crate) const SIG_VERSION: i32 = 1;

/// Unreal Engine version variant that determines the signing scheme.
///
/// The on-disk `.sig` format is identical for both versions; they differ
/// only in what data is RSA-signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UeVersion {
    /// UE 4.26 — signs `SHA1(chunk_crcs)` (20 bytes).
    V426,
    /// UE 4.27 — signs `IndexHash || SHA1(chunk_crcs)` (40 bytes),
    /// where `IndexHash` is the SHA1 of the pak's primary index as stored
    /// in the pak footer.
    V427,
}

/// A parsed UE4 `.sig` file.
#[derive(Debug, Clone)]
pub struct SigFile {
    /// RSA-encrypted block produced by `FRSA::EncryptPrivate`.
    pub encrypted_hash: Vec<u8>,
    /// CRC32 hashes of each contiguous 64 KiB chunk of the corresponding
    /// `.pak` file, in order.
    pub chunk_hashes: Vec<u32>,
}

impl SigFile {
    /// Deserialize a `.sig` file from `reader`.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let magic = read_u32(reader)?;
        if magic != SIG_MAGIC {
            return Err(Error::InvalidMagic(magic));
        }

        let version = read_i32(reader)?;
        if version != SIG_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let enc_len = read_i32(reader)? as usize;
        let mut encrypted_hash = vec![0u8; enc_len];
        reader.read_exact(&mut encrypted_hash)?;

        let chunk_count = read_i32(reader)? as usize;
        let mut chunk_hashes = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunk_hashes.push(read_u32(reader)?);
        }

        Ok(Self {
            encrypted_hash,
            chunk_hashes,
        })
    }

    /// Deserialize a `.sig` file from `path`.
    pub fn read_from_file(path: &Path) -> Result<Self, Error> {
        let mut f = File::open(path)?;
        Self::read(&mut f)
    }

    /// Serialize this `.sig` file to `writer`.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&SIG_MAGIC.to_le_bytes())?;
        writer.write_all(&SIG_VERSION.to_le_bytes())?;

        writer.write_all(&(self.encrypted_hash.len() as i32).to_le_bytes())?;
        writer.write_all(&self.encrypted_hash)?;

        writer.write_all(&(self.chunk_hashes.len() as i32).to_le_bytes())?;
        for &h in &self.chunk_hashes {
            writer.write_all(&h.to_le_bytes())?;
        }

        Ok(())
    }

    /// Serialize this `.sig` file to `path`.
    pub fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        let mut f = File::create(path)?;
        self.write(&mut f)
    }

    /// Compute `SHA1(chunk_hashes)` — the "master hash" that is embedded
    /// inside the RSA-encrypted block.
    pub fn master_hash(&self) -> [u8; 20] {
        crypto::sha1_of_u32_slice(&self.chunk_hashes)
    }

    /// Sign a `.pak` file and produce a `SigFile`.
    ///
    /// Reads the pak file in streaming 64 KiB chunks to avoid loading the
    /// entire file into memory.  For `UeVersion::V427`, also reads the pak
    /// footer to extract the primary index hash.
    pub fn sign(pak_path: &Path, key: &SigningKey, version: UeVersion) -> Result<Self, Error> {
        let f = File::open(pak_path)?;
        let mut reader = BufReader::new(f);
        Self::sign_from_reader(&mut reader, key, version)
    }

    /// Sign from an arbitrary `Read + Seek` source.
    pub fn sign_from_reader<R: Read + Seek>(
        reader: &mut R,
        key: &SigningKey,
        version: UeVersion,
    ) -> Result<Self, Error> {
        let chunk_hashes = compute_chunk_hashes(reader)?;
        let master = crypto::sha1_of_u32_slice(&chunk_hashes);

        let plaintext = build_sign_plaintext(reader, version, &master)?;
        let encrypted_hash = key.sign(&plaintext)?;

        Ok(Self {
            encrypted_hash,
            chunk_hashes,
        })
    }

    /// Verify this `.sig` file against a `.pak` file.
    ///
    /// Checks that:
    /// 1. The chunk CRC32s match those computed from the pak file.
    /// 2. The RSA signature decrypts to the expected plaintext.
    pub fn verify(
        &self,
        pak_path: &Path,
        key: &SigningKey,
        version: UeVersion,
    ) -> Result<(), Error> {
        let f = File::open(pak_path)?;
        let mut reader = BufReader::new(f);
        self.verify_from_reader(&mut reader, key, version)
    }

    /// Verify against an arbitrary `Read + Seek` source.
    pub fn verify_from_reader<R: Read + Seek>(
        &self,
        reader: &mut R,
        key: &SigningKey,
        version: UeVersion,
    ) -> Result<(), Error> {
        let computed = compute_chunk_hashes(reader)?;
        if computed != self.chunk_hashes {
            return Err(Error::SignatureMismatch);
        }

        let master = crypto::sha1_of_u32_slice(&self.chunk_hashes);
        let plaintext = build_sign_plaintext(reader, version, &master)?;
        key.verify(&plaintext, &self.encrypted_hash)
    }
}

fn compute_chunk_hashes<R: Read + Seek>(reader: &mut R) -> Result<Vec<u32>, Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hashes = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = read_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hashes.push(crypto::crc32(&buf[..n]));
    }

    Ok(hashes)
}

fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

fn build_sign_plaintext<R: Read + Seek>(
    reader: &mut R,
    version: UeVersion,
    master_hash: &[u8; 20],
) -> Result<Vec<u8>, Error> {
    match version {
        UeVersion::V426 => Ok(master_hash.to_vec()),
        UeVersion::V427 => {
            let footer = PakFooter::read(reader)?;
            let mut plaintext = Vec::with_capacity(40);
            plaintext.extend_from_slice(&footer.index_hash);
            plaintext.extend_from_slice(master_hash);
            Ok(plaintext)
        }
    }
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, Error> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_i32<R: Read>(r: &mut R) -> Result<i32, Error> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialization() {
        let sig = SigFile {
            encrypted_hash: vec![0xAAu8; 256],
            chunk_hashes: vec![0x11223344, 0xDEADBEEF],
        };

        let mut buf = Vec::new();
        sig.write(&mut buf).unwrap();

        let parsed = SigFile::read(&mut buf.as_slice()).unwrap();
        assert_eq!(parsed.encrypted_hash, sig.encrypted_hash);
        assert_eq!(parsed.chunk_hashes, sig.chunk_hashes);
    }

    #[test]
    fn wrong_magic_returns_error() {
        let mut buf = 0u32.to_le_bytes().to_vec();
        buf.extend_from_slice(&1i32.to_le_bytes());
        let result = SigFile::read(&mut buf.as_slice());
        assert!(matches!(result, Err(Error::InvalidMagic(_))));
    }

    #[test]
    fn master_hash_is_sha1_of_le_u32s() {
        let sig = SigFile {
            encrypted_hash: vec![],
            chunk_hashes: vec![1u32, 2u32],
        };
        let expected = crypto::sha1_of_u32_slice(&[1, 2]);
        assert_eq!(sig.master_hash(), expected);
    }
}
