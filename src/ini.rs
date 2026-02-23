use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::Path;

use crate::error::Error;

/// Parsed contents of a UE4 `DefaultCrypto.ini` file.
#[derive(Debug, Clone, Default)]
pub struct CryptoConfig {
    /// AES-256 encryption key (32 bytes).
    pub encryption_key: Option<Vec<u8>>,
    /// RSA public exponent, little-endian.
    pub signing_public_exponent: Option<Vec<u8>>,
    /// RSA modulus, little-endian.
    pub signing_modulus: Option<Vec<u8>>,
    /// RSA private exponent, little-endian. Only present in editor/developer configs.
    pub signing_private_exponent: Option<Vec<u8>>,
}

impl CryptoConfig {
    /// Parse a `config.ini` file from the given path.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path)?;
        Self::from_ini_str(&content)
    }

    /// Parse a `config.ini` from a string slice.
    pub fn from_ini_str(content: &str) -> Result<Self, Error> {
        let mut config = Self::default();

        for line in content.lines() {
            let line = line.trim();
            let Some(eq) = line.find('=') else { continue };
            let key = line[..eq].trim();
            let value = line[eq + 1..].trim().trim_matches('"');

            match key {
                "EncryptionKey" => {
                    config.encryption_key = decode_b64_optional(value)?;
                }
                "SigningPublicExponent" => {
                    config.signing_public_exponent = decode_b64_optional(value)?;
                }
                "SigningModulus" => {
                    config.signing_modulus = decode_b64_optional(value)?;
                }
                "SigningPrivateExponent" => {
                    config.signing_private_exponent = decode_b64_optional(value)?;
                }
                _ => {}
            }
        }

        Ok(config)
    }
}

fn decode_b64_optional(value: &str) -> Result<Option<Vec<u8>>, Error> {
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(STANDARD.decode(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"EncryptionKey=AAEC
SigningPublicExponent=AQAB
SigningModulus=AQAB
SigningPrivateExponent="AQAB"
bEnablePakSigning=True
"#;

    #[test]
    fn parses_sample() {
        let cfg = CryptoConfig::from_ini_str(SAMPLE).unwrap();
        assert_eq!(
            cfg.signing_public_exponent.as_deref(),
            Some(&[0x01, 0x00, 0x01][..])
        );
        assert!(cfg.encryption_key.is_some());
    }

    #[test]
    fn quoted_private_exponent() {
        let cfg = CryptoConfig::from_ini_str(SAMPLE).unwrap();
        assert_eq!(
            cfg.signing_private_exponent.as_deref(),
            Some(&[0x01, 0x00, 0x01][..])
        );
    }
}
