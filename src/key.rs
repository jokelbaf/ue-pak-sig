use rsa::rand_core::OsRng;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, pkcs1v15::Pkcs1v15Sign, traits::SignatureScheme};

use crate::{error::Error, ini::CryptoConfig};

/// RSA signing key pair loaded from a `CryptoConfig`.
///
/// Holds the public key always; the private key is present only when the
/// config includes `SigningPrivateExponent` (i.e. editor/developer configs).
pub struct SigningKey {
    public: RsaPublicKey,
    private: Option<RsaPrivateKey>,
}

impl SigningKey {
    /// Construct a `SigningKey` from a parsed `CryptoConfig`.
    ///
    /// Returns an error if the config is missing the modulus or public
    /// exponent, or if the RSA components are invalid.
    pub fn from_config(config: &CryptoConfig) -> Result<Self, Error> {
        let modulus = config
            .signing_modulus
            .as_deref()
            .ok_or_else(|| Error::InvalidIni("missing SigningModulus".into()))?;

        let pub_exp = config
            .signing_public_exponent
            .as_deref()
            .ok_or_else(|| Error::InvalidIni("missing SigningPublicExponent".into()))?;

        // UE stores RSA components as little-endian big integers.
        let n = BigUint::from_bytes_le(modulus);
        let e = BigUint::from_bytes_le(pub_exp);

        let public =
            RsaPublicKey::new(n.clone(), e.clone()).map_err(|e| Error::Rsa(e.to_string()))?;

        let private = config
            .signing_private_exponent
            .as_deref()
            .map(|priv_exp| {
                let d = BigUint::from_bytes_le(priv_exp);
                RsaPrivateKey::from_components(n, e, d, vec![])
                    .map_err(|e| Error::Rsa(e.to_string()))
            })
            .transpose()?;

        Ok(Self { public, private })
    }

    /// Returns `true` if a private key is available for signing.
    pub fn has_private_key(&self) -> bool {
        self.private.is_some()
    }

    /// Sign `data` using RSA private key with PKCS#1 v1.5 Type 1 padding
    /// (no DigestInfo prefix), matching UE's `FRSA::EncryptPrivate`.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let priv_key = self
            .private
            .as_ref()
            .ok_or_else(|| Error::Rsa("private key not available".into()))?;

        Pkcs1v15Sign::new_unprefixed()
            .sign(Some(&mut OsRng), priv_key, data)
            .map_err(|e| Error::Rsa(e.to_string()))
    }

    /// Verify a signature against `expected_plaintext` using the public key,
    /// matching UE's `FRSA::DecryptPublic`.
    pub fn verify(&self, expected_plaintext: &[u8], signature: &[u8]) -> Result<(), Error> {
        Pkcs1v15Sign::new_unprefixed()
            .verify(&self.public, expected_plaintext, signature)
            .map_err(|_| Error::SignatureMismatch)
    }
}
