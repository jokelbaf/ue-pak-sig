//! # ue-pak-sig
//!
//! Generate and verify Unreal Engine 4.26/4.27 `.sig` files.
//!
//! ## Quick start
//!
//! ```no_run
//! use ue_pak_sig::{CryptoConfig, SigningKey, SigFile, UeVersion};
//! use std::path::Path;
//!
//! let config = CryptoConfig::from_file(Path::new("config.ini")).unwrap();
//! let key = SigningKey::from_config(&config).unwrap();
//!
//! // Sign a pak file.
//! let sig = SigFile::sign(Path::new("MyMod.pak"), &key, UeVersion::V427).unwrap();
//! sig.write_to_file(Path::new("MyMod.sig")).unwrap();
//!
//! // Verify a sig file.
//! let sig = SigFile::read_from_file(Path::new("MyMod.sig")).unwrap();
//! sig.verify(Path::new("MyMod.pak"), &key, UeVersion::V427).unwrap();
//! ```

pub mod crypto;
pub mod error;
pub mod ini;
pub mod key;
pub mod pak;
pub mod sig;

pub use error::Error;
pub use ini::CryptoConfig;
pub use key::SigningKey;
pub use sig::{SigFile, UeVersion};

/// Convenience type alias for results returned by this library.
pub type Result<T> = std::result::Result<T, Error>;
