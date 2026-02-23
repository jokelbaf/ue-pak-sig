# ue-pak-sig

A simple tool to create and verify Unreal Engine 4.26/4.27 `.sig` files in Rust.

## Usage

### CLI

```
ue-pak-sig --config config.ini [--ue-version 4-27] <COMMAND>

Commands:
  sign    Sign a .pak file and write the corresponding .sig file
  verify  Verify a .sig file against its .pak file
  info    Print parsed information about a .sig file
```

Sign a pak:

```sh
ue-pak-sig --config config.ini sign file.pak
# writes file.sig
```

Verify an existing pair:

```sh
ue-pak-sig --config config.ini verify pakchunk0.pak pakchunk0.sig
```

Inspect a sig file without verifying:

```sh
ue-pak-sig --config config.ini info pakchunk0.sig
```

The `--ue-version` flag defaults to `4-27`. Use `4-26` for games built with
UE 4.26 - the two versions use a different signing plaintext (see below).

### Library

```rust
use ue_pak_sig::{CryptoConfig, SigningKey, SigFile, UeVersion};
use std::path::Path;

let config = CryptoConfig::from_file(Path::new("config.ini"))?;
let key = SigningKey::from_config(&config)?;

// Sign
let sig = SigFile::sign(Path::new("file.pak"), &key, UeVersion::V427)?;
sig.write_to_file(Path::new("file.sig"))?;

// Verify
let sig = SigFile::read_from_file(Path::new("file.sig"))?;
sig.verify(Path::new("file.pak"), &key, UeVersion::V427)?;
```

## Config

The tool was made to support the standard UE `DefaultCrypto.ini` syntax (the same file shipped in
every UE project's `Build/` directory). In this project, it is referred to as `config.ini` to avoid confusion with the original UE file. The expected format is:

```ini
SigningPublicExponent=AQAB
SigningModulus=<base64>
SigningPrivateExponent="<base64>"
```

Signing requires `SigningPrivateExponent`. Verification requires only the
public components. All key values are base64-encoded little-endian big
integers, as produced by the UE editor.

## Signing schemes

| Version | Plaintext signed |
|---------|-----------------|
| 4.26 | `SHA1(chunk_crcs)` - 20 bytes |
| 4.27 | `pak_IndexHash \|\| SHA1(chunk_crcs)` - 40 bytes |

`SHA1(chunk_crcs)` is the SHA1 digest of all CRC32 chunk hashes concatenated
as little-endian `u32` values. `pak_IndexHash` is the SHA1 of the pak's
primary index, read directly from the pak footer. Both versions use RSA
PKCS#1 v1.5 Type 1 padding with no DigestInfo prefix, matching OpenSSL's
`RSA_private_encrypt`/`RSA_public_decrypt` with `RSA_PKCS1_PADDING`.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.
