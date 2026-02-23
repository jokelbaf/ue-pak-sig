use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use ue_pak_sig::{CryptoConfig, SigFile, SigningKey, UeVersion};

#[derive(Parser)]
#[command(
    name = "ue-pak-sig",
    about = "Generate and verify Unreal Engine 4.26/4.27 .sig files",
    version
)]
struct Cli {
    /// Path to config containing the RSA signing keys.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Target Unreal Engine version (affects the signing scheme).
    #[arg(short = 'u', long, value_name = "VERSION", default_value = "4-27")]
    ue_version: VersionArg,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, ValueEnum)]
enum VersionArg {
    #[value(name = "4-26")]
    V426,
    #[value(name = "4-27")]
    V427,
}

impl From<VersionArg> for UeVersion {
    fn from(v: VersionArg) -> Self {
        match v {
            VersionArg::V426 => UeVersion::V426,
            VersionArg::V427 => UeVersion::V427,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Sign a .pak file and write the corresponding .sig file.
    Sign {
        /// Input .pak file to sign.
        #[arg(value_name = "PAK")]
        pak: PathBuf,

        /// Output .sig file path. Defaults to <PAK> with the .sig extension.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Verify a .sig file against its .pak file.
    Verify {
        /// The .pak file to verify.
        #[arg(value_name = "PAK")]
        pak: PathBuf,

        /// The .sig file to check. Defaults to <PAK> with the .sig extension.
        #[arg(value_name = "SIG")]
        sig: Option<PathBuf>,
    },

    /// Print parsed information about a .sig file without verification.
    Info {
        /// The .sig file to inspect.
        #[arg(value_name = "SIG")]
        sig: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = run(&cli);
    if let Err(e) = result {
        eprintln!("{} {}", "error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> ue_pak_sig::Result<()> {
    let config = load_config(&cli.config)?;
    let key = SigningKey::from_config(&config)?;
    let version: UeVersion = cli.ue_version.clone().into();

    match &cli.command {
        Command::Sign { pak, output } => cmd_sign(pak, output.as_deref(), &key, version),
        Command::Verify { pak, sig } => cmd_verify(pak, sig.as_deref(), &key, version),
        Command::Info { sig } => cmd_info(sig),
    }
}

fn cmd_sign(
    pak_path: &Path,
    output: Option<&Path>,
    key: &SigningKey,
    version: UeVersion,
) -> ue_pak_sig::Result<()> {
    let sig_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| pak_path.with_extension("sig"));

    if !key.has_private_key() {
        return Err(ue_pak_sig::Error::Rsa(
            "private key not found in the provided config".into(),
        ));
    }

    println!(
        "{} {} (UE {})",
        "Signing".cyan().bold(),
        pak_path.display(),
        version_label(version),
    );

    let sig = SigFile::sign(pak_path, key, version)?;
    sig.write_to_file(&sig_path)?;

    println!(
        "{} {} chunks signed, output: {}",
        "Done.".green().bold(),
        sig.chunk_hashes.len(),
        sig_path.display().to_string().cyan(),
    );

    Ok(())
}

fn cmd_verify(
    pak_path: &Path,
    sig_arg: Option<&Path>,
    key: &SigningKey,
    version: UeVersion,
) -> ue_pak_sig::Result<()> {
    let sig_path = sig_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| pak_path.with_extension("sig"));

    println!(
        "{} {} against {} (UE {})",
        "Verifying".cyan().bold(),
        sig_path.display(),
        pak_path.display(),
        version_label(version),
    );

    let sig = SigFile::read_from_file(&sig_path)?;
    sig.verify(pak_path, key, version)?;

    println!("{}", "Signature is valid.".green().bold());

    Ok(())
}

fn cmd_info(sig_path: &Path) -> ue_pak_sig::Result<()> {
    let sig = SigFile::read_from_file(sig_path)?;

    println!("{}: {}", "File".bold(), sig_path.display());
    println!(
        "{}: {} bytes",
        "Encrypted hash size".bold(),
        sig.encrypted_hash.len()
    );
    println!(
        "{}: {} ({} MiB of pak data)",
        "Chunk count".bold(),
        sig.chunk_hashes.len(),
        sig.chunk_hashes.len() * 64 / 1024,
    );

    let master = sig.master_hash();
    let hex: String = master.iter().map(|b| format!("{b:02x}")).collect();
    println!("{}: {}", "Master hash (SHA1)".bold(), hex.yellow());

    Ok(())
}

fn load_config(path: &Path) -> ue_pak_sig::Result<CryptoConfig> {
    CryptoConfig::from_file(path).map_err(|e| {
        eprintln!(
            "{} loading key file {}: {}",
            "error:".red().bold(),
            path.display().to_string().cyan(),
            e
        );
        e
    })
}

fn version_label(v: UeVersion) -> &'static str {
    match v {
        UeVersion::V426 => "4.26",
        UeVersion::V427 => "4.27",
    }
}
