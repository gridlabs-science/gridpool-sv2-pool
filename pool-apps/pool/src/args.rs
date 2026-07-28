//! CLI argument parsing for the Pool binary.
//!
//! Defines the `Args` struct and a function to process CLI arguments into a PoolConfig.

use clap::Parser;
use ext_config::{Config, File, FileFormat};
use pool_sv2::config::PoolConfig;
use rand::rngs::OsRng;
use secp256k1::SecretKey;
use std::path::PathBuf;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

/// Holds the parsed CLI arguments for the Pool binary.
#[derive(Parser, Debug)]
#[command(author, version, about = "Pool CLI", long_about = None)]
pub struct Args {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the TOML configuration file",
        default_value = "pool-config.toml"
    )]
    pub config_path: PathBuf,
    #[arg(
        short = 'f',
        long = "log-file",
        help = "Path to the log file. If not set, logs will only be written to stdout."
    )]
    pub log_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Generate a fresh SV2 authority keypair and exit without loading a config"
    )]
    pub generate_authority_keypair: bool,
}

#[cfg_attr(not(test), hotpath::measure)]
/// Parses CLI arguments and loads the PoolConfig from the specified file.
pub fn process_cli_args() -> Option<PoolConfig> {
    let args = Args::parse();
    if args.generate_authority_keypair {
        let secret = Secp256k1SecretKey(SecretKey::new(&mut OsRng));
        let public = Secp256k1PublicKey::from(secret);
        println!("authority_public_key={public}");
        println!("authority_secret_key={secret}");
        return None;
    }

    let config_path = args.config_path.to_str().expect("Invalid config path");
    let mut config: PoolConfig = Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()
        .and_then(|settings| settings.try_deserialize::<PoolConfig>())
        .expect("Failed to load or deserialize config");

    config.set_log_dir(args.log_file);

    Some(config)
}
