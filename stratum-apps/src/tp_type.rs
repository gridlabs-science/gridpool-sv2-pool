use crate::key_utils::Secp256k1PublicKey;
use std::path::PathBuf;

#[cfg(feature = "bitcoin-core-sv2")]
use crate::config_helpers::opt_path_from_toml;

#[cfg(feature = "bitcoin-core-sv2")]
use bitcoin_core_sv2::common::BitcoinCoreVersion;

/// Bitcoin network for determining node.sock location
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

#[cfg(feature = "bitcoin-core-sv2")]
fn deserialize_bitcoin_core_version<'de, D>(deserializer: D) -> Result<BitcoinCoreVersion, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let major = <u8 as serde::Deserialize>::deserialize(deserializer)?;
    BitcoinCoreVersion::try_from(major).map_err(|unsupported| {
        serde::de::Error::custom(format!(
            "unsupported Bitcoin Core IPC version: {unsupported}. expected 30 or 31"
        ))
    })
}

impl BitcoinNetwork {
    /// Returns the subdirectory name for this network.
    /// Mainnet uses the root data directory.
    fn subdir(&self) -> Option<&'static str> {
        match self {
            BitcoinNetwork::Mainnet => None,
            BitcoinNetwork::Testnet4 => Some("testnet4"),
            BitcoinNetwork::Signet => Some("signet"),
            BitcoinNetwork::Regtest => Some("regtest"),
        }
    }
}

/// Returns the default Bitcoin Core data directory for the current OS.
fn default_bitcoin_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir().map(|h| h.join(".bitcoin"))
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/Bitcoin"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Resolves the IPC socket path from network and optional data_dir.
/// Constructs path from network + optional data_dir (or OS default).
///
/// Returns `None` if data_dir cannot be determined (neither provided nor OS default available).
pub fn resolve_ipc_socket_path(
    network: &BitcoinNetwork,
    data_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    let base_dir = data_dir.or_else(default_bitcoin_data_dir)?;

    Some(match network.subdir() {
        Some(subdir) => base_dir.join(subdir).join("node.sock"),
        None => base_dir.join("node.sock"),
    })
}

/// Which type of Template Provider will be used,
/// along with the relevant config parameters for each.
#[derive(Clone, Debug, serde::Deserialize)]
pub enum TemplateProviderType {
    Sv2Tp {
        address: String,
        public_key: Option<Secp256k1PublicKey>,
    },
    #[cfg(feature = "bitcoin-core-sv2")]
    BitcoinCoreIpc {
        /// Bitcoin Core IPC schema major version.
        #[serde(deserialize_with = "deserialize_bitcoin_core_version")]
        version: BitcoinCoreVersion,
        /// Network for determining socket path subdirectory.
        network: BitcoinNetwork,
        /// Custom Bitcoin data directory. Uses OS default if not set.
        #[serde(default, deserialize_with = "opt_path_from_toml")]
        data_dir: Option<PathBuf>,
        fee_threshold: u64,
        min_interval: u8,
    },
    /// Builds Template Distribution messages from the standard Bitcoin JSON-RPC mining API.
    ///
    /// This backend intentionally targets the common `getblocktemplate` / `submitblock`
    /// contract rather than a specific node implementation. It is the compatibility path for
    /// Bitcoin Knots, older Bitcoin Core releases, and appliance boundaries that cannot expose
    /// a UNIX IPC socket.
    BitcoinJsonRpc {
        url: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default, deserialize_with = "opt_path_from_toml")]
        cookie_file: Option<PathBuf>,
        #[serde(default = "default_rpc_timeout_seconds")]
        timeout_seconds: u64,
        #[serde(default = "default_rpc_retry_seconds")]
        retry_seconds: u64,
        #[serde(default = "default_rpc_min_interval_seconds")]
        min_interval: u8,
    },
    /// Prefers Bitcoin Core IPC when its socket is reachable, otherwise uses JSON-RPC.
    ///
    /// `version` is optional so the same configuration can be used with Bitcoin Knots. When it
    /// is absent, or when the resolved IPC socket cannot be opened, the RPC fields are used.
    BitcoinAuto {
        #[serde(
            default,
            deserialize_with = "deserialize_optional_bitcoin_core_version"
        )]
        version: Option<BitcoinCoreVersion>,
        network: BitcoinNetwork,
        #[serde(default, deserialize_with = "opt_path_from_toml")]
        data_dir: Option<PathBuf>,
        fee_threshold: u64,
        min_interval: u8,
        rpc_url: String,
        #[serde(default)]
        rpc_username: Option<String>,
        #[serde(default)]
        rpc_password: Option<String>,
        #[serde(default, deserialize_with = "opt_path_from_toml")]
        rpc_cookie_file: Option<PathBuf>,
        #[serde(default = "default_rpc_timeout_seconds")]
        rpc_timeout_seconds: u64,
        #[serde(default = "default_rpc_retry_seconds")]
        rpc_retry_seconds: u64,
    },
}

fn default_rpc_timeout_seconds() -> u64 {
    90
}

fn default_rpc_retry_seconds() -> u64 {
    2
}

fn default_rpc_min_interval_seconds() -> u8 {
    1
}

#[cfg(feature = "bitcoin-core-sv2")]
fn deserialize_optional_bitcoin_core_version<'de, D>(
    deserializer: D,
) -> Result<Option<BitcoinCoreVersion>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let major = <Option<u8> as serde::Deserialize>::deserialize(deserializer)?;
    major
        .map(|value| {
            BitcoinCoreVersion::try_from(value).map_err(|unsupported| {
                serde::de::Error::custom(format!(
                    "unsupported Bitcoin Core IPC version: {unsupported}. expected 30 or 31"
                ))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_with_data_dir_mainnet() {
        let result =
            resolve_ipc_socket_path(&BitcoinNetwork::Mainnet, Some(PathBuf::from("/data")));
        assert_eq!(result, Some(PathBuf::from("/data/node.sock")));
    }

    #[test]
    fn network_with_data_dir_regtest() {
        let result =
            resolve_ipc_socket_path(&BitcoinNetwork::Regtest, Some(PathBuf::from("/data")));
        assert_eq!(result, Some(PathBuf::from("/data/regtest/node.sock")));
    }

    #[test]
    fn network_with_data_dir_signet() {
        let result = resolve_ipc_socket_path(&BitcoinNetwork::Signet, Some(PathBuf::from("/data")));
        assert_eq!(result, Some(PathBuf::from("/data/signet/node.sock")));
    }

    #[test]
    fn network_with_data_dir_testnet4() {
        let result =
            resolve_ipc_socket_path(&BitcoinNetwork::Testnet4, Some(PathBuf::from("/data")));
        assert_eq!(result, Some(PathBuf::from("/data/testnet4/node.sock")));
    }

    #[test]
    fn missing_data_dir_uses_os_default() {
        // This test verifies behavior when data_dir is None
        // Result depends on OS - will be Some on Linux/macOS, None on unsupported OS
        let result = resolve_ipc_socket_path(&BitcoinNetwork::Regtest, None);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(result.is_some());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(result.is_none());
    }

    #[cfg(feature = "bitcoin-core-sv2")]
    #[test]
    fn bitcoin_core_version_accepts_30_and_31() {
        assert!(matches!(
            BitcoinCoreVersion::try_from(30),
            Ok(BitcoinCoreVersion::V30X)
        ));
        assert!(matches!(
            BitcoinCoreVersion::try_from(31),
            Ok(BitcoinCoreVersion::V31X)
        ));
    }

    #[cfg(feature = "bitcoin-core-sv2")]
    #[test]
    fn bitcoin_core_version_rejects_unsupported_values() {
        assert!(BitcoinCoreVersion::try_from(29).is_err());
        assert!(BitcoinCoreVersion::try_from(32).is_err());
    }
}
