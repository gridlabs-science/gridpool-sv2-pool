//! Minimal GridPool integration for the stock SRI pool role.
//!
//! GridPool remains responsible for consensus and proof validation. This module only supplies
//! the active payout suffix, resolves a channel's slot-0 identity, and submits trusted local
//! telemetry/full proofs to the colocated GridPool node.

use std::{
    collections::HashMap,
    fs,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stratum_apps::stratum_core::bitcoin::{
    address::NetworkUnchecked, Address, Amount, Network, ScriptBuf, TxOut,
};
use tracing::{error, info, warn};

use crate::config::GridPoolConfig;

const ADAPTER_TOKEN_HEADER: &str = "X-GridPool-Adapter-Token";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkSelection {
    pub bitcoin_network: String,
    pub active_snapshot_id: String,
    pub current_tip_block_hash: Option<String>,
    pub minimum_difficulty_to_enter_reserve: f64,
    pub coinbase_outputs: Vec<GridPoolOutput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareAdvice {
    pulse_proofs_enabled: bool,
    minimum_pulse_difficulty: f64,
    pulse_target_interval_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GridPoolOutput {
    pub value: u64,
    pub script_pub_key_hex: String,
}

#[derive(Clone, Debug)]
pub struct ChannelPayout {
    pub payout_address: String,
    pub username: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSubmission {
    pub miner_address: String,
    pub username: String,
    pub header_hex: String,
    pub coinbase_hex: String,
    pub merkle_path: Vec<String>,
    pub payout_snapshot_id: Option<String>,
    pub prev_block_hash: Option<String>,
    pub difficulty: f64,
}

#[derive(Clone, Debug, Default)]
pub struct TelemetryDelta {
    pub channel_id: u32,
    pub payout_address: String,
    pub username: String,
    pub accepted: bool,
    pub work_difficulty: f64,
    pub achieved_difficulty: f64,
    pub fee_work: bool,
}

#[derive(Clone, Debug, Default)]
struct TelemetryAggregate {
    channel_id: u32,
    payout_address: String,
    username: String,
    window_start_ms: u128,
    window_end_ms: u128,
    accepted_share_count: u64,
    rejected_share_count: u64,
    accepted_work_difficulty: f64,
    fee_work_difficulty: f64,
    best_difficulty: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TelemetryBatch {
    source_instance: String,
    entries: Vec<TelemetryEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TelemetryEntry {
    channel_id: String,
    payout_address: String,
    username: String,
    window_start_utc: String,
    window_end_utc: String,
    accepted_share_count: u64,
    rejected_share_count: u64,
    accepted_work_difficulty: f64,
    fee_work_difficulty: f64,
    best_difficulty: f64,
}

#[derive(Clone)]
pub struct GridPoolClient {
    config: GridPoolConfig,
    http: reqwest::Client,
    token: Arc<String>,
    work: Arc<RwLock<WorkSelection>>,
    telemetry: Arc<Mutex<HashMap<String, TelemetryAggregate>>>,
    advice: Arc<RwLock<ShareAdvice>>,
    last_pulse: Arc<Mutex<HashMap<u64, u64>>>,
}

impl GridPoolClient {
    pub async fn connect(config: GridPoolConfig) -> Result<Self, String> {
        validate_config(&config)?;
        let token = fs::read_to_string(&config.adapter_token_file)
            .map_err(|e| format!("failed to read GridPool adapter token: {e}"))?
            .trim()
            .to_string();
        if token.len() < 32 {
            return Err("GridPool adapter token must contain at least 32 characters".into());
        }
        fs::create_dir_all(proof_spool_dir(&config))
            .map_err(|e| format!("failed to create GridPool proof spool: {e}"))?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        let work = fetch_work(&http, &config.node_url).await?;
        let advice = fetch_advice(&http, &config.node_url).await?;
        parse_network(&work.bitcoin_network)?;
        parse_address(&config.fallback_payout_address, &work.bitcoin_network)?;
        if let Some(address) = config.operator_fee_address.as_deref() {
            parse_address(address, &work.bitcoin_network)?;
        }

        Ok(Self {
            config,
            http,
            token: Arc::new(token),
            work: Arc::new(RwLock::new(work)),
            telemetry: Arc::new(Mutex::new(HashMap::new())),
            advice: Arc::new(RwLock::new(advice)),
            last_pulse: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn start(&self) {
        let refresh = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(refresh.config.refresh_seconds));
            loop {
                interval.tick().await;
                match fetch_work(&refresh.http, &refresh.config.node_url).await {
                    Ok(work) => {
                        *refresh.work.write().expect("GridPool work lock poisoned") = work;
                    }
                    Err(e) => warn!(error = %e, "Unable to refresh GridPool work selection"),
                }
                if let Ok(advice) = fetch_advice(&refresh.http, &refresh.config.node_url).await {
                    *refresh
                        .advice
                        .write()
                        .expect("GridPool advice lock poisoned") = advice;
                }
            }
        });

        let telemetry = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                telemetry.config.telemetry_flush_seconds,
            ));
            loop {
                interval.tick().await;
                telemetry.flush_telemetry().await;
            }
        });

        let proofs = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                proofs.retry_spooled_proofs().await;
            }
        });
    }

    pub fn work(&self) -> WorkSelection {
        self.work
            .read()
            .expect("GridPool work lock poisoned")
            .clone()
    }

    pub async fn refresh_for_chain_tip(&self) -> Result<(), String> {
        let previous_tip = self.work().current_tip_block_hash;
        let mut latest = None;

        // Bitcoin Core IPC and the GridPool node observe the same local tip through
        // independent paths. Give the node a short window to commit its snapshot
        // before constructing the future SV2 job.
        for _ in 0..40 {
            let work = fetch_work(&self.http, &self.config.node_url).await?;
            let tip_changed = previous_tip.is_none() || work.current_tip_block_hash != previous_tip;
            latest = Some(work);
            if tip_changed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let work = latest.ok_or_else(|| "GridPool returned no work selection".to_string())?;
        if previous_tip.is_some() && work.current_tip_block_hash == previous_tip {
            return Err("GridPool work selection did not advance to the new chain tip".into());
        }
        *self.work.write().expect("GridPool work lock poisoned") = work;
        Ok(())
    }

    pub fn resolve_channel(&self, identity: &str) -> Result<ChannelPayout, String> {
        let work = self.work();
        let trimmed = identity.trim();
        let explicit = if let Some(rest) = trimmed.strip_prefix("sri/solo/") {
            rest.split('/').next().unwrap_or_default()
        } else {
            trimmed.split('.').next().unwrap_or_default()
        };

        match parse_address(explicit, &work.bitcoin_network) {
            Ok(_) => Ok(ChannelPayout {
                payout_address: explicit.to_string(),
                username: trimmed.to_string(),
            }),
            Err(e) if looks_like_address(explicit) => Err(e),
            Err(_) => Ok(ChannelPayout {
                payout_address: self.config.fallback_payout_address.clone(),
                username: if trimmed.is_empty() {
                    "sv2".into()
                } else {
                    trimmed.into()
                },
            }),
        }
    }

    pub fn fee_active(&self, payout_address: &str, unix_seconds: u64) -> bool {
        if self.config.operator_fee_percent <= 0.0 || self.config.operator_fee_address.is_none() {
            return false;
        }
        let cycle = self.config.fee_cycle_seconds.max(1);
        let duration = ((cycle as f64 * self.config.operator_fee_percent / 100.0).round() as u64)
            .clamp(1, cycle);
        let mut hasher = Sha256::new();
        hasher.update(self.token.as_bytes());
        hasher.update(payout_address.as_bytes());
        let digest = hasher.finalize();
        let offset = u64::from_be_bytes(digest[..8].try_into().expect("fixed hash slice")) % cycle;
        (unix_seconds + cycle - offset) % cycle < duration
    }

    pub fn coinbase_outputs(
        &self,
        payout: &ChannelPayout,
        total_value: u64,
    ) -> Result<Vec<TxOut>, String> {
        let work = self.work();
        let suffix_value = work.coinbase_outputs.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value)
                .ok_or_else(|| "GridPool payout suffix overflow".to_string())
        })?;
        let slot_zero_value = total_value
            .checked_sub(suffix_value)
            .ok_or_else(|| "GridPool payout suffix exceeds available coinbase value".to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let slot_zero_address = if self.fee_active(&payout.payout_address, now) {
            self.config
                .operator_fee_address
                .as_deref()
                .unwrap_or(&payout.payout_address)
        } else {
            &payout.payout_address
        };
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(slot_zero_value),
            script_pubkey: parse_address(slot_zero_address, &work.bitcoin_network)?,
        }];
        for output in work.coinbase_outputs {
            outputs.push(TxOut {
                value: Amount::from_sat(output.value),
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode(output.script_pub_key_hex)
                        .map_err(|e| format!("invalid GridPool payout script: {e}"))?,
                ),
            });
        }
        Ok(outputs)
    }

    pub fn constraint_outputs(&self) -> Result<Vec<TxOut>, String> {
        self.coinbase_outputs(
            &ChannelPayout {
                payout_address: self.config.fallback_payout_address.clone(),
                username: "constraints".into(),
            },
            self.work()
                .coinbase_outputs
                .iter()
                .map(|o| o.value)
                .sum::<u64>()
                + 1,
        )
    }

    pub fn record_telemetry(&self, delta: TelemetryDelta) {
        let now = now_millis();
        let key = format!("{}:{}", delta.channel_id, delta.payout_address);
        let mut telemetry = self
            .telemetry
            .lock()
            .expect("GridPool telemetry lock poisoned");
        let aggregate = telemetry.entry(key).or_insert_with(|| TelemetryAggregate {
            channel_id: delta.channel_id,
            payout_address: delta.payout_address.clone(),
            username: delta.username.clone(),
            window_start_ms: now,
            ..Default::default()
        });
        aggregate.window_end_ms = now;
        aggregate.username = delta.username;
        if delta.accepted {
            aggregate.accepted_share_count += 1;
            aggregate.accepted_work_difficulty += delta.work_difficulty.max(0.0);
            if delta.fee_work {
                aggregate.fee_work_difficulty += delta.work_difficulty.max(0.0);
            }
            aggregate.best_difficulty = aggregate.best_difficulty.max(delta.achieved_difficulty);
        } else {
            aggregate.rejected_share_count += 1;
        }
    }

    pub fn submit_proof(&self, proof: ShareSubmission) {
        let this = self.clone();
        tokio::spawn(async move {
            let path = proof_spool_dir(&this.config).join(format!("{}.json", proof.header_hex));
            let encoded = match serde_json::to_vec(&proof) {
                Ok(encoded) => encoded,
                Err(e) => {
                    error!(error = %e, "Unable to serialize SV2 proof");
                    return;
                }
            };
            if let Err(e) = tokio::fs::write(&path, encoded).await {
                error!(error = %e, "Unable to spool SV2 proof; refusing lossy submission");
                return;
            }
            this.submit_spooled_proof(&path, &proof).await;
        });
    }

    pub fn should_submit_proof(
        &self,
        channel_key: u64,
        achieved_difficulty: f64,
        is_block: bool,
    ) -> bool {
        if is_block || achieved_difficulty >= self.work().minimum_difficulty_to_enter_reserve {
            return true;
        }
        let advice = self
            .advice
            .read()
            .expect("GridPool advice lock poisoned")
            .clone();
        if !advice.pulse_proofs_enabled || achieved_difficulty < advice.minimum_pulse_difficulty {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut last = self
            .last_pulse
            .lock()
            .expect("GridPool pulse lock poisoned");
        let previous = last.get(&channel_key).copied().unwrap_or(0);
        if now.saturating_sub(previous) < advice.pulse_target_interval_seconds.max(1) {
            return false;
        }
        last.insert(channel_key, now);
        true
    }

    pub fn is_fee_job(&self, outputs: &[TxOut], payout: &ChannelPayout) -> bool {
        let Some(operator) = self.config.operator_fee_address.as_deref() else {
            return false;
        };
        if operator == payout.payout_address || outputs.is_empty() {
            return false;
        }
        parse_address(operator, &self.work().bitcoin_network)
            .map(|script| outputs[0].script_pubkey == script)
            .unwrap_or(false)
    }

    async fn flush_telemetry(&self) {
        let drained: Vec<TelemetryAggregate> = {
            let mut guard = self
                .telemetry
                .lock()
                .expect("GridPool telemetry lock poisoned");
            guard.drain().map(|(_, value)| value).collect()
        };
        if drained.is_empty() {
            return;
        }
        let batch = TelemetryBatch {
            source_instance: "gridpool-sv2-pool".into(),
            entries: drained
                .iter()
                .map(|item| TelemetryEntry {
                    channel_id: item.channel_id.to_string(),
                    payout_address: item.payout_address.clone(),
                    username: item.username.clone(),
                    window_start_utc: iso8601_millis(item.window_start_ms),
                    window_end_utc: iso8601_millis(item.window_end_ms.max(item.window_start_ms)),
                    accepted_share_count: item.accepted_share_count,
                    rejected_share_count: item.rejected_share_count,
                    accepted_work_difficulty: item.accepted_work_difficulty,
                    fee_work_difficulty: item.fee_work_difficulty,
                    best_difficulty: item.best_difficulty,
                })
                .collect(),
        };
        let url = endpoint(&self.config.node_url, "api/mining/local/share-telemetry");
        let send_result = self
            .http
            .post(url)
            .header(ADAPTER_TOKEN_HEADER, self.token.as_str())
            .json(&batch)
            .send()
            .await;
        match send_result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                error!(status = %response.status(), "GridPool rejected SV2 telemetry batch")
            }
            Err(e) => error!(error = %e, "Failed to submit SV2 telemetry batch"),
        }
    }

    async fn retry_spooled_proofs(&self) {
        let Ok(mut entries) = tokio::fs::read_dir(proof_spool_dir(&self.config)).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(proof) = serde_json::from_slice::<ShareSubmission>(&bytes) else {
                error!(path = %path.display(), "Invalid proof in GridPool spool");
                continue;
            };
            self.submit_spooled_proof(&path, &proof).await;
        }
    }

    async fn submit_spooled_proof(&self, path: &std::path::Path, proof: &ShareSubmission) {
        let url = endpoint(&self.config.node_url, "api/mining/local/share");
        match self
            .http
            .post(url)
            .header(ADAPTER_TOKEN_HEADER, self.token.as_str())
            .json(proof)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let _ = tokio::fs::remove_file(path).await;
                info!("Submitted SV2 proof to GridPool");
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                error!(%status, %body, "GridPool rejected spooled SV2 proof");
            }
            Err(e) => error!(error = %e, "Failed to submit spooled SV2 proof"),
        }
    }
}

async fn fetch_work(http: &reqwest::Client, base: &str) -> Result<WorkSelection, String> {
    http.get(endpoint(base, "api/mining/sv2-work-selection"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

async fn fetch_advice(http: &reqwest::Client, base: &str) -> Result<ShareAdvice, String> {
    http.get(endpoint(base, "api/mining/share-advice"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

fn validate_config(config: &GridPoolConfig) -> Result<(), String> {
    if !(0.0..=100.0).contains(&config.operator_fee_percent) {
        return Err("GridPool operator_fee_percent must be between 0 and 100".into());
    }
    if config.operator_fee_percent > 0.0 && config.operator_fee_address.is_none() {
        return Err(
            "GridPool operator_fee_address is required when the operator fee is enabled".into(),
        );
    }
    if config.refresh_seconds == 0
        || config.telemetry_flush_seconds == 0
        || config.fee_cycle_seconds == 0
    {
        return Err("GridPool intervals must be positive".into());
    }
    Ok(())
}

fn parse_address(value: &str, network: &str) -> Result<ScriptBuf, String> {
    let network = parse_network(network)?;
    let unchecked = Address::<NetworkUnchecked>::from_str(value)
        .map_err(|e| format!("invalid payout address '{value}': {e}"))?;
    let checked = unchecked
        .require_network(network)
        .map_err(|e| format!("wrong-network payout address '{value}': {e}"))?;
    Ok(checked.script_pubkey())
}

fn parse_network(value: &str) -> Result<Network, String> {
    match value.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unsupported Bitcoin network '{value}'")),
    }
}

fn looks_like_address(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("bc1")
        || lower.starts_with("tb1")
        || lower.starts_with("bcrt1")
        || matches!(value.chars().next(), Some('1' | '3' | 'm' | 'n' | '2'))
}

fn endpoint(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn proof_spool_dir(config: &GridPoolConfig) -> std::path::PathBuf {
    config.proof_spool_dir.clone().unwrap_or_else(|| {
        config
            .adapter_token_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("sv2-proof-spool")
    })
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

// System.Text.Json accepts ISO-8601. Avoid another time dependency by emitting Unix epoch plus
// milliseconds in the equivalent DateTimeOffset JSON shape accepted by the local API.
fn iso8601_millis(ms: u128) -> String {
    // RFC3339 conversion is deliberately delegated to a tiny dependency-free UTC algorithm.
    let seconds = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = seconds.div_euclid(86_400);
    let sod = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> GridPoolClient {
        GridPoolClient {
            config: GridPoolConfig {
                node_url: "http://127.0.0.1:5000".into(),
                fallback_payout_address: "bc1qrwsx8fs0l6z7ugp5cvzy6lhss7jlyru3kg9s8y".into(),
                operator_fee_address: Some("bc1qce93hy5rhg02s6aeu7mfdvxg76x66pqqtrvzs3".into()),
                operator_fee_percent: 2.0,
                adapter_token_file: "/tmp/gridpool-test.token".into(),
                proof_spool_dir: None,
                refresh_seconds: 10,
                telemetry_flush_seconds: 5,
                fee_cycle_seconds: 1_500,
            },
            http: reqwest::Client::new(),
            token: Arc::new("0123456789abcdef0123456789abcdef".into()),
            work: Arc::new(RwLock::new(WorkSelection {
                bitcoin_network: "mainnet".into(),
                active_snapshot_id: "snapshot".into(),
                current_tip_block_hash: None,
                minimum_difficulty_to_enter_reserve: 100.0,
                coinbase_outputs: vec![GridPoolOutput {
                    value: 100,
                    script_pub_key_hex: "00141ba063a60ffe85ee2034c3044d7ef087a5f20f91".into(),
                }],
            })),
            telemetry: Arc::new(Mutex::new(HashMap::new())),
            advice: Arc::new(RwLock::new(ShareAdvice {
                pulse_proofs_enabled: true,
                minimum_pulse_difficulty: 10.0,
                pulse_target_interval_seconds: 60,
            })),
            last_pulse: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn address_like_invalid_identity_fails_closed() {
        assert!(looks_like_address("bc1qnotarealaddress"));
        assert!(!looks_like_address("worker-01"));
    }

    #[test]
    fn unix_epoch_format_is_rfc3339() {
        assert_eq!(iso8601_millis(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn worker_falls_back_but_address_errors_fail_closed() {
        let client = client();
        let fallback = client.resolve_channel("garage-rig").unwrap();
        assert_eq!(
            fallback.payout_address,
            client.config.fallback_payout_address
        );
        let explicit = client
            .resolve_channel("bc1qrwsx8fs0l6z7ugp5cvzy6lhss7jlyru3kg9s8y.worker")
            .unwrap();
        assert_eq!(
            explicit.payout_address,
            client.config.fallback_payout_address
        );
        assert!(client
            .resolve_channel("tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8")
            .is_err());
        assert!(client.resolve_channel("bc1qnotarealaddress").is_err());
    }

    #[test]
    fn payout_suffix_leaves_remainder_in_slot_zero() {
        let client = client();
        let payout = client.resolve_channel("garage-rig").unwrap();
        let outputs = client.coinbase_outputs(&payout, 1_000).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].value.to_sat(), 900);
        assert_eq!(outputs[1].value.to_sat(), 100);
    }

    #[test]
    fn two_percent_window_is_exactly_thirty_seconds_per_cycle() {
        let client = client();
        let active = (0..1_500)
            .filter(|second| client.fee_active(&client.config.fallback_payout_address, *second))
            .count();
        assert_eq!(active, 30);
    }
}
