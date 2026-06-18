//! Monitoring integration for JD Client
//!
//! This module implements the ServerMonitoring and Sv2ClientsMonitoring traits on `ChannelManager`.
//! JDC has:
//! - Server channels (upstream to pool)
//! - Client channels (downstream miners connecting to JDC)

use hex;
use stratum_apps::monitoring::{
    client::{ExtendedChannelInfo, StandardChannelInfo, Sv2ClientInfo, Sv2ClientsMonitoring},
    server::{ServerExtendedChannelInfo, ServerInfo, ServerMonitoring},
    MinerTelemetry, MinerTelemetryCollector,
};

use crate::{channel_manager::ChannelManager, downstream::Downstream};
use std::{collections::HashSet, net::IpAddr, time::Duration};
use tracing::{debug, info};

impl ServerMonitoring for ChannelManager {
    fn get_server(&self) -> ServerInfo {
        self.channel_manager_data
            .safe_lock(|d| {
                let mut extended_channels = Vec::new();
                let standard_channels = Vec::new(); // JDC only uses extended channels

                if let Some(upstream_channel) = &d.upstream_channel {
                    let channel_id = upstream_channel.get_channel_id();
                    let target = upstream_channel.get_target();
                    let extranonce_prefix = upstream_channel.get_extranonce_prefix();
                    let user_identity = upstream_channel.get_user_identity();
                    let share_accounting = upstream_channel.get_share_accounting();
                    let shares_rejected_by_reason = share_accounting
                        .get_rejected_shares()
                        .map(|(reason, count)| (reason.to_string(), count))
                        .collect();
                    let shares_rejected = share_accounting.get_rejected_shares_count();

                    extended_channels.push(ServerExtendedChannelInfo {
                        channel_id,
                        user_identity: user_identity.to_string(),
                        nominal_hashrate: Some(upstream_channel.get_nominal_hashrate()),
                        target_hex: hex::encode(target.to_be_bytes()),
                        extranonce_prefix_hex: hex::encode(extranonce_prefix),
                        full_extranonce_size: upstream_channel.get_full_extranonce_size(),
                        rollable_extranonce_size: upstream_channel.get_rollable_extranonce_size(),
                        version_rolling: upstream_channel.is_version_rolling(),
                        shares_acknowledged: share_accounting.get_acknowledged_shares(),
                        shares_submitted: share_accounting.get_validated_shares(),
                        shares_rejected,
                        shares_rejected_by_reason,
                        acknowledged_work_sum: share_accounting.get_acknowledged_work_sum(),
                        validated_work_sum: share_accounting.get_validated_work_sum(),
                        best_diff: share_accounting.get_best_diff(),
                        blocks_found: share_accounting.get_blocks_found(),
                    });
                }

                ServerInfo {
                    extended_channels,
                    standard_channels,
                }
            })
            .unwrap_or_else(|_| ServerInfo {
                extended_channels: Vec::new(),
                standard_channels: Vec::new(),
            })
    }
}

/// Helper to convert a Downstream to Sv2ClientInfo.
/// Returns None if the lock cannot be acquired (graceful degradation for monitoring).
fn downstream_to_sv2_client_info(
    client: &Downstream,
    miner_telemetry: Option<MinerTelemetry>,
) -> Option<Sv2ClientInfo> {
    client
        .downstream_data
        .safe_lock(|dd| {
            let mut extended_channels = Vec::new();
            let mut standard_channels = Vec::new();

            for (_channel_id, extended_channel) in dd.extended_channels.iter() {
                let channel_id = extended_channel.get_channel_id();
                let target = extended_channel.get_target();
                let requested_max_target = extended_channel.get_requested_max_target();
                let user_identity = extended_channel.get_user_identity();
                let share_accounting = extended_channel.get_share_accounting();

                extended_channels.push(ExtendedChannelInfo {
                    channel_id,
                    user_identity: user_identity.to_string(),
                    nominal_hashrate: extended_channel.get_nominal_hashrate(),
                    stable_hashrate: extended_channel.get_stable_hashrate(),
                    target_hex: hex::encode(target.to_be_bytes()),
                    requested_max_target_hex: hex::encode(requested_max_target.to_be_bytes()),
                    extranonce_prefix_hex: hex::encode(extended_channel.get_extranonce_prefix()),
                    full_extranonce_size: extended_channel.get_full_extranonce_size(),
                    rollable_extranonce_size: extended_channel.get_rollable_extranonce_size(),
                    expected_shares_per_minute: extended_channel.get_shares_per_minute(),
                    shares_accepted: share_accounting.get_shares_accepted(),
                    shares_rejected: share_accounting.get_rejected_shares_count(),
                    shares_rejected_by_reason: share_accounting
                        .get_rejected_shares()
                        .map(|(reason, count)| (reason.to_string(), count))
                        .collect(),
                    share_work_sum: share_accounting.get_share_work_sum(),
                    last_share_sequence_number: share_accounting.get_last_share_sequence_number(),
                    best_diff: share_accounting.get_best_diff(),
                    last_batch_accepted: share_accounting.get_last_batch_accepted(),
                    last_batch_work_sum: share_accounting.get_last_batch_work_sum(),
                    share_batch_size: share_accounting.get_share_batch_size(),
                    blocks_found: share_accounting.get_blocks_found(),
                });
            }

            for (_channel_id, standard_channel) in dd.standard_channels.iter() {
                let channel_id = standard_channel.get_channel_id();
                let target = standard_channel.get_target();
                let requested_max_target = standard_channel.get_requested_max_target();
                let user_identity = standard_channel.get_user_identity();
                let share_accounting = standard_channel.get_share_accounting();

                standard_channels.push(StandardChannelInfo {
                    channel_id,
                    user_identity: user_identity.to_string(),
                    nominal_hashrate: standard_channel.get_nominal_hashrate(),
                    stable_hashrate: standard_channel.get_stable_hashrate(),
                    target_hex: hex::encode(target.to_be_bytes()),
                    requested_max_target_hex: hex::encode(requested_max_target.to_be_bytes()),
                    extranonce_prefix_hex: hex::encode(standard_channel.get_extranonce_prefix()),
                    expected_shares_per_minute: standard_channel.get_shares_per_minute(),
                    shares_accepted: share_accounting.get_shares_accepted(),
                    shares_rejected: share_accounting.get_rejected_shares_count(),
                    shares_rejected_by_reason: share_accounting
                        .get_rejected_shares()
                        .map(|(reason, count)| (reason.to_string(), count))
                        .collect(),
                    share_work_sum: share_accounting.get_share_work_sum(),
                    last_share_sequence_number: share_accounting.get_last_share_sequence_number(),
                    best_diff: share_accounting.get_best_diff(),
                    last_batch_accepted: share_accounting.get_last_batch_accepted(),
                    last_batch_work_sum: share_accounting.get_last_batch_work_sum(),
                    share_batch_size: share_accounting.get_share_batch_size(),
                    blocks_found: share_accounting.get_blocks_found(),
                });
            }

            Sv2ClientInfo {
                client_id: client.downstream_id,
                extended_channels,
                standard_channels,
                miner_telemetry,
            }
        })
        .ok()
}

impl Sv2ClientsMonitoring for ChannelManager {
    fn get_sv2_clients(&self) -> Vec<Sv2ClientInfo> {
        // Clone Downstream references and release lock immediately to avoid contention
        // with template distribution and message handling
        let downstream_refs: Vec<Downstream> = self
            .channel_manager_data
            .safe_lock(|data| data.downstream.values().cloned().collect())
            .unwrap_or_default();

        downstream_refs
            .iter()
            .filter_map(|downstream| {
                let miner_telemetry = self.miner_telemetry_for(downstream.downstream_id);
                downstream_to_sv2_client_info(downstream, miner_telemetry)
            })
            .collect()
    }

    fn get_sv2_client_by_id(&self, client_id: usize) -> Option<Sv2ClientInfo> {
        let miner_telemetry = self.miner_telemetry_for(client_id);
        self.channel_manager_data
            .safe_lock(|d| {
                d.downstream.get(&client_id).and_then(|downstream| {
                    downstream_to_sv2_client_info(downstream, miner_telemetry)
                })
            })
            .unwrap_or(None)
    }
}

impl ChannelManager {
    pub(crate) fn miner_telemetry_for(&self, downstream_id: usize) -> Option<MinerTelemetry> {
        self.miner_telemetry
            .safe_lock(|telemetry| telemetry.get(&downstream_id).cloned())
            .unwrap_or(None)
    }

    pub(crate) async fn run_miner_telemetry_loop(
        &self,
        refresh_interval: Duration,
        cancellation_token: bitcoin_core_sv2::template_distribution_protocol::CancellationToken,
        fallback_token: bitcoin_core_sv2::template_distribution_protocol::CancellationToken,
    ) {
        let refresh_interval = refresh_interval.max(Duration::from_secs(1));
        let collector = MinerTelemetryCollector::new();
        let mut interval = tokio::time::interval(refresh_interval);

        info!(
            "Starting JDC miner telemetry loop with interval of {} seconds",
            refresh_interval.as_secs()
        );

        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("JDC miner telemetry loop received shutdown signal");
                    break;
                }
                _ = fallback_token.cancelled() => {
                    info!("JDC miner telemetry loop received fallback signal");
                    break;
                }
                _ = interval.tick() => {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            info!("JDC miner telemetry loop received shutdown signal");
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            info!("JDC miner telemetry loop received fallback signal");
                            break;
                        }
                        _ = self.refresh_miner_telemetry(&collector) => {}
                    }
                }
            }
        }
    }

    async fn refresh_miner_telemetry(&self, collector: &MinerTelemetryCollector) {
        let downstreams = self.current_downstream_connection_ips();
        let active_downstream_ids = downstreams
            .iter()
            .map(|(downstream_id, _)| *downstream_id)
            .collect::<HashSet<_>>();

        let _ = self.miner_telemetry.safe_lock(|telemetry| {
            telemetry.retain(|downstream_id, _| active_downstream_ids.contains(downstream_id));
        });

        if downstreams.is_empty() {
            return;
        }

        for (downstream_id, ip) in downstreams {
            match collector.fetch(ip).await {
                Some(telemetry) => {
                    let is_active = self
                        .channel_manager_data
                        .safe_lock(|data| data.downstream.contains_key(&downstream_id))
                        .unwrap_or(false);

                    if is_active {
                        let _ = self
                            .miner_telemetry
                            .safe_lock(|cache| cache.insert(downstream_id, telemetry));
                    }
                }
                None => {
                    let _ = self
                        .miner_telemetry
                        .safe_lock(|cache| cache.remove(&downstream_id));
                }
            }
        }
    }

    fn current_downstream_connection_ips(&self) -> Vec<(usize, IpAddr)> {
        let downstream_refs: Vec<Downstream> = self
            .channel_manager_data
            .safe_lock(|data| data.downstream.values().cloned().collect())
            .unwrap_or_default();

        downstream_refs
            .iter()
            .filter_map(|downstream| {
                downstream
                    .downstream_data
                    .safe_lock(|data| (downstream.downstream_id, data.connection_ip))
                    .map_err(|error| {
                        debug!(
                            downstream_id = downstream.downstream_id,
                            "Failed to lock downstream data for telemetry: {error}"
                        );
                    })
                    .ok()
            })
            .collect()
    }
}
