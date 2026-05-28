//! SV1 client monitoring integration for Sv1Server
//!
//! This module implements the Sv1ClientsMonitoring trait on `Sv1Server`.
use std::{collections::HashSet, net::IpAddr, time::Duration};

use stratum_apps::{
    monitoring::{
        sv1::{Sv1ClientInfo, Sv1ClientsMonitoring},
        MinerTelemetry, MinerTelemetryCollector,
    },
    utils::types::DownstreamId,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::sv1::{Downstream, Sv1Server};

/// Helper to convert a Downstream to Sv1ClientInfo
fn downstream_to_sv1_client_info(
    downstream: &Downstream,
    miner_telemetry: Option<MinerTelemetry>,
) -> Option<Sv1ClientInfo> {
    downstream
        .downstream_data
        .safe_lock(|dd| Sv1ClientInfo {
            client_id: downstream.downstream_id,
            channel_id: dd.channel_id,
            connection_ip: dd.connection_ip,
            authorized_worker_name: dd.authorized_worker_name.clone(),
            user_identity: dd.user_identity.clone(),
            target_hex: hex::encode(dd.target.to_be_bytes()),
            hashrate: dd.hashrate,
            miner_telemetry,
            stable_hashrate: dd.stable_hashrate,
            extranonce1_hex: hex::encode(&dd.extranonce1),
            extranonce2_len: dd.extranonce2_len,
            version_rolling_mask: dd
                .version_rolling_mask
                .as_ref()
                .map(|mask| format!("{:08x}", mask.0)),
            version_rolling_min_bit: dd
                .version_rolling_min_bit
                .as_ref()
                .map(|bit| format!("{:08x}", bit.0)),
        })
        .ok()
}

impl Sv1ClientsMonitoring for Sv1Server {
    fn get_sv1_clients(&self) -> Vec<Sv1ClientInfo> {
        self.downstreams
            .iter()
            .filter_map(|downstream| {
                let miner_telemetry = self.miner_telemetry_for(*downstream.key());
                downstream_to_sv1_client_info(downstream.value(), miner_telemetry)
            })
            .collect()
    }

    fn get_sv1_client_by_id(&self, client_id: usize) -> Option<Sv1ClientInfo> {
        let miner_telemetry = self.miner_telemetry_for(client_id);
        self.downstreams.get(&client_id).and_then(|downstream| {
            downstream_to_sv1_client_info(downstream.value(), miner_telemetry)
        })
    }
}

impl Sv1Server {
    pub(crate) fn miner_telemetry_for(
        &self,
        downstream_id: DownstreamId,
    ) -> Option<MinerTelemetry> {
        self.miner_telemetry
            .get(&downstream_id)
            .map(|telemetry| telemetry.clone())
    }

    pub(crate) async fn run_miner_telemetry_loop(
        &self,
        refresh_interval: Duration,
        cancellation_token: CancellationToken,
        fallback_token: CancellationToken,
    ) {
        let refresh_interval = refresh_interval.max(Duration::from_secs(1));
        let collector = MinerTelemetryCollector::new();
        let mut interval = tokio::time::interval(refresh_interval);

        info!(
            "Starting SV1 miner telemetry loop with interval of {} seconds",
            refresh_interval.as_secs()
        );

        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("SV1 miner telemetry loop received shutdown signal");
                    break;
                }
                _ = fallback_token.cancelled() => {
                    info!("SV1 miner telemetry loop received fallback signal");
                    break;
                }
                _ = interval.tick() => {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            info!("SV1 miner telemetry loop received shutdown signal");
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            info!("SV1 miner telemetry loop received fallback signal");
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

        self.miner_telemetry
            .retain(|downstream_id, _| active_downstream_ids.contains(downstream_id));

        if downstreams.is_empty() {
            return;
        }

        for (downstream_id, ip) in downstreams {
            match collector.fetch(ip).await {
                Some(telemetry) => {
                    if self.downstreams.contains_key(&downstream_id) {
                        self.miner_telemetry.insert(downstream_id, telemetry);
                    }
                }
                None => {
                    self.miner_telemetry.remove(&downstream_id);
                }
            }
        }
    }

    fn current_downstream_connection_ips(&self) -> Vec<(DownstreamId, IpAddr)> {
        self.downstreams
            .iter()
            .filter_map(|downstream| {
                downstream
                    .value()
                    .downstream_data
                    .safe_lock(|data| (*downstream.key(), data.connection_ip))
                    .ok()
            })
            .collect()
    }
}
