//! Miner telemetry monitoring types and helpers.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use asic_rs::{
    core::data::{collector::DataField, hashrate::HashRateUnit, miner::MinerData},
    MinerFactory,
};
use std::net::IpAddr;
use tracing::debug;

/// Telemetry reported by the miner's management interface.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MinerTelemetry {
    /// Miner manufacturer or brand reported by the management interface.
    pub make: Option<String>,
    /// Miner model reported by the management interface.
    pub model: Option<String>,
    /// Firmware version reported by the miner, when exposed.
    pub firmware_version: Option<String>,
    /// Miner-reported hashrate in hashes per second.
    pub reported_hashrate_hs: Option<f64>,
    /// Current miner power consumption in watts.
    pub power_consumption_w: Option<f64>,
    /// Miner efficiency in joules per terahash.
    pub efficiency_j_per_th: Option<f64>,
    /// Average miner temperature in degrees Celsius.
    pub average_temperature_c: Option<f64>,
    /// Total miner system uptime in seconds.
    pub uptime_secs: Option<u64>,
    /// Whether the miner reports that hashing is currently running.
    pub is_mining: Option<bool>,
}

impl From<MinerData> for MinerTelemetry {
    fn from(data: MinerData) -> Self {
        Self {
            make: Some(data.device_info.make),
            model: Some(data.device_info.model),
            firmware_version: data.firmware_version,
            reported_hashrate_hs: data
                .hashrate
                .map(|hashrate| hashrate.as_unit(HashRateUnit::Hash).value),
            power_consumption_w: data.wattage.map(|power| power.as_watts()),
            efficiency_j_per_th: data.efficiency,
            average_temperature_c: data
                .average_temperature
                .map(|temperature| temperature.as_celsius()),
            uptime_secs: data.uptime.map(|uptime| uptime.as_secs()),
            is_mining: Some(data.is_mining),
        }
    }
}

const MINER_TELEMETRY_EXCLUDED_FIELDS: &[DataField] = &[
    DataField::Mac,
    DataField::SerialNumber,
    DataField::Hostname,
    DataField::ApiVersion,
    DataField::ControlBoardVersion,
    DataField::Chips,
    DataField::ExpectedHashrate,
    DataField::Fans,
    DataField::PsuFans,
    DataField::FluidTemperature,
    DataField::TuningTarget,
    DataField::LightFlashing,
    DataField::Messages,
    DataField::Pools,
];

pub struct MinerTelemetryCollector {
    factory: MinerFactory,
}

impl MinerTelemetryCollector {
    pub fn new() -> Self {
        Self {
            factory: MinerFactory::new(),
        }
    }

    pub async fn fetch(&self, ip: IpAddr) -> Option<MinerTelemetry> {
        let miner = match self.factory.get_miner(ip).await {
            Ok(Some(miner)) => miner,
            Ok(None) => {
                debug!("No miner management interface found at {ip}");
                return None;
            }
            Err(error) => {
                debug!("Failed to get miner management interface at {ip}: {error}");
                return None;
            }
        };

        Some(MinerTelemetry::from(
            miner
                .get_data_filtered(MINER_TELEMETRY_EXCLUDED_FIELDS.to_vec())
                .await,
        ))
    }
}

impl Default for MinerTelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}
