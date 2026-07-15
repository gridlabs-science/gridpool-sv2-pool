use std::{convert::TryFrom, sync::atomic::Ordering};

use stratum_apps::stratum_core::{
    binary_sv2::Str0255,
    bitcoin::{
        absolute::LockTime,
        blockdata::{
            block::{Header, Version},
            witness::Witness,
        },
        consensus,
        hashes::{sha256d, Hash},
        transaction::{OutPoint, Transaction, TxIn, Version as TxVersion},
        BlockHash, CompactTarget, Sequence, Target,
    },
    channels_sv2::{
        server::{
            error::{ExtendedChannelError, StandardChannelError},
            extended::ExtendedChannel,
            share_accounting::{ShareValidationError, ShareValidationResult},
            standard::StandardChannel,
        },
        Vardiff, VardiffState,
    },
    extensions_sv2::{
        UserIdentity, EXTENSION_TYPE_WORKER_HASHRATE_TRACKING, TLV_FIELD_TYPE_USER_IDENTITY,
    },
    handlers_sv2::{HandleMiningMessagesFromClientAsync, SupportedChannelTypes},
    mining_sv2::*,
    parsers_sv2::{Mining, TemplateDistribution, Tlv, TlvField},
    template_distribution_sv2::SubmitSolution,
};
use tracing::{error, info};

use jd_server_sv2::job_declarator::SetCustomMiningJobResponse;

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo, CLIENT_SEARCH_SPACE_BYTES},
    error::{self, PoolError, PoolErrorKind},
    gridpool::{ChannelPayout, ShareSubmission, TelemetryDelta},
    utils::{create_close_channel_msg, PayoutMode, PayoutModeError},
};

fn build_standard_gridpool_proof(
    pool_tag: &str,
    channel: &StandardChannel<'_>,
    msg: &SubmitSharesStandard,
    payout: &ChannelPayout,
    achieved_difficulty: f64,
) -> Option<ShareSubmission> {
    let job = channel
        .get_active_job()
        .filter(|job| job.get_job_id() == msg.job_id)
        .or_else(|| channel.get_past_job(msg.job_id))?;
    let chain_tip = channel.get_chain_tip()?;
    let tag = format!("/{pool_tag}//").into_bytes();
    if tag.len() > 61 {
        return None;
    }
    let mut script_sig = job.get_template().coinbase_prefix.to_owned_bytes();
    script_sig.push(tag.len() as u8);
    script_sig.extend(tag);
    script_sig.push(job.get_extranonce_prefix().len() as u8);
    script_sig.extend(job.get_extranonce_prefix());
    let coinbase = Transaction {
        version: TxVersion::non_standard(job.get_template().coinbase_tx_version as i32),
        lock_time: LockTime::from_consensus(job.get_template().coinbase_tx_locktime),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: script_sig.into(),
            sequence: Sequence(job.get_template().coinbase_tx_input_sequence),
            witness: Witness::from(vec![vec![0; 32]]),
        }],
        output: job.get_coinbase_outputs().to_vec(),
    };
    let merkle_root = job.get_merkle_root().to_array();
    let prev_hash = chain_tip.prev_hash().clone().into_array();
    let header = Header {
        version: Version::from_consensus(msg.version as i32),
        prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::from_slice(&prev_hash).ok()?),
        merkle_root: (*sha256d::Hash::from_bytes_ref(&merkle_root)).into(),
        time: msg.ntime,
        bits: CompactTarget::from_consensus(chain_tip.nbits()),
        nonce: msg.nonce,
    };
    Some(ShareSubmission {
        miner_address: payout.payout_address.clone(),
        username: payout.username.clone(),
        header_hex: hex::encode(consensus::serialize(&header)),
        coinbase_hex: hex::encode(consensus::serialize(&coinbase)),
        merkle_path: job
            .get_template()
            .merkle_path
            .iter()
            .map(|node| hex::encode(node.to_array()))
            .collect(),
        payout_snapshot_id: None,
        prev_block_hash: Some(header.prev_blockhash.to_string()),
        difficulty: achieved_difficulty,
    })
}

fn build_extended_gridpool_proof(
    channel: &ExtendedChannel<'_>,
    msg: &SubmitSharesExtended<'_>,
    payout: &ChannelPayout,
    achieved_difficulty: f64,
) -> Option<ShareSubmission> {
    let job = channel
        .get_active_job()
        .filter(|job| job.get_job_id() == msg.job_id)
        .or_else(|| channel.get_past_job(msg.job_id))?;
    let chain_tip = channel.get_chain_tip()?;
    let mut full_extranonce = Vec::new();
    full_extranonce.extend_from_slice(job.get_extranonce_prefix());
    full_extranonce.extend_from_slice(msg.extranonce.as_bytes());
    let mut coinbase = Vec::new();
    coinbase.extend(job.get_coinbase_tx_prefix_without_bip141());
    coinbase.extend_from_slice(&full_extranonce);
    coinbase.extend(job.get_coinbase_tx_suffix_without_bip141());
    let coinbase_tx: Transaction = consensus::deserialize(&coinbase).ok()?;
    let mut merkle_root: [u8; 32] = *coinbase_tx.compute_txid().as_ref();
    let mut merkle_path = Vec::new();
    for node in job.get_merkle_path().iter() {
        let bytes = node.to_array();
        merkle_path.push(hex::encode(bytes));
        let combined = [&merkle_root[..], &bytes[..]].concat();
        merkle_root = *sha256d::Hash::hash(&combined).as_ref();
    }
    let prev_hash = chain_tip.prev_hash().clone().into_array();
    let header = Header {
        version: Version::from_consensus(msg.version as i32),
        prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::from_slice(&prev_hash).ok()?),
        merkle_root: (*sha256d::Hash::from_bytes_ref(&merkle_root)).into(),
        time: msg.ntime,
        bits: CompactTarget::from_consensus(chain_tip.nbits()),
        nonce: msg.nonce,
    };
    Some(ShareSubmission {
        miner_address: payout.payout_address.clone(),
        username: payout.username.clone(),
        header_hex: hex::encode(consensus::serialize(&header)),
        coinbase_hex: hex::encode(coinbase),
        merkle_path,
        payout_snapshot_id: None,
        prev_block_hash: Some(header.prev_blockhash.to_string()),
        difficulty: achieved_difficulty,
    })
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleMiningMessagesFromClientAsync for ChannelManager {
    type Error = PoolError<error::ChannelManager>;

    fn get_channel_type_for_client(&self, _client_id: Option<usize>) -> SupportedChannelTypes {
        SupportedChannelTypes::GroupAndExtended
    }

    fn is_work_selection_enabled_for_client(&self, _client_id: Option<usize>) -> bool {
        true
    }

    fn is_client_authorized(
        &self,
        _client_id: Option<usize>,
        _user_identity: &Str0255,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn get_negotiated_extensions_with_client(
        &self,
        client_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        self.with_registered_downstream(downstream_id, |downstream| {
            downstream
                .negotiated_extensions
                .get()
                .map_err(PoolError::shutdown)
        })
    }

    async fn handle_close_channel(
        &mut self,
        client_id: Option<usize>,
        msg: CloseChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received Close Channel: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        self.with_registered_downstream(downstream_id, |downstream| {
            downstream
                .group_channel
                .with(|group_channel| {
                    if group_channel.has_channel_id(msg.channel_id) {
                        group_channel.remove_channel_id(msg.channel_id);
                    }
                })
                .map_err(PoolError::shutdown)?;
            downstream.standard_channels.remove(&msg.channel_id);
            downstream.extended_channels.remove(&msg.channel_id);
            Ok(())
        })?;
        self.vardiff.remove(&(downstream_id, msg.channel_id).into());
        self.gridpool_channels
            .remove(&(downstream_id, msg.channel_id));
        Ok(())
    }

    async fn handle_open_standard_mining_channel(
        &mut self,
        client_id: Option<usize>,
        msg: OpenStandardMiningChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        let request_id = msg.get_request_id_as_u32();
        let user_identity = msg.user_identity.as_utf8_or_hex();
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        info!("Received OpenStandardMiningChannel: {}", msg);

        let messages = self.with_registered_downstream(downstream_id, |downstream| {
                if downstream.requires_custom_work.load(Ordering::SeqCst) {
                    error!("OpenStandardMiningChannel: Standard Channels are not supported for this connection");
                    let open_standard_mining_channel_error = OpenMiningChannelError {
                        request_id,
                        error_code: ERROR_CODE_OPEN_MINING_CHANNEL_STANDARD_CHANNELS_NOT_SUPPORTED_FOR_CUSTOM_WORK
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    return Ok(vec![(
                        downstream_id,
                        Mining::OpenMiningChannelError(open_standard_mining_channel_error),
                    )
                        .into()]);
                }

                let Some(last_future_template) = self
                    .last_future_template
                    .get()
                    .map_err(PoolError::shutdown)?
                else {
                    return Err(PoolError::disconnect(
                        PoolErrorKind::FutureTemplateNotPresent,
                        downstream_id,
                    ));
                };

                let Some(last_set_new_prev_hash_tdp) =
                    self.last_new_prev_hash.get().map_err(PoolError::shutdown)?
                else {
                    return Err(PoolError::disconnect(
                        PoolErrorKind::LastNewPrevhashNotFound,
                        downstream_id,
                    ));
                };

                let gridpool_payout = match self.gridpool.as_ref() {
                    Some(gridpool) => match gridpool.resolve_channel(&user_identity) {
                        Ok(payout) => Some(payout),
                        Err(reason) => {
                            error!(%reason, user_identity, "Rejecting invalid GridPool payout identity");
                            let response = OpenMiningChannelError {
                                request_id,
                                error_code: ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY
                                    .to_string().try_into().expect("valid error code"),
                            };
                            return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(response)).into()]);
                        }
                    },
                    None => None,
                };

                let payout_mode = match PayoutMode::try_from(user_identity.as_str()) {
                    Ok(mode) => mode,
                    Err(PayoutModeError::NoPayoutMode(_)) if gridpool_payout.is_some() => PayoutMode::FullDonation,
                    Err(PayoutModeError::NoPayoutMode(_)) => PayoutMode::FullDonation,
                    Err(_) => {
                        error!(
                            "Invalid user_identity '{}': does not match any supported identity format",
                            user_identity
                        );
                        let open_standard_mining_channel_error = OpenMiningChannelError {
                            request_id,
                            error_code: ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        return Ok(vec![(
                            downstream_id,
                            Mining::OpenMiningChannelError(open_standard_mining_channel_error),
                        )
                            .into()]);
                    }
                };

                let coinbase_outputs = match (&self.gridpool, &gridpool_payout) {
                    (Some(gridpool), Some(payout)) => gridpool
                        .coinbase_outputs(payout, last_future_template.coinbase_tx_value_remaining)
                        .map_err(|e| PoolError::disconnect(PoolErrorKind::Configuration(e), downstream_id))?,
                    _ => payout_mode.coinbase_outputs(
                        last_future_template.coinbase_tx_value_remaining,
                        &self.coinbase_reward_script,
                    ),
                };

                downstream
                    .payout_mode
                    .set(Some(payout_mode))
                    .map_err(PoolError::shutdown)?;

                let nominal_hash_rate = msg.nominal_hash_rate;
                let requested_max_target = Target::from_le_bytes(msg.max_target.to_array());
                let extranonce_prefix = self
                    .extranonce_allocator
                    .with(|allocator| allocator.allocate_standard())
                    .map_err(PoolError::shutdown)?
                    .map_err(PoolError::shutdown)?;

                let channel_id = downstream.channel_id_factory.fetch_add(1, Ordering::SeqCst);
                let mut standard_channel = match StandardChannel::new_for_pool(
                    channel_id,
                    user_identity.to_string(),
                    extranonce_prefix,
                    requested_max_target,
                    nominal_hash_rate,
                    self.share_batch_size,
                    self.shares_per_minute,
                    self.pool_tag_string.clone(),
                ) {
                    Ok(channel) => channel,
                    Err(e) => match e {
                        StandardChannelError::OpenChannelInvalidNominalHashrate(code) => {
                            error!("OpenMiningChannelError: {}", code);
                            let open_standard_mining_channel_error = OpenMiningChannelError {
                                request_id,
                                error_code: code
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            return Ok(vec![(
                                downstream_id,
                                Mining::OpenMiningChannelError(open_standard_mining_channel_error),
                            )
                                .into()]);
                        }
                        _ => {
                            error!("error in handle_open_standard_mining_channel: {:?}", e);
                            return Err(PoolError::disconnect(
                                PoolErrorKind::ChannelErrorSender,
                                downstream_id,
                            ));
                        }
                    },
                };
                if let Some(payout) = gridpool_payout {
                    self.gridpool_channels.insert((downstream_id, channel_id), payout);
                }

                let group_channel_id = downstream
                    .group_channel
                    .with(|channel| channel.get_group_channel_id())
                    .map_err(PoolError::shutdown)?;
                let extranonce_prefix_size = standard_channel.get_extranonce_prefix().len();

                let open_standard_mining_channel_success = OpenStandardMiningChannelSuccess {
                    request_id: msg.request_id,
                    channel_id,
                    target: standard_channel.get_target().to_le_bytes().into(),
                    extranonce_prefix: standard_channel
                        .get_extranonce_prefix()
                        .to_vec()
                        .try_into()
                        .expect("Extranonce_prefix must be valid"),
                    group_channel_id,
                }
                .into_static();

                let mut messages: Vec<RouteMessageTo> = Vec::new();

                messages.push(
                    (
                        downstream_id,
                        Mining::OpenStandardMiningChannelSuccess(
                            open_standard_mining_channel_success,
                        ),
                    )
                        .into(),
                );

                let template_id = last_future_template.template_id;

                standard_channel
                    .on_new_template(last_future_template, coinbase_outputs.clone())
                    .map_err(PoolError::shutdown)?;
                let future_standard_job_id = standard_channel
                    .get_future_job_id_from_template_id(template_id)
                    .expect("future job id must exist");
                let future_standard_job = standard_channel
                    .get_future_job(future_standard_job_id)
                    .expect("future job must exist");
                let future_standard_job_message =
                    future_standard_job.get_job_message().clone().into_static();

                messages.push(
                    (
                        downstream_id,
                        Mining::NewMiningJob(future_standard_job_message),
                    )
                        .into(),
                );
                let prev_hash = last_set_new_prev_hash_tdp.prev_hash.clone();
                let header_timestamp = last_set_new_prev_hash_tdp.header_timestamp;
                let n_bits = last_set_new_prev_hash_tdp.n_bits;
                let set_new_prev_hash_mining = SetNewPrevHash {
                    channel_id,
                    job_id: future_standard_job_id,
                    prev_hash,
                    min_ntime: header_timestamp,
                    nbits: n_bits,
                };

                standard_channel
                    .on_set_new_prev_hash(last_set_new_prev_hash_tdp.clone())
                    .map_err(PoolError::shutdown)?;

                messages.push(
                    (
                        downstream_id,
                        Mining::SetNewPrevHash(set_new_prev_hash_mining),
                    )
                        .into(),
                );

                downstream
                    .standard_channels
                    .insert(channel_id, standard_channel);
                if !downstream.requires_standard_jobs.load(Ordering::SeqCst) {
                    downstream
                        .group_channel
                        .with(|channel| channel.add_channel_id(channel_id, extranonce_prefix_size))
                        .map_err(PoolError::shutdown)?
                        .map_err(|e| {
                            error!("Failed to add channel id to group channel: {:?}", e);
                            PoolError::shutdown(e)
                        })?;
                }
                let vardiff = VardiffState::new().map_err(PoolError::shutdown)?;
                self.vardiff
                    .insert((downstream_id, channel_id).into(), vardiff);

                Ok(messages)
            })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_io).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_open_extended_mining_channel(
        &mut self,
        client_id: Option<usize>,
        msg: OpenExtendedMiningChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        let request_id = msg.get_request_id_as_u32();
        let user_identity = msg.user_identity.as_utf8_or_hex();
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        info!("Received OpenExtendedMiningChannel: {}", msg);

        let nominal_hash_rate = msg.nominal_hash_rate;
        let requested_max_target = Target::from_le_bytes(msg.max_target.to_array());
        let requested_min_rollable_extranonce_size = msg.min_extranonce_size;

        let messages = self.with_registered_downstream(downstream_id, |downstream| {
                if downstream.requires_standard_jobs.load(Ordering::SeqCst) {
                    let open_extended_mining_channel_error = OpenMiningChannelError {
                            request_id,
                            error_code: ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                    return Ok(vec![(
                        downstream_id,
                        Mining::OpenMiningChannelError(open_extended_mining_channel_error),
                    )
                        .into()]);
                }

                let mut messages: Vec<RouteMessageTo> = Vec::new();

                let extranonce_prefix = match self
                    .extranonce_allocator
                    .with(|allocator| {
                        allocator.allocate_extended(requested_min_rollable_extranonce_size.into())
                    })
                    .map_err(PoolError::shutdown)?
                {
                    Ok(prefix) => prefix,
                    Err(_) => {
                        error!("OpenMiningChannelError: min-extranonce-size-too-large");
                        let open_extended_mining_channel_error = OpenMiningChannelError {
                            request_id,
                            error_code: ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        return Ok(vec![(
                            downstream_id,
                            Mining::OpenMiningChannelError(open_extended_mining_channel_error),
                        )
                            .into()]);
                    }
                };

                let gridpool_payout = match self.gridpool.as_ref() {
                    Some(gridpool) => match gridpool.resolve_channel(&user_identity) {
                        Ok(payout) => Some(payout),
                        Err(reason) => {
                            error!(%reason, user_identity, "Rejecting invalid GridPool payout identity");
                            let response = OpenMiningChannelError {
                                request_id,
                                error_code: ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY
                                    .to_string().try_into().expect("valid error code"),
                            };
                            return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(response)).into()]);
                        }
                    },
                    None => None,
                };

                let payout_mode = match PayoutMode::try_from(user_identity.as_str()) {
                    Ok(mode) => mode,
                    Err(PayoutModeError::NoPayoutMode(_)) => PayoutMode::FullDonation,
                    Err(_) => {
                        error!(
                            "Invalid user_identity '{}': does not match any supported identity format",
                            user_identity
                        );
                        let open_extended_mining_channel_error = OpenMiningChannelError {
                            request_id,
                            error_code: ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        return Ok(vec![(
                            downstream_id,
                            Mining::OpenMiningChannelError(open_extended_mining_channel_error),
                        )
                            .into()]);
                    }
                };

                downstream
                    .payout_mode
                    .set(Some(payout_mode.clone()))
                    .map_err(PoolError::shutdown)?;

                let channel_id = downstream.channel_id_factory.fetch_add(1, Ordering::SeqCst);
                let mut extended_channel = match ExtendedChannel::new_for_pool(
                    channel_id,
                    user_identity.to_string(),
                    extranonce_prefix,
                    requested_max_target,
                    nominal_hash_rate,
                    true, // version rolling always allowed
                    CLIENT_SEARCH_SPACE_BYTES as u16,
                    self.share_batch_size,
                    self.shares_per_minute,
                    self.pool_tag_string.clone(),
                ) {
                    Ok(channel) => channel,
                    Err(e) => match e {
                        ExtendedChannelError::OpenChannelInvalidNominalHashrate(code) => {
                            error!("OpenMiningChannelError: {}", code);
                            let open_extended_mining_channel_error = OpenMiningChannelError {
                                request_id,
                                error_code: code
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            return Ok(vec![(
                                downstream_id,
                                Mining::OpenMiningChannelError(open_extended_mining_channel_error),
                            )
                                .into()]);
                        }
                        ExtendedChannelError::RequestedMinExtranonceSizeTooLarge(code) => {
                            error!("OpenMiningChannelError: {}", code);
                            let open_extended_mining_channel_error = OpenMiningChannelError {
                                request_id,
                                error_code: code
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            return Ok(vec![(
                                downstream_id,
                                Mining::OpenMiningChannelError(open_extended_mining_channel_error),
                            )
                                .into()]);
                        }
                        e => {
                            error!("error in handle_open_extended_mining_channel: {:?}", e);
                            return Err(PoolError::disconnect(e, downstream_id));
                        }
                    },
                };
                if let Some(payout) = gridpool_payout.clone() {
                    self.gridpool_channels.insert((downstream_id, channel_id), payout);
                }

                let group_channel_id = downstream
                    .group_channel
                    .with(|channel| channel.get_group_channel_id())
                    .map_err(PoolError::shutdown)?;

                let open_extended_mining_channel_success = OpenExtendedMiningChannelSuccess {
                    request_id,
                    channel_id,
                    target: extended_channel.get_target().to_le_bytes().into(),
                    extranonce_prefix: extended_channel
                        .get_extranonce_prefix()
                        .to_vec()
                        .try_into()
                        .map_err(PoolError::shutdown)?,
                    extranonce_size: extended_channel.get_rollable_extranonce_size(),
                    group_channel_id,
                }
                .into_static();
                info!("Sending OpenExtendedMiningChannel.Success (downstream_id: {downstream_id}): {open_extended_mining_channel_success}");

                messages.push(
                    (
                        downstream_id,
                        Mining::OpenExtendedMiningChannelSuccess(
                            open_extended_mining_channel_success,
                        ),
                    )
                        .into(),
                );

                let Some(last_set_new_prev_hash_tdp) =
                    self.last_new_prev_hash.get().map_err(PoolError::shutdown)?
                else {
                    return Err(PoolError::disconnect(
                        PoolErrorKind::LastNewPrevhashNotFound,
                        downstream_id,
                    ));
                };

                let Some(last_future_template) = self
                    .last_future_template
                    .get()
                    .map_err(PoolError::shutdown)?
                else {
                    return Err(PoolError::disconnect(
                        PoolErrorKind::FutureTemplateNotPresent,
                        downstream_id,
                    ));
                };

                // if the client requires custom work, we don't need to send any extended
                // jobs so we just process the SetNewPrevHash
                // message
                if downstream.requires_custom_work.load(Ordering::SeqCst) {
                    extended_channel
                        .on_set_new_prev_hash(last_set_new_prev_hash_tdp)
                        .map_err(PoolError::shutdown)?;
                    // if the client does not require custom work, we need to send the
                    // future extended job
                    // and the SetNewPrevHash message
                } else {
                    let coinbase_outputs = match (&self.gridpool, &gridpool_payout) {
                        (Some(gridpool), Some(payout)) => gridpool
                            .coinbase_outputs(payout, last_future_template.coinbase_tx_value_remaining)
                            .map_err(|e| PoolError::disconnect(PoolErrorKind::Configuration(e), downstream_id))?,
                        _ => payout_mode.coinbase_outputs(
                            last_future_template.coinbase_tx_value_remaining,
                            &self.coinbase_reward_script,
                        ),
                    };

                    extended_channel
                        .on_new_template(last_future_template.clone(), coinbase_outputs)
                        .map_err(PoolError::shutdown)?;

                    let future_extended_job_id = extended_channel
                        .get_future_job_id_from_template_id(last_future_template.template_id)
                        .expect("future job id must exist");
                    let future_extended_job = extended_channel
                        .get_future_job(future_extended_job_id)
                        .expect("future job must exist");

                    let future_extended_job_message =
                        future_extended_job.get_job_message().clone().into_static();

                    // send this future job as new job message
                    // to be immediately activated with the subsequent SetNewPrevHash
                    // message
                    messages.push(
                        (
                            downstream_id,
                            Mining::NewExtendedMiningJob(future_extended_job_message),
                        )
                            .into(),
                    );

                    // SetNewPrevHash message activates the future job
                    let prev_hash = last_set_new_prev_hash_tdp.prev_hash.clone();
                    let header_timestamp = last_set_new_prev_hash_tdp.header_timestamp;
                    let n_bits = last_set_new_prev_hash_tdp.n_bits;
                    let set_new_prev_hash_mining = SetNewPrevHash {
                        channel_id,
                        job_id: future_extended_job_id,
                        prev_hash,
                        min_ntime: header_timestamp,
                        nbits: n_bits,
                    };

                    extended_channel
                        .on_set_new_prev_hash(last_set_new_prev_hash_tdp)
                        .map_err(PoolError::shutdown)?;

                    messages.push(
                        (
                            downstream_id,
                            Mining::SetNewPrevHash(set_new_prev_hash_mining),
                        )
                            .into(),
                    );

                    let full_extranonce_size = extended_channel.get_full_extranonce_size();
                    downstream
                        .group_channel
                        .with(|channel| channel.add_channel_id(channel_id, full_extranonce_size))
                        .map_err(PoolError::shutdown)?
                        .map_err(|e| {
                            error!("Failed to add channel id to group channel: {:?}", e);
                            PoolError::shutdown(e)
                        })?;
                }

                downstream
                    .extended_channels
                    .insert(channel_id, extended_channel);
                let vardiff = VardiffState::new().map_err(PoolError::shutdown)?;
                self.vardiff
                    .insert((downstream_id, channel_id).into(), vardiff);

                Ok(messages)
            })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_io).await {
                error!("Failed to forward message {e:?}");
            }
        }
        Ok(())
    }

    async fn handle_submit_shares_standard(
        &mut self,
        client_id: Option<usize>,
        msg: SubmitSharesStandard,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received SubmitSharesStandard: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        let channel_id = msg.channel_id;
        let vardiff_key = (downstream_id, channel_id).into();
        let messages = self.with_registered_downstream(downstream_id, |downstream| {
                let messages = if !downstream.standard_channels.contains_key(&channel_id) {
                    let error = SubmitSharesError {
                        channel_id,
                        sequence_number: msg.sequence_number,
                        error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
                    vec![(downstream_id, Mining::SubmitSharesError(error)).into()]
                } else if !self.vardiff.contains_key(&vardiff_key) {
                    vec![(
                        downstream_id,
                        Mining::CloseChannel(create_close_channel_msg(
                            channel_id,
                            ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
                        )),
                    )
                        .into()]
                } else {
                    let validation =
                        downstream
                            .standard_channels
                            .with_mut(&channel_id, |standard_channel| {
                                let mut messages: Vec<RouteMessageTo> = Vec::new();
                                let res = standard_channel.validate_share(msg.clone());
                                if res.is_err() {
                                    if let (Some(gridpool), Some(payout)) = (
                                        self.gridpool.as_ref(),
                                        self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                    ) {
                                        gridpool.record_telemetry(TelemetryDelta {
                                            channel_id,
                                            payout_address: payout.payout_address,
                                            username: payout.username,
                                            accepted: false,
                                            ..Default::default()
                                        });
                                    }
                                }
                                match res {
                                    Ok(ShareValidationResult::Valid(share_hash)) => {
                                        if let (Some(gridpool), Some(payout)) = (
                                            self.gridpool.as_ref(),
                                            self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                        ) {
                                            let achieved_difficulty = Target::from_le_bytes(*share_hash.as_ref()).difficulty_float();
                                            let work_difficulty = standard_channel.get_target().difficulty_float();
                                            let fee_work = standard_channel.get_active_job()
                                                .map(|job| gridpool.is_fee_job(job.get_coinbase_outputs(), &payout))
                                                .unwrap_or(false);
                                            gridpool.record_telemetry(TelemetryDelta {
                                                channel_id,
                                                payout_address: payout.payout_address.clone(),
                                                username: payout.username.clone(),
                                                accepted: true,
                                                work_difficulty,
                                                achieved_difficulty,
                                                fee_work,
                                            });
                                            let channel_key = ((downstream_id as u64) << 32) | channel_id as u64;
                                            if gridpool.should_submit_proof(channel_key, achieved_difficulty, false) {
                                                if let Some(proof) = build_standard_gridpool_proof(
                                                    &self.pool_tag_string, standard_channel, &msg, &payout, achieved_difficulty,
                                                ) {
                                                    gridpool.submit_proof(proof);
                                                }
                                            }
                                        }
                                        let share_accounting = standard_channel.get_share_accounting();
                                        if share_accounting.should_acknowledge() {
                                            let success = SubmitSharesSuccess {
                                                channel_id,
                                                last_sequence_number: share_accounting
                                                    .get_last_share_sequence_number(),
                                                new_submits_accepted_count: share_accounting
                                                    .get_last_batch_accepted(),
                                                new_shares_sum: share_accounting
                                                    .get_last_batch_work_sum(),
                                            };
                                            info!("SubmitSharesStandard: {} ✅", success);
                                            messages.push(
                                                (downstream_id, Mining::SubmitSharesSuccess(success))
                                                    .into(),
                                            );
                                        } else {
                                            let share_work =
                                                standard_channel.get_target().difficulty_float();
                                            info!(
                                                "SubmitSharesStandard: valid share | downstream_id: {}, channel_id: {}, sequence_number: {}, share_hash: {}, share_work: {} ✅",
                                                downstream_id, channel_id, msg.sequence_number, share_hash, share_work
                                            );
                                        }
                                    }
                                    Ok(ShareValidationResult::BlockFound(
                                        share_hash,
                                        template_id,
                                        coinbase,
                                    )) => {
                                        if let (Some(gridpool), Some(payout)) = (
                                            self.gridpool.as_ref(),
                                            self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                        ) {
                                            let achieved_difficulty = Target::from_le_bytes(*share_hash.as_ref()).difficulty_float();
                                            let work_difficulty = standard_channel.get_target().difficulty_float();
                                            let fee_work = standard_channel.get_active_job()
                                                .map(|job| gridpool.is_fee_job(job.get_coinbase_outputs(), &payout))
                                                .unwrap_or(false);
                                            gridpool.record_telemetry(TelemetryDelta {
                                                channel_id,
                                                payout_address: payout.payout_address.clone(),
                                                username: payout.username.clone(),
                                                accepted: true,
                                                work_difficulty,
                                                achieved_difficulty,
                                                fee_work,
                                            });
                                            if let Some(proof) = build_standard_gridpool_proof(
                                                &self.pool_tag_string, standard_channel, &msg, &payout, achieved_difficulty,
                                            ) {
                                                gridpool.submit_proof(proof);
                                            }
                                        }
                                        info!("SubmitSharesStandard: 💰 Block Found!!! 💰{share_hash}");
                                        // if we have a template id (i.e.: this was not a custom job)
                                        // we can propagate the solution to the TP
                                        if let Some(template_id) = template_id {
                                            info!("SubmitSharesStandard: Propagating solution to the Template Provider.");
                                            let solution = SubmitSolution {
                                                template_id,
                                                version: msg.version,
                                                header_timestamp: msg.ntime,
                                                header_nonce: msg.nonce,
                                                coinbase_tx: coinbase
                                                    .try_into()
                                                    .map_err(PoolError::shutdown)?,
                                            };
                                            messages.push(
                                                TemplateDistribution::SubmitSolution(solution)
                                                    .into(),
                                            );
                                        }
                                        let share_accounting = standard_channel.get_share_accounting();
                                        let success = SubmitSharesSuccess {
                                            channel_id,
                                            last_sequence_number: share_accounting
                                                .get_last_share_sequence_number(),
                                            new_submits_accepted_count: share_accounting
                                                .get_last_batch_accepted(),
                                            new_shares_sum: share_accounting
                                                .get_last_batch_work_sum(),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesSuccess(success))
                                                .into(),
                                        );
                                    }
                                    Err(ShareValidationError::Invalid(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };

                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::Stale(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::InvalidJobId(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::DoesNotMeetTarget(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::DuplicateShare(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::VersionRollingNotAllowed(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(e) => {
                                        return Err(PoolError::disconnect(e, downstream_id));
                                    }
                                }

                                Ok(messages)
                            });
                    match validation {
                        Some(validation) => {
                            self.vardiff.with_mut(&vardiff_key, |vardiff| {
                                vardiff.increment_shares_since_last_update()
                            });
                            validation?
                        }
                        None => {
                            let submit_shares_error = SubmitSharesError {
                                channel_id,
                                sequence_number: msg.sequence_number,
                                error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
                            vec![(
                                downstream_id,
                                Mining::SubmitSharesError(submit_shares_error),
                            )
                                .into()]
                        }
                    }
                };

                Ok(messages)
            })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_io).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_submit_shares_extended(
        &mut self,
        client_id: Option<usize>,
        msg: SubmitSharesExtended<'_>,
        tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received SubmitSharesExtended: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        // Extract user_identity from TLV fields if the extension is negotiated
        let negotiated_extensions = self.get_negotiated_extensions_with_client(client_id);
        let user_identity = if negotiated_extensions
            .as_ref()
            .is_ok_and(|exts| exts.contains(&EXTENSION_TYPE_WORKER_HASHRATE_TRACKING))
        {
            tlv_fields.and_then(|tlvs| {
                tlvs.iter()
                    .find(|tlv| {
                        tlv.r#type.extension_type == EXTENSION_TYPE_WORKER_HASHRATE_TRACKING
                            && tlv.r#type.field_type == TLV_FIELD_TYPE_USER_IDENTITY
                    })
                    .and_then(|tlv| UserIdentity::from_tlv(tlv).ok())
            })
        } else {
            None
        };

        let channel_id = msg.channel_id;
        let vardiff_key = (downstream_id, channel_id).into();
        let messages = self.with_registered_downstream(downstream_id, |downstream| {
                let messages = if !downstream.extended_channels.contains_key(&channel_id) {
                    let error = SubmitSharesError {
                        channel_id,
                        sequence_number: msg.sequence_number,
                        error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
                    vec![(downstream_id, Mining::SubmitSharesError(error)).into()]
                } else if !self.vardiff.contains_key(&vardiff_key) {
                    vec![(
                        downstream_id,
                        Mining::CloseChannel(create_close_channel_msg(
                            channel_id,
                            ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
                        )),
                    )
                        .into()]
                } else {
                    if let Some(_user_identity) = user_identity {
                        // here we have the UserIdentity TLV, so we can use it to enhance monitoring of
                        // individual miners in the future
                    }
                    let validation =
                        downstream
                            .extended_channels
                            .with_mut(&channel_id, |extended_channel| {
                                let mut messages: Vec<RouteMessageTo> = Vec::new();
                                let res = extended_channel.validate_share(msg.clone());
                                if res.is_err() {
                                    if let (Some(gridpool), Some(payout)) = (
                                        self.gridpool.as_ref(),
                                        self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                    ) {
                                        gridpool.record_telemetry(TelemetryDelta {
                                            channel_id,
                                            payout_address: payout.payout_address,
                                            username: payout.username,
                                            accepted: false,
                                            ..Default::default()
                                        });
                                    }
                                }
                                match res {
                                    Ok(ShareValidationResult::Valid(share_hash)) => {
                                        if let (Some(gridpool), Some(payout)) = (
                                            self.gridpool.as_ref(),
                                            self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                        ) {
                                            let achieved_difficulty = Target::from_le_bytes(*share_hash.as_ref()).difficulty_float();
                                            let work_difficulty = extended_channel.get_target().difficulty_float();
                                            let fee_work = extended_channel.get_active_job()
                                                .map(|job| gridpool.is_fee_job(job.get_coinbase_outputs(), &payout))
                                                .unwrap_or(false);
                                            gridpool.record_telemetry(TelemetryDelta {
                                                channel_id,
                                                payout_address: payout.payout_address.clone(),
                                                username: payout.username.clone(),
                                                accepted: true,
                                                work_difficulty,
                                                achieved_difficulty,
                                                fee_work,
                                            });
                                            let channel_key = ((downstream_id as u64) << 32) | channel_id as u64;
                                            if gridpool.should_submit_proof(channel_key, achieved_difficulty, false) {
                                                if let Some(proof) = build_extended_gridpool_proof(
                                                    extended_channel, &msg, &payout, achieved_difficulty,
                                                ) { gridpool.submit_proof(proof); }
                                            }
                                        }
                                        let share_accounting = extended_channel.get_share_accounting();
                                        if share_accounting.should_acknowledge() {
                                            let success = SubmitSharesSuccess {
                                                channel_id,
                                                last_sequence_number: share_accounting
                                                    .get_last_share_sequence_number(),
                                                new_submits_accepted_count: share_accounting
                                                    .get_last_batch_accepted(),
                                                new_shares_sum: share_accounting
                                                    .get_last_batch_work_sum(),
                                            };
                                            info!("SubmitSharesExtended: {} ✅", success);
                                            messages.push(
                                                (downstream_id, Mining::SubmitSharesSuccess(success))
                                                    .into(),
                                            );
                                        } else {
                                            let share_work =
                                                extended_channel.get_target().difficulty_float();
                                            info!(
                                                "SubmitSharesExtended: valid share | downstream_id: {}, channel_id: {}, sequence_number: {}, share_hash: {}, share_work: {} ✅",
                                                downstream_id, channel_id, msg.sequence_number, share_hash, share_work
                                            );
                                        }
                                    }
                                    Ok(ShareValidationResult::BlockFound(
                                        share_hash,
                                        template_id,
                                        coinbase,
                                    )) => {
                                        if let (Some(gridpool), Some(payout)) = (
                                            self.gridpool.as_ref(),
                                            self.gridpool_channels.get_cloned(&(downstream_id, channel_id)),
                                        ) {
                                            let achieved_difficulty = Target::from_le_bytes(*share_hash.as_ref()).difficulty_float();
                                            let work_difficulty = extended_channel.get_target().difficulty_float();
                                            let fee_work = extended_channel.get_active_job()
                                                .map(|job| gridpool.is_fee_job(job.get_coinbase_outputs(), &payout))
                                                .unwrap_or(false);
                                            gridpool.record_telemetry(TelemetryDelta {
                                                channel_id,
                                                payout_address: payout.payout_address.clone(),
                                                username: payout.username.clone(),
                                                accepted: true,
                                                work_difficulty,
                                                achieved_difficulty,
                                                fee_work,
                                            });
                                            if let Some(proof) = build_extended_gridpool_proof(
                                                extended_channel, &msg, &payout, achieved_difficulty,
                                            ) { gridpool.submit_proof(proof); }
                                        }
                                        info!("SubmitSharesExtended: 💰 Block Found!!! 💰{share_hash}");
                                        if let Some(template_id) = template_id {
                                            info!("SubmitSharesExtended: Propagating solution to the Template Provider.");
                                            let solution = SubmitSolution {
                                                template_id,
                                                version: msg.version,
                                                header_timestamp: msg.ntime,
                                                header_nonce: msg.nonce,
                                                coinbase_tx: coinbase
                                                    .try_into()
                                                    .map_err(PoolError::shutdown)?,
                                            };
                                            messages.push(
                                                TemplateDistribution::SubmitSolution(solution)
                                                    .into(),
                                            );
                                        }
                                        let share_accounting = extended_channel.get_share_accounting();
                                        let success = SubmitSharesSuccess {
                                            channel_id,
                                            last_sequence_number: share_accounting
                                                .get_last_share_sequence_number(),
                                            new_submits_accepted_count: share_accounting
                                                .get_last_batch_accepted(),
                                            new_shares_sum: share_accounting
                                                .get_last_batch_work_sum(),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesSuccess(success))
                                                .into(),
                                        );
                                    }
                                    Err(ShareValidationError::Invalid(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::Stale(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::InvalidJobId(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::DoesNotMeetTarget(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::DuplicateShare(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::BadExtranonceSize(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(ShareValidationError::VersionRollingNotAllowed(code)) => {
                                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, code);
                                        let error = SubmitSharesError {
                                            channel_id: msg.channel_id,
                                            sequence_number: msg.sequence_number,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (downstream_id, Mining::SubmitSharesError(error)).into(),
                                        );
                                    }
                                    Err(e) => {
                                        return Err(PoolError::disconnect(e, downstream_id));
                                    }
                                }

                                Ok(messages)
                            });
                    match validation {
                        Some(validation) => {
                            self.vardiff.with_mut(&vardiff_key, |vardiff| {
                                vardiff.increment_shares_since_last_update()
                            });
                            validation?
                        }
                        None => {
                            let error = SubmitSharesError {
                                channel_id,
                                sequence_number: msg.sequence_number,
                                error_code: ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: {} ❌", downstream_id, channel_id, msg.sequence_number, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
                            vec![(downstream_id, Mining::SubmitSharesError(error)).into()]
                        }
                    }
                };

                Ok(messages)
            })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_io).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_update_channel(
        &mut self,
        client_id: Option<usize>,
        msg: UpdateChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        let channel_id = msg.channel_id;
        let new_nominal_hash_rate = msg.nominal_hash_rate;
        let requested_maximum_target = Target::from_le_bytes(msg.maximum_target.to_array());
        let messages = self.with_registered_downstream(downstream_id, |downstream| {
            let mut messages: Vec<RouteMessageTo> = Vec::new();

            if downstream
                .standard_channels
                .with_mut(&channel_id, |standard_channel| {
                    let res = standard_channel
                        .update_channel(new_nominal_hash_rate, Some(requested_maximum_target));
                    match res {
                        Ok(_) => {}
                        Err(e) => {
                            error!("UpdateChannelError: {:?}", e);
                            match e {
                                StandardChannelError::UpdateChannelInvalidNominalHashrate(code) => {
                                    error!("UpdateChannelError: {}", code);
                                    let update_channel_error = UpdateChannelError {
                                        channel_id,
                                        error_code: code
                                            .to_string()
                                            .try_into()
                                            .expect("error code must be valid string"),
                                    };
                                    messages.push(
                                        (
                                            downstream_id,
                                            Mining::UpdateChannelError(update_channel_error),
                                        )
                                            .into(),
                                    );
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    let new_target = standard_channel.get_target();
                    let set_target = SetTarget {
                        channel_id,
                        maximum_target: new_target.to_le_bytes().into(),
                    };
                    messages.push((downstream_id, Mining::SetTarget(set_target)).into());
                })
                .is_none()
                && downstream
                    .extended_channels
                    .with_mut(&channel_id, |extended_channel| {
                        let res = extended_channel
                            .update_channel(new_nominal_hash_rate, Some(requested_maximum_target));
                        match res {
                            Ok(_) => {}
                            Err(e) => {
                                error!("UpdateChannelError: {:?}", e);
                                match e {
                                    ExtendedChannelError::UpdateChannelInvalidNominalHashrate(
                                        code,
                                    ) => {
                                        error!("UpdateChannelError: {}", code);
                                        let update_channel_error = UpdateChannelError {
                                            channel_id,
                                            error_code: code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                        messages.push(
                                            (
                                                downstream_id,
                                                Mining::UpdateChannelError(update_channel_error),
                                            )
                                                .into(),
                                        );
                                    }
                                    _ => unreachable!(),
                                }
                            }
                        }
                        let new_target = extended_channel.get_target();
                        let set_target = SetTarget {
                            channel_id,
                            maximum_target: new_target.to_le_bytes().into(),
                        };
                        messages.push((downstream_id, Mining::SetTarget(set_target)).into());
                    })
                    .is_none()
            {
                error!("UpdateChannelError: invalid-channel-id");
                let update_channel_error = UpdateChannelError {
                    channel_id,
                    error_code: ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID
                        .to_string()
                        .try_into()
                        .expect("error code must be valid string"),
                };
                messages.push(
                    (
                        downstream_id,
                        Mining::UpdateChannelError(update_channel_error),
                    )
                        .into(),
                );
            }

            Ok(messages)
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_io).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_set_custom_mining_job(
        &mut self,
        client_id: Option<usize>,
        msg: SetCustomMiningJob<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        let Some(ref mut job_declarator) = self.job_declarator else {
            let error = SetCustomMiningJobError {
                request_id: msg.request_id,
                channel_id: msg.channel_id,
                error_code: ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED
                    .to_string()
                    .try_into()
                    .expect("error code must be valid string"),
            };
            let message: RouteMessageTo =
                (downstream_id, Mining::SetCustomMiningJobError(error)).into();
            message
                .forward(&self.channel_manager_io)
                .await
                .map_err(|e| PoolError::disconnect(e, downstream_id))?;
            return Ok(());
        };

        let msg_static = msg.clone().into_static();

        // Step 1: Validate the custom job via JDS (token + job validation).
        let jds_response = job_declarator
            .handle_set_custom_mining_job(msg_static.clone(), _tlv_fields)
            .await
            .map_err(|e| PoolError::shutdown(PoolErrorKind::Jds(e.into())))?;

        if let SetCustomMiningJobResponse::Error(jds_err) = jds_response {
            let message: RouteMessageTo = (
                downstream_id,
                Mining::SetCustomMiningJobError(jds_err.into_static()),
            )
                .into();
            message
                .forward(&self.channel_manager_io)
                .await
                .map_err(|e| PoolError::disconnect(e, downstream_id))?;
            return Ok(());
        }

        // Step 2: JDS validated successfully — commit the job to the extended channel.
        let message: RouteMessageTo =
            self.with_registered_downstream(downstream_id, |downstream| {
                match downstream.extended_channels.with_mut(
                    &msg_static.channel_id,
                    |extended_channel| {
                        let job_id = extended_channel
                            .on_set_custom_mining_job(msg_static.clone())
                            .map_err(|error| PoolError::disconnect(error, downstream_id))?;

                        let success = SetCustomMiningJobSuccess {
                            channel_id: msg_static.channel_id,
                            request_id: msg_static.request_id,
                            job_id,
                        };
                        Ok((downstream_id, Mining::SetCustomMiningJobSuccess(success)).into())
                    },
                ) {
                    Some(message) => message,
                    None => {
                        error!("SetCustomMiningJobError: invalid-channel-id");
                        let error = SetCustomMiningJobError {
                            request_id: msg_static.request_id,
                            channel_id: msg_static.channel_id,
                            error_code: ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_CHANNEL_ID
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        Ok((downstream_id, Mining::SetCustomMiningJobError(error)).into())
                    }
                }
            })?;

        message
            .forward(&self.channel_manager_io)
            .await
            .map_err(|e| PoolError::disconnect(e, downstream_id))?;

        Ok(())
    }
}
