use std::{
    collections::HashMap,
    fs,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stratum_apps::{
    bitcoin_core_sv2::common::template_distribution_protocol::CancellationToken,
    stratum_core::{
        binary_sv2::{Seq0255, Seq064K, B016M, B0255, B064K, U256},
        bitcoin::{
            block::{Header, Version},
            consensus::{deserialize, serialize},
            hashes::{sha256d, Hash, HashEngine},
            script::Builder,
            Block, BlockHash, CompactTarget, ScriptBuf, Target, Transaction, TxOut, Txid, Wtxid,
        },
        parsers_sv2::TemplateDistribution,
        template_distribution_sv2::{
            CoinbaseOutputConstraints, NewTemplate, RequestTransactionData,
            RequestTransactionDataError, RequestTransactionDataSuccess, SetNewPrevHash,
            SubmitSolution, ERROR_CODE_REQUEST_TRANSACTION_DATA_STALE_TEMPLATE_ID,
            ERROR_CODE_REQUEST_TRANSACTION_DATA_TEMPLATE_ID_NOT_FOUND,
        },
    },
    task_manager::TaskManager,
};
use tracing::{error, info, warn};

const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
const MIN_BLOCK_RESERVED_WEIGHT: u64 = 2_000;
const MAX_RETAINED_TEMPLATES: usize = 32;

#[derive(Clone, Debug)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie_file: Option<std::path::PathBuf>,
    pub timeout_seconds: u64,
    pub retry_seconds: u64,
    pub min_interval: u8,
}

#[derive(Clone)]
pub struct BitcoinRpcTemplateProvider {
    rpc: RpcClient,
    incoming: Receiver<TemplateDistribution<'static>>,
    outgoing: Sender<TemplateDistribution<'static>>,
    cancellation_token: CancellationToken,
    retry_delay: Duration,
    min_interval: Duration,
    next_template_id: Arc<AtomicU64>,
    templates: Arc<tokio::sync::RwLock<HashMap<u64, RpcTemplate>>>,
}

#[derive(Clone)]
struct RpcClient {
    url: String,
    username: Option<String>,
    password: Option<String>,
    client: Client,
    next_request_id: Arc<AtomicU64>,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    result: Value,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GetBlockTemplate {
    version: i32,
    previousblockhash: String,
    transactions: Vec<GetBlockTemplateTransaction>,
    #[serde(default)]
    coinbaseaux: CoinbaseAux,
    coinbasevalue: u64,
    #[serde(default)]
    longpollid: Option<String>,
    mintime: u32,
    curtime: u32,
    bits: String,
    height: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct GetBlockTemplateTransaction {
    data: String,
    txid: String,
    hash: String,
    #[serde(default)]
    weight: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CoinbaseAux {
    #[serde(default)]
    flags: String,
}

#[derive(Clone)]
struct RpcTemplate {
    id: u64,
    prev_hash: BlockHash,
    version: u32,
    curtime: u32,
    mintime: u32,
    bits: CompactTarget,
    target: Target,
    coinbase_prefix: Vec<u8>,
    coinbase_value: u64,
    required_outputs: Vec<TxOut>,
    transactions: Vec<Transaction>,
    transaction_bytes: Vec<Vec<u8>>,
    merkle_path: Vec<[u8; 32]>,
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

impl RpcClient {
    fn new(config: &BitcoinRpcConfig) -> Result<Self, String> {
        let (username, password) = if let Some(cookie_file) = &config.cookie_file {
            let cookie = fs::read_to_string(cookie_file).map_err(|error| {
                format!(
                    "failed to read Bitcoin RPC cookie {}: {error}",
                    cookie_file.display()
                )
            })?;
            let (user, pass) = cookie.trim().split_once(':').ok_or_else(|| {
                format!(
                    "Bitcoin RPC cookie {} is not in username:password form",
                    cookie_file.display()
                )
            })?;
            (Some(user.to_owned()), Some(pass.to_owned()))
        } else {
            (config.username.clone(), config.password.clone())
        };

        if username.is_some() != password.is_some() {
            return Err(
                "Bitcoin RPC username and password must be configured together".to_string(),
            );
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds.max(10)))
            .build()
            .map_err(|error| format!("failed to build Bitcoin RPC client: {error}"))?;

        Ok(Self {
            url: config.url.clone(),
            username,
            password,
            client,
            next_request_id: Arc::new(AtomicU64::new(1)),
        })
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, String> {
        let request = RpcRequest {
            jsonrpc: "1.0",
            id: self.next_request_id.fetch_add(1, Ordering::Relaxed),
            method,
            params,
        };
        let mut http = self.client.post(&self.url).json(&request);
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            http = http.basic_auth(username, Some(password));
        }

        let response = http
            .send()
            .await
            .map_err(|error| format!("Bitcoin RPC {method} transport failure: {error}"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("Bitcoin RPC {method} response read failure: {error}"))?;
        let envelope: RpcEnvelope = serde_json::from_slice(&body).map_err(|error| {
            format!("Bitcoin RPC {method} returned HTTP {status} with invalid JSON: {error}")
        })?;

        if let Some(rpc_error) = envelope.error {
            return Err(format!(
                "Bitcoin RPC {method} error {}: {}",
                rpc_error.code, rpc_error.message
            ));
        }
        serde_json::from_value(envelope.result)
            .map_err(|error| format!("Bitcoin RPC {method} returned an invalid result: {error}"))
    }

    async fn get_block_template(
        &self,
        longpollid: Option<&str>,
    ) -> Result<GetBlockTemplate, String> {
        let mut request = json!({
            "rules": ["segwit"],
            "capabilities": ["longpoll", "coinbasevalue", "workid"]
        });
        if let Some(longpollid) = longpollid {
            request["longpollid"] = Value::String(longpollid.to_string());
        }
        self.call("getblocktemplate", json!([request])).await
    }

    async fn submit_block(&self, block: &Block) -> Result<(), String> {
        let result: Option<String> = self
            .call("submitblock", json!([hex::encode(serialize(block))]))
            .await?;
        match result {
            None => Ok(()),
            Some(reason) => Err(format!("Bitcoin node rejected solved block: {reason}")),
        }
    }
}

impl BitcoinRpcTemplateProvider {
    pub fn new(
        config: BitcoinRpcConfig,
        incoming: Receiver<TemplateDistribution<'static>>,
        outgoing: Sender<TemplateDistribution<'static>>,
        cancellation_token: CancellationToken,
    ) -> Result<Self, String> {
        Ok(Self {
            rpc: RpcClient::new(&config)?,
            incoming,
            outgoing,
            cancellation_token,
            retry_delay: Duration::from_secs(config.retry_seconds.max(1)),
            min_interval: Duration::from_secs(config.min_interval as u64),
            next_template_id: Arc::new(AtomicU64::new(1)),
            templates: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }

    pub fn start(self, task_manager: Arc<TaskManager>) {
        task_manager.spawn(async move {
            self.run().await;
        });
    }

    async fn run(self) {
        info!("Bitcoin JSON-RPC template provider waiting for coinbase constraints");
        let mut constraints = None;
        let mut longpollid = None;
        let mut current_prev_hash = None;
        let mut last_non_tip_publish = None;

        loop {
            if self.cancellation_token.is_cancelled() {
                break;
            }

            if constraints.is_none() {
                match self.incoming.recv().await {
                    Ok(TemplateDistribution::CoinbaseOutputConstraints(value)) => {
                        constraints = Some(value);
                    }
                    Ok(other) => {
                        warn!("Ignoring {other} until coinbase constraints are available");
                        continue;
                    }
                    Err(_) => break,
                }

                match self
                    .refresh_template(
                        constraints.as_ref().expect("constraints were just set"),
                        None,
                        true,
                        true,
                    )
                    .await
                {
                    Ok(template) => {
                        current_prev_hash = Some(template.prev_hash);
                        longpollid = template.longpollid;
                    }
                    Err(error) => {
                        warn!("{error}; retrying Bitcoin RPC");
                        tokio::time::sleep(self.retry_delay).await;
                        constraints = None;
                    }
                }
                continue;
            }

            let rpc = self.rpc.clone();
            let poll_id = longpollid.clone();
            tokio::select! {
                _ = self.cancellation_token.cancelled() => break,
                incoming = self.incoming.recv() => {
                    match incoming {
                        Ok(TemplateDistribution::CoinbaseOutputConstraints(value)) => {
                            constraints = Some(value);
                            match self.refresh_template(
                                constraints.as_ref().expect("constraints were just set"),
                                None,
                                true,
                                true,
                            ).await {
                                Ok(template) => {
                                    current_prev_hash = Some(template.prev_hash);
                                    longpollid = template.longpollid;
                                }
                                Err(error) => warn!("{error}"),
                            }
                        }
                        Ok(TemplateDistribution::RequestTransactionData(request)) => {
                            if let Err(error) = self.handle_request_transaction_data(request).await {
                                warn!("{error}");
                            }
                        }
                        Ok(TemplateDistribution::SubmitSolution(solution)) => {
                            if let Err(error) = self.handle_submit_solution(solution).await {
                                error!("{error}");
                            }
                        }
                        Ok(other) => warn!("Ignoring unsupported TDP message from pool: {other}"),
                        Err(_) => break,
                    }
                }
                response = rpc.get_block_template(poll_id.as_deref()) => {
                    match response {
                        Ok(gbt) => {
                            let prev_hash = match BlockHash::from_str(&gbt.previousblockhash) {
                                Ok(hash) => hash,
                                Err(error) => {
                                    warn!("Bitcoin RPC returned invalid previousblockhash: {error}");
                                    continue;
                                }
                            };
                            let tip_changed = current_prev_hash != Some(prev_hash);
                            let throttled = !tip_changed
                                && last_non_tip_publish
                                    .is_some_and(|last: Instant| last.elapsed() < self.min_interval);

                            longpollid = gbt.longpollid.clone();
                            if throttled {
                                continue;
                            }

                            match self.publish_gbt(
                                constraints.as_ref().expect("constraints are initialized"),
                                gbt,
                                tip_changed,
                                tip_changed,
                            ).await {
                                Ok(template) => {
                                    current_prev_hash = Some(template.prev_hash);
                                    if !tip_changed {
                                        last_non_tip_publish = Some(Instant::now());
                                    }
                                }
                                Err(error) => warn!("{error}"),
                            }
                        }
                        Err(error) => {
                            warn!("{error}; retrying Bitcoin RPC in {}s", self.retry_delay.as_secs());
                            tokio::time::sleep(self.retry_delay).await;
                        }
                    }
                }
            }
        }
        info!("Bitcoin JSON-RPC template provider stopped");
    }

    async fn refresh_template(
        &self,
        constraints: &CoinbaseOutputConstraints,
        longpollid: Option<&str>,
        future_template: bool,
        send_prev_hash: bool,
    ) -> Result<PublishedTemplate, String> {
        let gbt = self.rpc.get_block_template(longpollid).await?;
        self.publish_gbt(constraints, gbt, future_template, send_prev_hash)
            .await
    }

    async fn publish_gbt(
        &self,
        constraints: &CoinbaseOutputConstraints,
        gbt: GetBlockTemplate,
        future_template: bool,
        send_prev_hash: bool,
    ) -> Result<PublishedTemplate, String> {
        let longpollid = gbt.longpollid.clone();
        let template = RpcTemplate::from_gbt(
            self.next_template_id.fetch_add(1, Ordering::Relaxed),
            gbt,
            constraints,
        )?;
        let new_template = template.new_template(future_template)?;
        let set_new_prev_hash = template.set_new_prev_hash();

        {
            let mut templates = self.templates.write().await;
            templates.insert(template.id, template.clone());
            if templates.len() > MAX_RETAINED_TEMPLATES {
                let mut ids = templates.keys().copied().collect::<Vec<_>>();
                ids.sort_unstable();
                for id in ids
                    .into_iter()
                    .take(templates.len() - MAX_RETAINED_TEMPLATES)
                {
                    templates.remove(&id);
                }
            }
        }

        self.outgoing
            .send(TemplateDistribution::NewTemplate(new_template))
            .await
            .map_err(|error| format!("failed to publish RPC NewTemplate: {error}"))?;
        if send_prev_hash {
            self.outgoing
                .send(TemplateDistribution::SetNewPrevHash(set_new_prev_hash))
                .await
                .map_err(|error| format!("failed to publish RPC SetNewPrevHash: {error}"))?;
        }

        info!(
            template_id = template.id,
            prev_hash = %template.prev_hash,
            transactions = template.transactions.len(),
            "Published Bitcoin JSON-RPC template"
        );
        Ok(PublishedTemplate {
            prev_hash: template.prev_hash,
            longpollid,
        })
    }

    async fn handle_request_transaction_data(
        &self,
        request: RequestTransactionData,
    ) -> Result<(), String> {
        let templates = self.templates.read().await;
        let response = match templates.get(&request.template_id) {
            Some(template) => {
                let txs = template
                    .transaction_bytes
                    .iter()
                    .cloned()
                    .map(|bytes| {
                        B016M::try_from(bytes)
                            .map_err(|_| "transaction is too large for SV2 B016M".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                TemplateDistribution::RequestTransactionDataSuccess(RequestTransactionDataSuccess {
                    template_id: request.template_id,
                    transaction_list: Seq064K::new(txs)
                        .map_err(|_| "too many transactions for SV2 Seq064K".to_string())?,
                    excess_data: B064K::try_from(Vec::new()).expect("an empty B064K must be valid"),
                })
            }
            None => {
                let stale = templates
                    .keys()
                    .max()
                    .is_some_and(|latest| request.template_id < *latest);
                TemplateDistribution::RequestTransactionDataError(RequestTransactionDataError {
                    template_id: request.template_id,
                    error_code: if stale {
                        ERROR_CODE_REQUEST_TRANSACTION_DATA_STALE_TEMPLATE_ID
                    } else {
                        ERROR_CODE_REQUEST_TRANSACTION_DATA_TEMPLATE_ID_NOT_FOUND
                    }
                    .to_string()
                    .try_into()
                    .expect("static error code must be valid"),
                })
            }
        };
        drop(templates);

        self.outgoing
            .send(response)
            .await
            .map_err(|error| format!("failed to send RPC transaction data response: {error}"))
    }

    async fn handle_submit_solution(
        &self,
        solution: SubmitSolution<'static>,
    ) -> Result<(), String> {
        let template = self
            .templates
            .read()
            .await
            .get(&solution.template_id)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "solution references unknown template {}",
                    solution.template_id
                )
            })?;
        let block = template.solution_block(solution)?;
        self.rpc.submit_block(&block).await?;
        info!(block_hash = %block.block_hash(), "Submitted solved SV2 block through Bitcoin RPC");
        Ok(())
    }
}

struct PublishedTemplate {
    prev_hash: BlockHash,
    longpollid: Option<String>,
}

impl RpcTemplate {
    fn from_gbt(
        id: u64,
        gbt: GetBlockTemplate,
        constraints: &CoinbaseOutputConstraints,
    ) -> Result<Self, String> {
        let prev_hash = BlockHash::from_str(&gbt.previousblockhash)
            .map_err(|error| format!("invalid GBT previousblockhash: {error}"))?;
        let bits_value = u32::from_str_radix(&gbt.bits, 16)
            .map_err(|error| format!("invalid GBT bits: {error}"))?;
        let bits = CompactTarget::from_consensus(bits_value);
        let target = Target::from(bits);

        let reserved_weight = (constraints.coinbase_output_max_additional_size as u64 * 4)
            .max(MIN_BLOCK_RESERVED_WEIGHT);
        let transaction_budget = MAX_BLOCK_WEIGHT.saturating_sub(reserved_weight);
        let selected_count = select_transaction_prefix(&gbt.transactions, transaction_budget);
        if selected_count < gbt.transactions.len() {
            warn!(
                removed = gbt.transactions.len() - selected_count,
                reserved_weight,
                "Trimmed low-priority GBT transaction suffix for GridPool coinbase reserve"
            );
        }
        let selected = &gbt.transactions[..selected_count];

        let mut transactions = Vec::with_capacity(selected.len());
        let mut transaction_bytes = Vec::with_capacity(selected.len());
        let mut txids = Vec::with_capacity(selected.len());
        let mut wtxids = Vec::with_capacity(selected.len());
        for tx in selected {
            let bytes = hex::decode(&tx.data)
                .map_err(|error| format!("invalid GBT transaction hex: {error}"))?;
            let transaction: Transaction =
                deserialize(&bytes).map_err(|error| format!("invalid GBT transaction: {error}"))?;
            let declared_txid =
                Txid::from_str(&tx.txid).map_err(|error| format!("invalid GBT txid: {error}"))?;
            let declared_wtxid =
                Wtxid::from_str(&tx.hash).map_err(|error| format!("invalid GBT wtxid: {error}"))?;
            if transaction.compute_txid() != declared_txid
                || transaction.compute_wtxid() != declared_wtxid
            {
                return Err(format!("GBT transaction {} hash mismatch", tx.txid));
            }
            txids.push(declared_txid.to_byte_array());
            wtxids.push(declared_wtxid.to_byte_array());
            transaction_bytes.push(bytes);
            transactions.push(transaction);
        }

        let witness_commitment = witness_commitment_output(&wtxids);
        let mut coinbase_prefix = Builder::new()
            .push_int(gbt.height as i64)
            .into_script()
            .into_bytes();
        if !gbt.coinbaseaux.flags.is_empty() {
            coinbase_prefix.extend(
                hex::decode(&gbt.coinbaseaux.flags)
                    .map_err(|error| format!("invalid GBT coinbaseaux.flags: {error}"))?,
            );
        }
        if coinbase_prefix.len() > 100 {
            return Err("GBT coinbase script prefix exceeds consensus limit".to_string());
        }

        Ok(Self {
            id,
            prev_hash,
            version: gbt.version as u32,
            curtime: gbt.curtime,
            mintime: gbt.mintime,
            bits,
            target,
            coinbase_prefix,
            coinbase_value: gbt.coinbasevalue,
            required_outputs: vec![witness_commitment],
            transactions,
            transaction_bytes,
            merkle_path: coinbase_merkle_path(&txids),
        })
    }

    fn new_template(&self, future_template: bool) -> Result<NewTemplate<'static>, String> {
        let mut outputs = Vec::new();
        for output in &self.required_outputs {
            outputs.extend(serialize(output));
        }
        let merkle_path = self
            .merkle_path
            .iter()
            .copied()
            .map(U256::from)
            .collect::<Vec<_>>();

        Ok(NewTemplate {
            template_id: self.id,
            future_template,
            version: self.version,
            coinbase_tx_version: 2,
            coinbase_prefix: B0255::try_from(self.coinbase_prefix.clone())
                .map_err(|_| "coinbase prefix exceeds SV2 B0255".to_string())?,
            coinbase_tx_input_sequence: u32::MAX,
            coinbase_tx_value_remaining: self.coinbase_value,
            coinbase_tx_outputs_count: self.required_outputs.len() as u32,
            coinbase_tx_outputs: B064K::try_from(outputs)
                .map_err(|_| "required coinbase outputs exceed SV2 B064K".to_string())?,
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255::new(merkle_path)
                .map_err(|_| "coinbase merkle path exceeds SV2 Seq0255".to_string())?,
        }
        .into_static())
    }

    fn set_new_prev_hash(&self) -> SetNewPrevHash<'static> {
        SetNewPrevHash {
            template_id: self.id,
            prev_hash: U256::from(self.prev_hash.to_byte_array()),
            header_timestamp: self.curtime.max(self.mintime),
            n_bits: self.bits.to_consensus(),
            target: U256::from(self.target.to_le_bytes()),
        }
        .into_static()
    }

    fn solution_block(&self, solution: SubmitSolution<'static>) -> Result<Block, String> {
        let coinbase: Transaction = deserialize(&solution.coinbase_tx.to_owned_bytes())
            .map_err(|error| format!("invalid solved coinbase transaction: {error}"))?;
        let merkle_root =
            apply_merkle_path(coinbase.compute_txid().to_byte_array(), &self.merkle_path);
        let header = Header {
            version: Version::from_consensus(solution.version as i32),
            prev_blockhash: self.prev_hash,
            merkle_root: sha256d::Hash::from_byte_array(merkle_root).into(),
            time: solution.header_timestamp,
            bits: self.bits,
            nonce: solution.header_nonce,
        };
        header
            .validate_pow(self.target)
            .map_err(|error| format!("SV2 solution does not meet network target: {error}"))?;

        let mut txdata = Vec::with_capacity(self.transactions.len() + 1);
        txdata.push(coinbase);
        txdata.extend(self.transactions.clone());
        Ok(Block { header, txdata })
    }
}

fn select_transaction_prefix(transactions: &[GetBlockTemplateTransaction], budget: u64) -> usize {
    let mut used = 320_u64;
    for (index, tx) in transactions.iter().enumerate() {
        let weight = tx
            .weight
            .unwrap_or_else(|| hex::decode(&tx.data).map_or(0, |bytes| bytes.len() as u64 * 4));
        if used.saturating_add(weight) > budget {
            return index;
        }
        used = used.saturating_add(weight);
    }
    transactions.len()
}

fn coinbase_merkle_path(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut level = Vec::with_capacity(txids.len() + 1);
    level.push([0_u8; 32]);
    level.extend_from_slice(txids);
    merkle_path_for_first_leaf(level)
}

fn merkle_path_for_first_leaf(mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("nonempty merkle level"));
        }
        path.push(level[1]);
        level = level
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    path
}

fn apply_merkle_path(mut hash: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    for sibling in path {
        hash = hash_pair(hash, *sibling);
    }
    hash
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut engine = sha256d::Hash::engine();
    engine.input(&left);
    engine.input(&right);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

fn witness_commitment_output(wtxids: &[[u8; 32]]) -> TxOut {
    let mut leaves = Vec::with_capacity(wtxids.len() + 1);
    leaves.push([0_u8; 32]);
    leaves.extend_from_slice(wtxids);
    let witness_root = merkle_root(leaves);

    let mut engine = sha256d::Hash::engine();
    engine.input(&witness_root);
    engine.input(&[0_u8; 32]);
    let commitment = sha256d::Hash::from_engine(engine).to_byte_array();

    let mut script = Vec::with_capacity(38);
    script.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    script.extend_from_slice(&commitment);
    TxOut {
        value: stratum_apps::stratum_core::bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn merkle_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        return [0_u8; 32];
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("nonempty merkle level"));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_leaf_merkle_path_reconstructs_root() {
        let txids = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];
        let path = coinbase_merkle_path(&txids);
        let coinbase = [9_u8; 32];
        let reconstructed = apply_merkle_path(coinbase, &path);
        let mut full = vec![coinbase];
        full.extend(txids);
        assert_eq!(reconstructed, merkle_root(full));
    }

    #[test]
    fn transaction_selection_keeps_a_prefix() {
        let txs = vec![
            GetBlockTemplateTransaction {
                data: "00".to_string(),
                txid: String::new(),
                hash: String::new(),
                weight: Some(100),
            },
            GetBlockTemplateTransaction {
                data: "00".to_string(),
                txid: String::new(),
                hash: String::new(),
                weight: Some(200),
            },
        ];
        assert_eq!(select_transaction_prefix(&txs, 620), 2);
        assert_eq!(select_transaction_prefix(&txs, 500), 1);
    }

    #[test]
    fn witness_commitment_has_standard_prefix() {
        let output = witness_commitment_output(&[[7_u8; 32]]);
        assert_eq!(
            &output.script_pubkey.as_bytes()[..6],
            &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        );
    }

    #[test]
    fn rpc_null_result_deserializes_as_successful_optional_value() {
        let envelope: RpcEnvelope =
            serde_json::from_str(r#"{"result":null,"error":null,"id":1}"#).unwrap();
        let result: Option<String> = serde_json::from_value(envelope.result).unwrap();
        assert_eq!(result, None);
    }
}
