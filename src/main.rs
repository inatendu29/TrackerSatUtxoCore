use bitcoin::consensus::deserialize;
use bitcoin::{Block, Address, Network, TxOut, Txid};
use bitcoin::hashes::Hash;
use bitcoin::hash_types::BlockHash;
use rocksdb::{DB, Options, WriteBatch, Cache, BlockBasedOptions};
use std::fs::{File, read_to_string};
use std::io::{Read, Seek, SeekFrom, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};
use std::convert::TryInto;
use std::error::Error as StdError;
use std::sync::Arc;
use std::collections::HashMap;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Serialize, Deserialize};
use bincode;
use rayon::prelude::*;
use num_cpus;
use log;

use bitcoincore_rpc::{Auth, Client, RpcApi, Error as RpcError_};
use bitcoincore_rpc::jsonrpc;

// --- Définition de la structure de configuration ---
#[derive(Deserialize, Debug, Clone)]
struct Config {
    log_level: String,
    network: String,
    rpc_only_catchup: bool,
    bitcoin_data_dir: String,
    db_base_path: String,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    zmq_url: String,
    rocksdb: RocksDBConfig,
}
#[derive(Deserialize, Debug, Clone)]
struct RocksDBConfig {
    write_buffer_size_mb: usize,
    max_background_jobs: i32,
    cache_size_gb: usize,
}
#[derive(Clone, Debug)]
struct RpcConnectionConfig { 
    url: String,
    user: String,
    pass: String,
}
fn load_config(config_path: &Path) -> Result<Config, Box<dyn StdError>> {
    let content = read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file at {:?}: {}", config_path, e))?;
    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    Ok(config)
}

// --- Structures de Données ---
#[derive(Serialize, Deserialize, Debug, Clone)]
enum ScriptTypeInfo { P2pk, P2pkh, P2sh, P2wpkh, P2wsh, P2tr, OpReturn, MultiSig, Unknown, NonStandard }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TxOutputInfo { value: u64, script_pub_key_bytes: Option<Vec<u8>>, address: Option<String>, script_type: ScriptTypeInfo }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TxInputInfo { previous_output_txid: [u8; 32], previous_output_vout: u32, spent_output_value: Option<u64>, spent_output_address: Option<String>, spent_output_script_type: Option<ScriptTypeInfo> }
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TxInfo { block_height: u32, tx_version: i32, lock_time: u32, inputs: Vec<TxInputInfo>, outputs: Vec<TxOutputInfo>, is_coinbase: bool, inscription_type: Option<String> }

// --- État de l'indexeur ---
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct IndexerTipState { block_height: u32, block_hash_bytes: [u8; 32], file_index: u32, file_offset: u64 }
const INDEXER_TIP_KEY: &[u8] = b"indexer_tip_state_v8_no_scan";
const GENESIS_PROCESSED_FLAG_KEY: &[u8] = b"genesis_block_processed_v1";
impl IndexerTipState { 
    fn genesis(network: Network) -> Self { let gh = bitcoin::blockdata::constants::genesis_block(network).block_hash(); Self { block_height: 0, block_hash_bytes: gh.to_byte_array(), file_index: 0, file_offset: 0 } }
    fn to_bytes(&self) -> Vec<u8> { bincode::serialize(self).unwrap_or_default() }
    fn from_bytes(b: &[u8]) -> Option<Self> { if b.len()==(4+32+4+8){ let h=u32::from_le_bytes(b[0..4].try_into().ok()?); let hs:[u8;32]=b[4..36].try_into().ok()?; let f=u32::from_le_bytes(b[36..40].try_into().ok()?); let o=u64::from_le_bytes(b[40..48].try_into().ok()?); Some(Self{block_height:h, block_hash_bytes:hs, file_index:f, file_offset:o})} else {None} }
}

fn analyze_txout(tx_out: &TxOut, network: Network) -> TxOutputInfo {
    let script = &tx_out.script_pubkey; let script_bytes_vec = script.as_bytes().to_vec();
    let address: Option<String>;
    let script_type: ScriptTypeInfo;
    match Address::from_script(script, network) {
        Ok(addr_obj) => {
            address = Some(addr_obj.to_string());
            if script.is_p2pkh() { script_type = ScriptTypeInfo::P2pkh; }
            else if script.is_p2sh() { script_type = ScriptTypeInfo::P2sh; }
            else if script.is_witness_program() {
                if script.is_p2wpkh() { script_type = ScriptTypeInfo::P2wpkh; }
                else if script.is_p2wsh() { script_type = ScriptTypeInfo::P2wsh; }
                else if script.is_p2tr() { script_type = ScriptTypeInfo::P2tr; }
                else { script_type = ScriptTypeInfo::Unknown; }
            } else { script_type = ScriptTypeInfo::Unknown; }
        }
        Err(_) => {
            address = None;
            if script.is_op_return() || script.is_provably_unspendable() { script_type = ScriptTypeInfo::OpReturn; }
            else if script.is_p2pk() { script_type = ScriptTypeInfo::P2pk; }
            else if script.is_multisig() { script_type = ScriptTypeInfo::MultiSig; }
            else { script_type = ScriptTypeInfo::NonStandard; }
        }
    }
    let script_bytes_to_store = if address.is_some() { None } else { Some(script_bytes_vec) };
    TxOutputInfo { value: tx_out.value.to_sat(), script_pub_key_bytes: script_bytes_to_store, address, script_type }
}
fn detect_inscription_heuristic(witness_stack: &Vec<Vec<u8>>) -> Option<String> { 
    let ord_marker = b"ord"; let mut detected_type: Option<String> = None;
    for item in witness_stack { if item.windows(ord_marker.len()).any(|window| window == ord_marker) { let text_plain_marker = b"text/plain"; if item.windows(text_plain_marker.len()).any(|w| w == text_plain_marker) { detected_type = Some("text/plain".to_string()); break; } let png_marker = &[0x89, 0x50, 0x4E, 0x47]; if item.windows(png_marker.len()).any(|w| w == png_marker) { detected_type = Some("image/png".to_string()); break; } let jpeg_marker = &[0xff, 0xd8, 0xff]; if item.windows(jpeg_marker.len()).any(|w| w == jpeg_marker) { detected_type = Some("image/jpeg".to_string()); break; } let gif_marker = &[0x47, 0x49, 0x46]; if item.windows(gif_marker.len()).any(|w| w == gif_marker) { detected_type = Some("image/gif".to_string()); break; } if detected_type.is_none() { detected_type = Some("unknown".to_string()); } break; } }
    detected_type
}
fn create_utxo_spend_key(out_point: &bitcoin::OutPoint) -> Vec<u8> { let mut k = Vec::with_capacity(36); k.extend_from_slice(&out_point.txid.to_byte_array()); k.extend_from_slice(&out_point.vout.to_le_bytes()); k}
fn create_utxo_spend_value(spending_txid: &Txid, vin_index: u32) -> Vec<u8> { let mut v = Vec::with_capacity(36); v.extend_from_slice(&spending_txid.to_byte_array()); v.extend_from_slice(&vin_index.to_le_bytes()); v}

#[derive(Debug)]
struct BlockDataToWrite { tx_details_puts: Vec<(Vec<u8>, Vec<u8>)>, utxo_spends_puts: Vec<(Vec<u8>, Vec<u8>)>, height_hash_put: (Vec<u8>, Vec<u8>), hash_coinbase_put: (Vec<u8>, Vec<u8>), }

// --- Fonction de traitement de bloc ---
fn process_block_logic( db_tx_details_ro: Arc<DB>, block: &Block, block_height: u32, block_outputs_cache_arc: Arc<HashMap<Txid, Arc<Vec<TxOutputInfo>>>>,) -> Result<BlockDataToWrite, Box<dyn StdError + Send + Sync>> { 
    let block_hash = block.header.block_hash();
    let block_hash_bytes = block_hash.to_byte_array();
    let block_cache_clone = Arc::clone(&block_outputs_cache_arc);
    type ThreadResult = Result<(Txid, TxInfo, Vec<(Vec<u8>, Vec<u8>)>), Box<dyn StdError + Send + Sync>>;

    let results: Vec<ThreadResult> = block.txdata.par_iter().map({
        let db_tx_details_reader_for_thread = Arc::clone(&db_tx_details_ro);
        move |transaction| {
            let txid = transaction.txid(); let is_coinbase = transaction.is_coinbase();
            let mut inputs_info: Vec<TxInputInfo> = Vec::new(); let mut utxo_spends_for_tx: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            if !is_coinbase {
                for (vin_index, txin) in transaction.input.iter().enumerate() {
                    let prev_outpoint = txin.previous_output; let prev_txid = prev_outpoint.txid; let prev_vout = prev_outpoint.vout; let prev_txid_bytes = prev_txid.to_byte_array();
                    let mut input_info = TxInputInfo { previous_output_txid: prev_txid_bytes, previous_output_vout: prev_vout, spent_output_value: None, spent_output_address: None, spent_output_script_type: None }; let mut found_in_cache = false;
                    if let Some(cache) = block_cache_clone.get(&prev_txid) { if let Some(out) = cache.get(prev_vout as usize) { input_info.spent_output_value = Some(out.value); input_info.spent_output_address = out.address.clone(); input_info.spent_output_script_type = Some(out.script_type.clone()); found_in_cache = true; } }
                    if !found_in_cache {
                        match db_tx_details_reader_for_thread.get(&prev_txid_bytes) {
                            Ok(Some(bytes)) => { if let Ok(p_info) = bincode::deserialize::<TxInfo>(&bytes) { if let Some(o) = p_info.outputs.get(prev_vout as usize) { input_info.spent_output_value=Some(o.value); input_info.spent_output_address=o.address.clone(); input_info.spent_output_script_type=Some(o.script_type.clone()); } } }
                            Ok(None) => { log::warn!("[Block: {}][Tx: {}] Input {}:{}: Prev tx {} not found in DB_TX_DETAILS", block_height, txid, prev_txid, prev_vout, prev_txid); }
                            Err(e) => { log::error!("[Block: {}][Tx: {}] DB_TX_DETAILS error for input {}:{}: {}", block_height, txid, prev_txid, prev_vout, e); return Err(Box::new(e) as Box<dyn StdError + Send + Sync>); }
                        }
                    }
                    inputs_info.push(input_info); let utxo_spend_key = create_utxo_spend_key(&prev_outpoint); let utxo_spend_value = create_utxo_spend_value(&txid, vin_index as u32); utxo_spends_for_tx.push((utxo_spend_key, utxo_spend_value));
                }
            }
            let outputs_info_for_this_tx = block_cache_clone.get(&txid).cloned().map(|arc_vec| (*arc_vec).clone()).unwrap_or_default();
            let inscription_type_detected = transaction.input.get(0).map(|i| detect_inscription_heuristic(&i.witness.to_vec())).unwrap_or(None);
            let tx_info = TxInfo { block_height, tx_version: transaction.version.0, lock_time: transaction.lock_time.to_consensus_u32(), inputs: inputs_info, outputs: outputs_info_for_this_tx, is_coinbase, inscription_type: inscription_type_detected, };
            Ok((txid, tx_info, utxo_spends_for_tx))
        }
    }).collect();

    let mut block_data = BlockDataToWrite { tx_details_puts: Vec::new(), utxo_spends_puts: Vec::new(), height_hash_put: (Vec::new(), Vec::<u8>::new()), hash_coinbase_put: (Vec::new(), Vec::<u8>::new()), };
    let mut coinbase_txid_bytes : Option<[u8; 32]> = None;
    for result in results { 
        match result { 
            Ok((txid, tx_info, utxo_spends)) => { 
                let txid_bytes = txid.to_byte_array(); 
                match bincode::serialize(&tx_info) { 
                    Ok(tx_info_bytes) => { block_data.tx_details_puts.push((txid_bytes.to_vec(), tx_info_bytes)); block_data.utxo_spends_puts.extend(utxo_spends); if tx_info.is_coinbase { coinbase_txid_bytes = Some(txid_bytes); } } 
                    Err(e) => { log::error!("TxInfo serialization failed for {}: {}", txid, e); return Err(e as Box<dyn StdError + Send + Sync>); }
                }
            } 
            Err(e) => { log::error!("Error in parallel tx processing: {}", e); return Err(e); } 
        } 
    }
    let height_key = block_height.to_be_bytes().to_vec(); block_data.height_hash_put = (height_key, block_hash_bytes.to_vec());
    if let Some(cb_bytes) = coinbase_txid_bytes { block_data.hash_coinbase_put = (block_hash_bytes.to_vec(), cb_bytes.to_vec()); }
    else if block_height > 0 { log::error!("Coinbase TxID not found for block {}", block_height); return Err(format!("Coinbase TxID not found block {}", block_height).into()); }
    else { block_data.hash_coinbase_put = (block_hash_bytes.to_vec(), vec![]); }
    Ok(block_data)
}

// --- Fonction wrapper pour les appels RPC avec tentatives de reconnexion ---
fn rpc_call_with_retry<F, T>( rpc_cfg: &RpcConnectionConfig, current_rpc: &mut Arc<Client>, max_retries: u32, operation_description: &str, operation_fn: F,) -> Result<T, RpcError_> where F: Fn(&Client) -> Result<T, RpcError_>, {
    let mut attempts = 0;
    loop {
        match operation_fn(current_rpc.as_ref()) {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempts += 1;
                if attempts > max_retries {
                    log::error!("RPC operation '{}' failed after {} attempts. Last error: {}", operation_description, attempts, e);
                    return Err(e);
                }

                let mut is_transport_error = false;
                match &e {
                    RpcError_::JsonRpc(jsonrpc::error::Error::Transport(_)) => {
                        is_transport_error = true;
                        log::warn!("RPC call '{}' encountered JsonRpc::Transport error (attempt {}/{}): {}. Reconnecting...", operation_description, attempts, max_retries + 1, e);
                    }

                    _ => {
                        let err_str = e.to_string().to_lowercase();
                        if err_str.contains("transport") || err_str.contains("connect") || 
                           err_str.contains("os error 10053") || err_str.contains("connection refused") ||
                           err_str.contains("failed to connect") {
                            is_transport_error = true;
                            log::warn!("RPC call '{}' encountered a likely transport error (string match, attempt {}/{}): {}. Reconnecting...", 
                                       operation_description, attempts, max_retries + 1, e);
                        }
                    }
                }

                if is_transport_error {
                    std::thread::sleep(Duration::from_secs(1 << (attempts.saturating_sub(1))));
                    match Client::new(&rpc_cfg.url, Auth::UserPass(rpc_cfg.user.clone(), rpc_cfg.pass.clone())) {
                        Ok(new_client_instance) => {
                            *current_rpc = Arc::new(new_client_instance);
                            log::info!("Successfully reconnected RPC client for '{}'. Retrying operation...", operation_description);
                        }
                        Err(reconnect_err) => {
                            log::error!("Failed to reconnect RPC client for '{}' (attempt {}/{}): {}. Will retry or fail.", operation_description, attempts, max_retries + 1, reconnect_err);
                        }
                    }
                } else {
                    log::debug!("RPC operation '{}' failed with non-retriable error: {}", operation_description, e);
                    return Err(e);
                }
            }
        }
    }
}

// --- Fonction pour effectuer le rattrapage RPC ---
fn perform_rpc_catchup( rpc_cfg: &RpcConnectionConfig, rpc: &mut Arc<Client>, db_tx_details: &Arc<DB>, db_utxo_spend: &Arc<DB>, db_height_to_hash: &Arc<DB>, db_hash_to_coinbase: &Arc<DB>, indexer_state: &mut IndexerTipState, network: Network, progress_bar_message_prefix: &str,) -> Result<(), Box<dyn StdError>> { 
    let mut current_rpc_tip_height = rpc_call_with_retry(rpc_cfg, rpc, 3, "get_block_count (rpc_catchup_start)", |client| client.get_block_count()).map_err(Box::new)? as u32;

    if indexer_state.block_height >= current_rpc_tip_height {
        log::info!("{} - Indexer already at or beyond current RPC tip ({}). No RPC catchup needed.", progress_bar_message_prefix, indexer_state.block_height);
        return Ok(());
    }

    log::info!("{} - Starting. Indexer at {}, RPC tip at {}. Blocks to sync: {}",
        progress_bar_message_prefix, indexer_state.block_height, current_rpc_tip_height, current_rpc_tip_height - indexer_state.block_height);

    let pb = ProgressBar::new(current_rpc_tip_height.saturating_sub(indexer_state.block_height) as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{{spinner:.green}} [{}] [{{elapsed_precise}}] [{{wide_bar:.cyan/blue}}] {{pos}}/{{len}} Blocks ({{per_sec}}, ETA {{eta}})", progress_bar_message_prefix))
        .expect("Progress bar template error")
        .progress_chars("=> "));
    pb.set_message(format!("Block {} -> {}", indexer_state.block_height + 1, current_rpc_tip_height));

    while indexer_state.block_height < current_rpc_tip_height {
        let next_height = indexer_state.block_height + 1;
        
        let block_hash_to_fetch_desc = format!("get_block_hash (height {})", next_height);
        let block_hash_to_fetch = rpc_call_with_retry(rpc_cfg, rpc, 3, &block_hash_to_fetch_desc, |client| client.get_block_hash(next_height as u64)).map_err(Box::new)?;
        
        let get_block_desc = format!("get_block (hash {})", block_hash_to_fetch);
        let block_to_process = rpc_call_with_retry(rpc_cfg, rpc, 3, &get_block_desc, |client| client.get_block(&block_hash_to_fetch)).map_err(Box::new)?;

        if block_to_process.header.prev_blockhash.to_byte_array() != indexer_state.block_hash_bytes {
            log::error!("CRITICAL RPC CATCHUP MISMATCH: Block {} at height {} has prev_hash {}, expected indexer prev_hash {}. Halting.",
                block_hash_to_fetch, next_height, block_to_process.header.prev_blockhash, BlockHash::from_byte_array(indexer_state.block_hash_bytes));
            return Err(format!("[{}] Block prev_hash mismatch with local tip.", progress_bar_message_prefix).into());
        }

        let mut temp_outputs_cache = HashMap::with_capacity(block_to_process.txdata.len());
        for tx in &block_to_process.txdata { let outputs = tx.output.iter().map(|out| analyze_txout(out, network)).collect(); temp_outputs_cache.insert(tx.txid(), Arc::new(outputs)); }
        let temp_outputs_cache_arc = Arc::new(temp_outputs_cache);

        match process_block_logic(Arc::clone(db_tx_details), &block_to_process, next_height, temp_outputs_cache_arc) {
            Ok(data_to_write) => {
                let mut tx_details_batch = WriteBatch::default();
                for (k, v) in &data_to_write.tx_details_puts { tx_details_batch.put(k, v); }
                let mut utxo_spend_batch = WriteBatch::default();
                for (k,v) in data_to_write.utxo_spends_puts { utxo_spend_batch.put(&k,&v); }
                db_utxo_spend.write(utxo_spend_batch)?;
                let mut height_batch = WriteBatch::default();
                height_batch.put(&data_to_write.height_hash_put.0, &data_to_write.height_hash_put.1);
                db_height_to_hash.write(height_batch)?;
                if !data_to_write.hash_coinbase_put.1.is_empty() {
                    let mut coinbase_batch = WriteBatch::default();
                    coinbase_batch.put(&data_to_write.hash_coinbase_put.0, &data_to_write.hash_coinbase_put.1);
                    db_hash_to_coinbase.write(coinbase_batch)?;
                }
                indexer_state.block_height = next_height;
                indexer_state.block_hash_bytes = block_to_process.header.block_hash().to_byte_array();
                tx_details_batch.put(INDEXER_TIP_KEY, &indexer_state.to_bytes());
                db_tx_details.write(tx_details_batch)?;
                log::debug!("[{}] Processed block {} ({})", progress_bar_message_prefix, next_height, block_to_process.header.block_hash());
                pb.inc(1);
            }
            Err(e) => { log::error!("[{}] Failed to process block data for height {}: {}. Halting.", progress_bar_message_prefix, next_height, e); return Err(e); }
        }
        current_rpc_tip_height = rpc_call_with_retry(rpc_cfg, rpc, 3, "get_block_count (rpc_catchup_update)", |client| client.get_block_count()).map_err(Box::new)? as u32;
        let remaining_blocks = current_rpc_tip_height.saturating_sub(indexer_state.block_height) as u64;
        if pb.length().unwrap_or(0) != remaining_blocks + pb.position() { 
             pb.set_length(remaining_blocks + pb.position());
        }
        pb.set_message(format!("Block {} -> {}", indexer_state.block_height + 1, current_rpc_tip_height));
    }
    pb.finish_with_message(format!("{} - Complete. Indexer at height {}.", progress_bar_message_prefix, indexer_state.block_height));
    Ok(())
}

// --- main() function ---
fn main() -> Result<(), Box<dyn StdError>> {
    let config_path = Path::new("config.toml");
    let config = load_config(config_path).map_err(|e| { 
        eprintln!("Error loading configuration: {}", e); 
        e 
    })?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.log_level)).init();
    log::info!("Configuration loaded: {:?}", config);

    let rpc_cfg = RpcConnectionConfig { url: config.rpc_url.clone(), user: config.rpc_user.clone(), pass: config.rpc_pass.clone(), };
    let network = match config.network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Network::Bitcoin, "testnet" => Network::Testnet,
        "signet" => Network::Signet, "regtest" => Network::Regtest,
        _ => { log::error!("Invalid network specified: '{}'. Defaulting to Bitcoin.", config.network); Network::Bitcoin }
    };
    log::info!("Using Bitcoin network: {:?}", network);
    let magic_value = network.magic();

    let bitcoin_data_dir = PathBuf::from(&config.bitcoin_data_dir);
    let db_base_path_str = &config.db_base_path;
    let tx_details_db_path = PathBuf::from(format!("{}/tx_details", db_base_path_str));
    let utxo_spend_db_path = PathBuf::from(format!("{}/utxo_spend", db_base_path_str));
    let height_hash_db_path = PathBuf::from(format!("{}/height_hash", db_base_path_str));
    let hash_coinbase_db_path = PathBuf::from(format!("{}/hash_coinbase", db_base_path_str));
    std::fs::create_dir_all(db_base_path_str)?;

    if !config.rpc_only_catchup && (!bitcoin_data_dir.exists() || !bitcoin_data_dir.is_dir()) {
        log::error!("Bitcoin data directory not found: {} (required if rpc_only_catchup is false)", bitcoin_data_dir.display());
        return Err("Bitcoin data directory not found".into());
    }
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.increase_parallelism(num_cpus::get() as i32);
    db_opts.set_write_buffer_size(config.rocksdb.write_buffer_size_mb * 1024 * 1024);
    db_opts.set_max_background_jobs(config.rocksdb.max_background_jobs);
    db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    let cache_bytes = config.rocksdb.cache_size_gb * 1024 * 1024 * 1024;
    let cache = Cache::new_lru_cache(cache_bytes);
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    db_opts.set_block_based_table_factory(&block_opts);
    log::info!("Opening DBs at {}...", db_base_path_str);
    let db_tx_details = Arc::new(DB::open(&db_opts, &tx_details_db_path)?);
    let db_utxo_spend = Arc::new(DB::open(&db_opts, &utxo_spend_db_path)?);
    let db_height_to_hash = Arc::new(DB::open(&db_opts, &height_hash_db_path)?);
    let db_hash_to_coinbase = Arc::new(DB::open(&db_opts, &hash_coinbase_db_path)?);

    log::info!("Connecting to Bitcoin Core RPC at {}...", rpc_cfg.url);
    let mut rpc: Arc<Client> = Arc::new(Client::new(&rpc_cfg.url, Auth::UserPass(rpc_cfg.user.clone(), rpc_cfg.pass.clone()))?);

    let mut indexer_state = match db_tx_details.get(INDEXER_TIP_KEY)? {
        Some(b) => IndexerTipState::from_bytes(&b).unwrap_or_else(|| {
            log::warn!("Invalid indexer state in DB, restarting from Genesis for network {:?}.", network);
            IndexerTipState::genesis(network)
        }),
        None => {
            log::info!("No indexer state in DB, starting from Genesis for network {:?}.", network);
            IndexerTipState::genesis(network)
        }
    };
    log::info!("Current Indexer Tip: Block {}, Hash {}, File Index: {}, File Offset: {}", indexer_state.block_height, BlockHash::from_byte_array(indexer_state.block_hash_bytes), indexer_state.file_index, indexer_state.file_offset);

    let genesis_processed = db_tx_details.get(GENESIS_PROCESSED_FLAG_KEY)?.is_some(); 
    if indexer_state.block_height == 0 && !genesis_processed {
        log::info!("Genesis block (height 0) data not yet processed in DB. Processing via RPC...");
        let genesis_block_hash_const = bitcoin::blockdata::constants::genesis_block(network).block_hash();
        if BlockHash::from_byte_array(indexer_state.block_hash_bytes) != genesis_block_hash_const {
             log::warn!("Indexer state at height 0, but hash {} does not match network genesis hash {}. Resetting to network genesis.", BlockHash::from_byte_array(indexer_state.block_hash_bytes), genesis_block_hash_const);
             indexer_state = IndexerTipState::genesis(network);
        }
        let get_genesis_block_desc = format!("get_block (GENESIS {})", genesis_block_hash_const);
        let genesis_block_rpc = rpc_call_with_retry(&rpc_cfg, &mut rpc, 3, &get_genesis_block_desc, |client| client.get_block(&genesis_block_hash_const)).map_err(Box::new)?;
        let mut genesis_outputs_cache = HashMap::new(); 
        for tx in &genesis_block_rpc.txdata { let outputs = tx.output.iter().map(|out| analyze_txout(out, network)).collect(); genesis_outputs_cache.insert(tx.txid(), Arc::new(outputs)); }
        let genesis_outputs_cache_arc = Arc::new(genesis_outputs_cache);
        match process_block_logic(Arc::clone(&db_tx_details), &genesis_block_rpc, 0, genesis_outputs_cache_arc) {
            Ok(data_to_write) => { 
                let mut batch = WriteBatch::default();
                for (k, v) in &data_to_write.tx_details_puts { batch.put(k, v); }
                db_utxo_spend.write(WriteBatch::default())?; 
                let mut height_batch_genesis = WriteBatch::default(); height_batch_genesis.put(&data_to_write.height_hash_put.0, &data_to_write.height_hash_put.1); db_height_to_hash.write(height_batch_genesis)?;
                if !data_to_write.hash_coinbase_put.1.is_empty() || data_to_write.hash_coinbase_put.0 == genesis_block_hash_const.to_byte_array() {
                    let mut coinbase_batch_genesis = WriteBatch::default(); coinbase_batch_genesis.put(&data_to_write.hash_coinbase_put.0, &data_to_write.hash_coinbase_put.1); db_hash_to_coinbase.write(coinbase_batch_genesis)?;
                }
                batch.put(GENESIS_PROCESSED_FLAG_KEY, b"true"); batch.put(INDEXER_TIP_KEY, &indexer_state.to_bytes()); db_tx_details.write(batch)?;
                log::info!("Genesis block data processed and stored. Indexer state confirmed at height 0.");
            }
            Err(e) => { log::error!("Failed to process Genesis block data: {}. Halting.", e); return Err(e); }
        }
    } else if indexer_state.block_height == 0 && genesis_processed {
        log::info!("Genesis block data already processed and marked in DB.");
    }

    let node_tip_for_catchup_phase = rpc_call_with_retry(&rpc_cfg, &mut rpc, 3, "get_block_count (pre-catchup)", |client| client.get_block_count()).map_err(Box::new)? as u32;
    
    if config.rpc_only_catchup {
        log::info!("RPC-only catchup mode selected.");
        if indexer_state.block_height < node_tip_for_catchup_phase { 
             perform_rpc_catchup(&rpc_cfg, &mut rpc, &db_tx_details, &db_utxo_spend, &db_height_to_hash, &db_hash_to_coinbase, &mut indexer_state, network, "RPC Full Catchup")?;
        } else { log::info!("Indexer already at or beyond current RPC tip ({}). No RPC full catchup needed.", indexer_state.block_height); }
    } else { 
        log::info!("File-based catchup mode selected (followed by RPC gap sync).");
        if indexer_state.block_height < node_tip_for_catchup_phase {
            log::info!("Starting File Catchup from block {} to target node tip {} for network {:?}", indexer_state.block_height + 1, node_tip_for_catchup_phase, network);
            let catchup_start_time = Instant::now();
            let pb_file_catchup = ProgressBar::new( if node_tip_for_catchup_phase > indexer_state.block_height { (node_tip_for_catchup_phase - indexer_state.block_height) as u64 } else { 0 });
            pb_file_catchup.set_style(ProgressStyle::default_bar().template("{spinner:.green} [File Catchup {msg}] [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} Blocks ({per_sec}, ETA {eta})").expect("Progress bar template error").progress_chars("=> "));
            pb_file_catchup.set_message(format!("Block {} -> {}", indexer_state.block_height +1, node_tip_for_catchup_phase));

            'file_catchup_loop: loop {
                if indexer_state.block_height >= node_tip_for_catchup_phase { break 'file_catchup_loop; }
                let current_block_file_path = bitcoin_data_dir.join(format!("blk{:05}.dat", indexer_state.file_index));
                if !current_block_file_path.exists() { log::warn!("Block file {} not found. Ending file catchup.", current_block_file_path.display()); break 'file_catchup_loop; }
                let mut current_file = match File::open(&current_block_file_path) { Ok(f) => f, Err(e) => { log::error!("Cannot open block file {}: {}. Halting.", current_block_file_path.display(), e); return Err(Box::new(e)); }};
                if indexer_state.file_offset > 0 { if let Err(e) = current_file.seek(SeekFrom::Start(indexer_state.file_offset)) { log::warn!("Seek failed: {}. Moving to next file.", e); indexer_state.file_index += 1; indexer_state.file_offset = 0; db_tx_details.put(INDEXER_TIP_KEY, &indexer_state.to_bytes())?; continue 'file_catchup_loop; }}

                loop { 
                    if indexer_state.block_height >= node_tip_for_catchup_phase { break 'file_catchup_loop; }
                    let block_start_offset_in_file = current_file.stream_position()?;
                    let mut file_magic_bytes = [0u8; 4]; if let Err(e) = current_file.read_exact(&mut file_magic_bytes) { if e.kind() == ErrorKind::UnexpectedEof { break; } else { log::error!("Error magic: {}", e); break;}}
                    if file_magic_bytes != magic_value.to_bytes() { log::error!("Invalid magic. Halting."); return Err("Invalid magic".into()); }
                    let mut file_size_bytes = [0u8; 4]; if let Err(e) = current_file.read_exact(&mut file_size_bytes) { log::warn!("Error size: {}", e); break; }
                    let file_block_size = u32::from_le_bytes(file_size_bytes);
                    if file_block_size == 0 || file_block_size > 5_000_000 { log::error!("Invalid block size {}. Halting.", file_block_size); return Err("Invalid block size".into()); }
                    let mut file_block_bytes = vec![0u8; file_block_size as usize]; if let Err(e) = current_file.read_exact(&mut file_block_bytes) { log::error!("Error block bytes: {}", e); break; }

                    let calculated_next_offset_if_file_block_used = block_start_offset_in_file + 8 + file_block_size as u64;
                    let height_being_processed = indexer_state.block_height + 1;
                    let block_for_processing: Block; 
                    

                    match deserialize::<Block>(&file_block_bytes) {
                        Ok(parsed_file_block) => {
                            if height_being_processed > 0 && parsed_file_block.header.prev_blockhash.to_byte_array() != indexer_state.block_hash_bytes {
                                log::info!("Block Mismatch (using RPC fallback): File block {} (hash {}), expected prev_hash {}. Indexer tip prev_hash: {}.", current_block_file_path.display(), parsed_file_block.header.block_hash(), parsed_file_block.header.prev_blockhash, BlockHash::from_byte_array(indexer_state.block_hash_bytes));
                                
                                let rpc_get_hash_desc = format!("get_block_hash (fallback height {})", height_being_processed);
                                let rpc_block_hash = rpc_call_with_retry(&rpc_cfg, &mut rpc, 3, &rpc_get_hash_desc, |client| client.get_block_hash(height_being_processed as u64)).map_err(Box::new)?;
                                let rpc_get_block_desc = format!("get_block (fallback hash {})", rpc_block_hash);
                                block_for_processing = rpc_call_with_retry(&rpc_cfg, &mut rpc, 3, &rpc_get_block_desc, |client| client.get_block(&rpc_block_hash)).map_err(Box::new)?;
                                if block_for_processing.header.prev_blockhash.to_byte_array() != indexer_state.block_hash_bytes { log::error!("CRITICAL RPC FALLBACK MISMATCH. Halting."); return Err("RPC fallback prev_hash mismatch".into()); }
                                log::info!("Fetched block {} via RPC after file mismatch.", rpc_block_hash);
                            } else { block_for_processing = parsed_file_block; }
                        }
                        Err(e) => { log::error!("Deserialization failed for block in {}: {}. Halting.", current_block_file_path.display(), e); return Err(Box::new(e)); }
                    }
                    
                    let actual_processed_block_hash = block_for_processing.header.block_hash();
                    let mut temp_block_outputs_cache = HashMap::with_capacity(block_for_processing.txdata.len());
                    for tx in &block_for_processing.txdata { let outputs = tx.output.iter().map(|out| analyze_txout(out, network)).collect(); temp_block_outputs_cache.insert(tx.txid(), Arc::new(outputs)); }
                    let temp_block_outputs_cache_arc = Arc::new(temp_block_outputs_cache);
                    match process_block_logic(Arc::clone(&db_tx_details), &block_for_processing, height_being_processed, temp_block_outputs_cache_arc) {
                        Ok(data_to_write) => {
                            let mut tx_details_batch = WriteBatch::default();
                            for (k, v) in &data_to_write.tx_details_puts { tx_details_batch.put(k, v); }
                            let mut utxo_spend_batch = WriteBatch::default(); for (k,v) in data_to_write.utxo_spends_puts { utxo_spend_batch.put(&k,&v); } db_utxo_spend.write(utxo_spend_batch)?;
                            let mut height_batch = WriteBatch::default(); height_batch.put(&data_to_write.height_hash_put.0, &data_to_write.height_hash_put.1); db_height_to_hash.write(height_batch)?;
                            if !data_to_write.hash_coinbase_put.1.is_empty() { let mut coinbase_batch = WriteBatch::default(); coinbase_batch.put(&data_to_write.hash_coinbase_put.0, &data_to_write.hash_coinbase_put.1); db_hash_to_coinbase.write(coinbase_batch)?; }
                            indexer_state.block_height = height_being_processed;
                            indexer_state.block_hash_bytes = actual_processed_block_hash.to_byte_array();
                            indexer_state.file_offset = calculated_next_offset_if_file_block_used;
                            tx_details_batch.put(INDEXER_TIP_KEY, &indexer_state.to_bytes());
                            db_tx_details.write(tx_details_batch)?;
                            pb_file_catchup.inc(1);
                        }
                        Err(e) => { log::error!("Failed to process block data for height {} (from file/rpc): {}. Halting.", height_being_processed, e); return Err(e); }
                    }
                    pb_file_catchup.set_message(format!("Block {} -> {}", indexer_state.block_height + 1, node_tip_for_catchup_phase));
                } 
                log::info!("Finished file {}. Moving to next.", current_block_file_path.display());
                indexer_state.file_index += 1; indexer_state.file_offset = 0;
                db_tx_details.put(INDEXER_TIP_KEY, &indexer_state.to_bytes())?;
            } 
            pb_file_catchup.finish_with_message(format!("File Catchup to target {} finished in {:.2?}.", node_tip_for_catchup_phase, catchup_start_time.elapsed()));
        } else {
            log::info!("Indexer already at or beyond target node tip for file catchup ({}).", indexer_state.block_height);
        }
        perform_rpc_catchup( &rpc_cfg, &mut rpc, &db_tx_details, &db_utxo_spend, &db_height_to_hash, &db_hash_to_coinbase, &mut indexer_state, network, "RPC Gap Sync", )?;
    }

    // --- Phase 2: Suivi Continu via ZMQ ---
    log::info!("Switching to ZMQ tracking mode for new blocks via {}...", config.zmq_url);
    let zmq_context = zmq::Context::new();
    let zmq_subscriber = zmq_context.socket(zmq::SUB)?;
    zmq_subscriber.connect(&config.zmq_url)?;
    zmq_subscriber.set_subscribe(b"hashblock")?;
    log::info!("Successfully connected and subscribed to ZMQ for 'hashblock'.");

    let pb_zmq = ProgressBar::new_spinner();
    pb_zmq.set_style(ProgressStyle::default_spinner().template("{spinner:.green} [ZMQ Mode] {msg}").expect("ZMQ progress bar template error"));
    pb_zmq.enable_steady_tick(Duration::from_millis(120));
    pb_zmq.set_message(format!("Height: {}, Hash: {:.8}..., Waiting for next block...", indexer_state.block_height, BlockHash::from_byte_array(indexer_state.block_hash_bytes).to_string()));

    loop {
        match zmq_subscriber.recv_multipart(0) {
            Ok(mut multipart_msg) => {
                if multipart_msg.len() >= 2 {
                    let _topic = multipart_msg.remove(0); 
                    let mut block_hash_zmq_bytes = multipart_msg.remove(0);
                    if block_hash_zmq_bytes.len() == 32 {
                        
                        block_hash_zmq_bytes.reverse();

                        if let Ok(block_hash_from_zmq) = BlockHash::from_slice(&block_hash_zmq_bytes) {
                            if block_hash_from_zmq.to_byte_array() == indexer_state.block_hash_bytes {
                                log::debug!("Received ZMQ notification for already processed block {}, skipping.", block_hash_from_zmq);
                                pb_zmq.set_message(format!("Height: {}, Hash: {:.8}..., Waiting... (last ZMQ was duplicate)", indexer_state.block_height, BlockHash::from_byte_array(indexer_state.block_hash_bytes).to_string()));
                                continue;
                            }
                            
                            let get_block_zmq_desc = format!("get_block (ZMQ hash {})", block_hash_from_zmq);
                            match rpc_call_with_retry(&rpc_cfg, &mut rpc, 3, &get_block_zmq_desc, |client| client.get_block(&block_hash_from_zmq)) {
                                Ok(zmq_block) => {
                                    let zmq_block_height = indexer_state.block_height + 1;
                                    if zmq_block.header.prev_blockhash.to_byte_array() != indexer_state.block_hash_bytes {
                                        log::error!("REORG DETECTED VIA ZMQ! Expected prev_hash {}, but block {} (height approx {}) has prev_hash {}. Halting.", BlockHash::from_byte_array(indexer_state.block_hash_bytes), block_hash_from_zmq, zmq_block_height, zmq_block.header.prev_blockhash);
                                        pb_zmq.finish_with_message("ZMQ Mode Halted - Reorg Detected!");
                                        return Err("Reorganization detected via ZMQ, not handled.".into());
                                    }
                                    let processing_start_zmq = Instant::now();
                                    let mut zmq_outputs_cache = HashMap::with_capacity(zmq_block.txdata.len());
                                    for tx in &zmq_block.txdata { let outputs = tx.output.iter().map(|out| analyze_txout(out, network)).collect(); zmq_outputs_cache.insert(tx.txid(), Arc::new(outputs)); }
                                    let zmq_outputs_cache_arc = Arc::new(zmq_outputs_cache);

                                    match process_block_logic(Arc::clone(&db_tx_details), &zmq_block, zmq_block_height, zmq_outputs_cache_arc) {
                                        Ok(data_to_write_zmq) => {
                                            let mut tx_details_batch_zmq = WriteBatch::default();
                                            for (k,v) in &data_to_write_zmq.tx_details_puts { tx_details_batch_zmq.put(k, v); }
                                            let mut utxo_spend_batch_zmq = WriteBatch::default(); for (k,v) in data_to_write_zmq.utxo_spends_puts { utxo_spend_batch_zmq.put(&k,&v); } db_utxo_spend.write(utxo_spend_batch_zmq)?;
                                            let mut height_batch_zmq = WriteBatch::default(); height_batch_zmq.put(&data_to_write_zmq.height_hash_put.0, &data_to_write_zmq.height_hash_put.1); db_height_to_hash.write(height_batch_zmq)?;
                                            if !data_to_write_zmq.hash_coinbase_put.1.is_empty() { let mut coinbase_batch_zmq = WriteBatch::default(); coinbase_batch_zmq.put(&data_to_write_zmq.hash_coinbase_put.0, &data_to_write_zmq.hash_coinbase_put.1); db_hash_to_coinbase.write(coinbase_batch_zmq)?; }
                                            
                                            indexer_state.block_height = zmq_block_height;
                                            indexer_state.block_hash_bytes = block_hash_from_zmq.to_byte_array();
                                            tx_details_batch_zmq.put(INDEXER_TIP_KEY, &indexer_state.to_bytes());
                                            db_tx_details.write(tx_details_batch_zmq)?;
                                            
                                            let elapsed_time = processing_start_zmq.elapsed();
                                            pb_zmq.set_message(format!("Height: {}, Hash: {:.8}..., Processed in: {:.2?}", indexer_state.block_height, block_hash_from_zmq.to_string(), elapsed_time));
                                            log::info!("ZMQ Block {} processed. Hash: {:.8}..., Time: {:.2?}.", indexer_state.block_height, block_hash_from_zmq.to_string(), elapsed_time);
                                        }
                                        Err(e) => { 
                                            log::error!("Error ZMQ process_block_logic for block {}: {}. Halting.", block_hash_from_zmq, e);
                                            pb_zmq.finish_with_message("ZMQ Mode Halted - Processing Error!");
                                            return Err(e);
                                        }
                                    }
                                }
                                Err(e_rpc) => {
                                    match e_rpc {
                                        RpcError_::JsonRpc(jsonrpc::error::Error::Rpc(jsonrpc::error::RpcError { code: -5, message, .. }))
                                        if message.to_lowercase().contains("block not found") || message.to_lowercase().contains("blocknotfound") => {
                                            log::warn!("ZMQ: Block hash {} (after reversing ZMQ bytes) received, but 'Block not found' via RPC (Code -5). Potential stale tip. Skipping. Error: {}", block_hash_from_zmq, message);
                                            pb_zmq.set_message(format!("Height: {}, Hash: {:.8}..., Waiting... (last ZMQ block {} not found)", indexer_state.block_height, BlockHash::from_byte_array(indexer_state.block_hash_bytes).to_string(), block_hash_from_zmq));
                                        }
                                        persistent_e => {
                                             log::error!("ZMQ: Persistent or unhandled RPC error for block {}: {}. Halting.", block_hash_from_zmq, persistent_e);
                                             pb_zmq.finish_with_message("ZMQ Mode Halted - RPC Error!");
                                             return Err(Box::new(persistent_e));
                                        }
                                    }
                                }
                             }
                        } else { log::warn!("Received ZMQ block hash with unexpected length: {} bytes", block_hash_zmq_bytes.len()); }
                    } else { log::warn!("Received ZMQ message with unexpected part count: {}", multipart_msg.len()); }
                }
            }
            Err(e) => {
                if e == zmq::Error::EINTR { 
                    log::info!("ZMQ receive interrupted, stopping indexer."); 
                    pb_zmq.finish_with_message("ZMQ Mode Interrupted.");
                    break; 
                }
                log::error!("ZMQ recv error: {}. Retrying in 1 sec.", e); 
                pb_zmq.set_message(format!("ZMQ Recv Error: {}. Retrying...", e));
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    log::info!("Indexer has been stopped.");
    Ok(())
}