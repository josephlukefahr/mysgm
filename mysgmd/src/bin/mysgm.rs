use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use clap::Parser;
use mysgm::dimls::{DiMlsProvider, DiMlsState, SignatureKeyPair, gen_reusable_kp_message};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::Ciphersuite;
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::{
    env::home_dir,
    fs::{
        create_dir_all, read_dir, read_to_string as read_file_to_string, remove_file,
        write as write_string_to_file,
    },
    thread::sleep,
    time::Duration,
};
use tls_codec::Serialize;

/// CLI for secure group messsaging agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Nickname to use for agent state (required)
    nickname: String,
    /// Command to execute
    #[command(subcommand)]
    command: MainCommands,
}

#[derive(clap::Subcommand, Debug)]
enum MainCommands {
    /// Generate new reusable key package
    GenKp {},
}

fn main() {
    pretty_env_logger::init();
    // mysgm root directory
    let root_dir = home_dir().unwrap().join(".mysgm");
    create_dir_all(&root_dir).unwrap();
    // cache requests directory
    let requests_dir = root_dir.join("requests");
    create_dir_all(&requests_dir).unwrap();
    // local cache directory
    let cache_dir = root_dir.join("cache");
    create_dir_all(&cache_dir).unwrap();
    // incoming message directory
    let inbox_dir = root_dir.join("inbox");
    create_dir_all(&inbox_dir).unwrap();
    // cli args
    let args = CliArgs::parse();
    log::info!("Command-line arguments: {args:?}");
    // path to use for agent state
    let state_path = root_dir.join(format!("{}.json", &args.nickname));
    log::info!("Path to agent state: {}", state_path.display());
    // crypto
    let crypto: RustCrypto = Default::default();
    // ciphersuite
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    // agent state
    let state: DiMlsState = json_decode(&read_file_to_string(&state_path).unwrap()).unwrap();
    log::info!("Loaded state: {state:?}");
    // provider with state
    let mut provider = DiMlsProvider::new(state, crypto);
    match args.command {
        MainCommands::GenKp {} => {
            let kp_msg = gen_reusable_kp_message(&provider, ciphersuite).unwrap();
            // print base64-encoded key package
            println!(
                "{}",
                Base64.encode(kp_msg.tls_serialize_detached().unwrap())
            );
        }
    }
    // traverse inbox
    for entry in read_dir(&inbox_dir).unwrap() {
        match entry {
            Err(e) => {
                log::error!("Error reading inbox: {e}");
            }
            Ok(entry) => match remove_file(entry.path()) {
                Ok(_) => {
                    log::info!("Removed inbox file {}", entry.path().display());
                }
                Err(e) => {
                    log::error!("Error removing inbox file: {e}");
                }
            },
        }
    }
    // save state
    log::info!("State before saving: {:?}", provider.state());
    write_string_to_file(&state_path, json_encode(provider.state()).unwrap()).unwrap();
    // done!
}
