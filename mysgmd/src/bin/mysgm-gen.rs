use clap::Parser;
use mysgm::dimls::{DiMlsProvider, DiMlsState, SignatureKeyPair, gen_send_group};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::Ciphersuite;
use serde_json::to_string as json_encode;
use std::{
    env::home_dir,
    fs::{create_dir_all, write as write_string_to_file},
};

/// CLI for secure group messsaging agent's state generation tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Nickname to use for agent state (required)
    nickname: String,
}

fn main() {
    pretty_env_logger::init();
    // mysgm root directory
    let root_dir = home_dir().unwrap().join(".mysgm");
    create_dir_all(&root_dir).unwrap();
    // cli args
    let args = CliArgs::parse();
    log::info!("Command-line arguments: {args:?}");
    // path to use for agent state
    let state_path = root_dir.join(format!("{}.json", &args.nickname));
    log::info!("Path to agent state: {}", state_path.display());
    // check if file already exists
    if state_path.exists() {
        panic!("State already exists: {}", state_path.display());
    }
    // crypto
    let crypto: RustCrypto = Default::default();
    // ciphersuite
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    // signature key pair + state
    let state =
        DiMlsState::new(SignatureKeyPair::from_crypto(&crypto, ciphersuite.into()).unwrap());
    log::info!("State: {state:?}");
    // provider with new state
    let mut provider = DiMlsProvider::new(state, crypto);
    // generate send-group
    let sg = gen_send_group(&mut provider, ciphersuite).unwrap();
    log::info!("Generated send-group: {sg:?}");
    // save state
    log::info!("State before saving: {:?}", provider.state());
    write_string_to_file(&state_path, json_encode(provider.state()).unwrap()).unwrap();
    // done!
}
