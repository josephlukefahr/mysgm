use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use clap::Parser;
use mysgm::dimls::{
    DiMlsProvider, DiMlsState, apply_commit, create_message, force_self_update,
    gen_reusable_kp_message, gen_send_group_and_add, inject_psks, other_group_commit_keys,
    plaintext, process_proto_msg, send_group_commit_key, try_join,
};
use openmls::{
    framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent},
    group::MlsGroup,
    key_packages::KeyPackage,
    versions::ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::{
    env::home_dir,
    error::Error,
    fs::{File, create_dir_all, read, read_dir, read_to_string, remove_file},
    io::{BufRead, Write, stdin},
};
use tls_codec::{Deserialize, Serialize};
use uuid::Uuid;

/// Validate and deserialize a base64-encoded KeyPackage provided via stdin.
///
/// The key package is validated using the provider's crypto and the MLS protocol version.
///
/// Example:
///
/// ```ignore
/// let kp = stdin_base64_to_kp(&provider, line)?;
/// ```
fn stdin_base64_to_kp(
    provider: &DiMlsProvider,
    s: std::io::Result<String>,
) -> Result<KeyPackage, Box<dyn Error>> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(&Base64.decode(s?)?)?;
    match msg_in.extract() {
        MlsMessageBodyIn::KeyPackage(kp_in) => Ok(kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)?
            .clone()),
        _ => Err("Provided message is not a KeyPackage".into()),
    }
}

fn stdin_base64_decode(s: std::io::Result<String>) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(Base64.decode(s?)?)
}

fn stdin_base64_process_proto_msg(
    provider: &mut DiMlsProvider,
    s: std::io::Result<String>,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(&Base64.decode(s?)?)?;
    let (mut g, m) = match msg_in.extract() {
        MlsMessageBodyIn::PublicMessage(pub_msg_in) => {
            process_proto_msg(provider, pub_msg_in.into())
        }
        MlsMessageBodyIn::PrivateMessage(prv_msg_in) => {
            process_proto_msg(provider, prv_msg_in.into())
        }
        _ => Err("Provided message is not a valid protocol message".into()),
    }?;
    match m.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(Some(plaintext(app_msg)?)),
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            apply_commit(provider, &mut g, *commit, ciphersuite, exporter_length).map(|_| None)
        }

        _ => Err("Processed message is not an application message or staged commit".into()),
    }
}

fn stdin_base64_try_join(
    provider: &mut DiMlsProvider,
    s: std::io::Result<String>,
) -> Result<MlsGroup, Box<dyn Error>> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(&Base64.decode(s?)?)?;
    match msg_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => try_join(provider, welcome),
        _ => Err("Provided message is not a KeyPackage".into()),
    }
}

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
    /// Generate send-group with static membership
    GenSendGroup {},
    /// Join group
    Join {},
    /// Trigger send-group update and enqueue PSK
    Update {},
    /// Inject queued PSKs into send-group and return commit
    Commit {},
    /// Process incoming messages
    Process {},
    /// Encrypt
    Encrypt {},
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
    // outgoing message directory
    let outbox_dir = root_dir.join("outbox");
    create_dir_all(&outbox_dir).unwrap();
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
    let state: DiMlsState = json_decode(&read_to_string(&state_path).unwrap()).unwrap();
    log::info!("Loaded state: {state:?}");
    // provider with state
    let mut provider = DiMlsProvider::new(state, crypto);
    // handle command
    match args.command {
        MainCommands::GenKp {} => {
            // generate reusable key package message
            let kp_msg = gen_reusable_kp_message(&provider, ciphersuite).unwrap();
            // print base64-encoded message
            println!(
                "{}",
                Base64.encode(kp_msg.tls_serialize_detached().unwrap())
            );
        }
        MainCommands::GenSendGroup {} => {
            // warn on opening stdin for reading key packages
            log::warn!(
                "Reading base64-encoded key packages from stdin (one key package per line)... press Ctrl+D to end input"
            );
            // add members via base64-encoded key packages from stdin
            let mut kps = Vec::new();
            for line in stdin().lock().lines() {
                match stdin_base64_to_kp(&provider, line) {
                    Err(e) => {
                        log::error!("Error validating key package: {e}");
                    }
                    Ok(kp) => {
                        log::info!("Validated key package:\n{kp:#?}");
                        kps.push(kp);
                    }
                }
            }
            let (sg, welcome_msg) =
                gen_send_group_and_add(&mut provider, ciphersuite, &kps).unwrap();
            // debug group
            log::info!("Generated send-group: {sg:#?}");
            // print base64-encoded message
            println!(
                "{}",
                Base64.encode(welcome_msg.tls_serialize_detached().unwrap())
            );
        }
        MainCommands::Join {} => {
            // warn on opening stdin for reading welcome message
            log::warn!(
                "Reading base64-encoded welcome message from stdin... press Ctrl+D to end input"
            );
            // try join via base64-encoded welcome message from stdin
            for line in stdin().lock().lines() {
                match stdin_base64_try_join(&mut provider, line) {
                    Err(e) => {
                        log::error!("Error processing welcome message: {e}");
                    }
                    Ok(group) => {
                        log::info!("Joined group: {group:#?}");
                    }
                }
            }
        }
        MainCommands::Update {} => {
            // generate uuid based on commit key for self-update
            let commit_uuid =
                Uuid::from_slice(&send_group_commit_key(&provider, 16).unwrap()).unwrap();
            // update
            let commit = force_self_update(&mut provider, ciphersuite, 32).unwrap();
            log::info!("Commit ({commit_uuid}): {commit:#?}");
            // save tls-encoded commit message to file with uuid as filename
            let mut commit_file =
                File::create_new(cache_dir.join(commit_uuid.to_string())).unwrap();
            commit_file
                .write_all(&commit.tls_serialize_detached().unwrap())
                .unwrap();
        }
        MainCommands::Commit {} => {
            // generate uuid based on commit key for psk-inject
            let commit_uuid =
                Uuid::from_slice(&send_group_commit_key(&provider, 16).unwrap()).unwrap();
            // update
            let commit = inject_psks(&mut provider, ciphersuite).unwrap();
            log::info!("Commit ({commit_uuid}): {commit:#?}");
            // save tls-encoded commit message to file with uuid as filename
            let mut commit_file =
                File::create_new(cache_dir.join(commit_uuid.to_string())).unwrap();
            commit_file
                .write_all(&commit.tls_serialize_detached().unwrap())
                .unwrap();
        }
        MainCommands::Process {} => {
            // generate & save commit keys for requesting commits from other groups
            for commit_key in other_group_commit_keys(&provider, 16).unwrap().iter() {
                let commit_uuid = Uuid::from_slice(commit_key).unwrap();
                log::info!("Requesting commit ({commit_uuid})");
                let _ = File::create(requests_dir.join(commit_uuid.to_string())).unwrap();
            }
            // process incoming messages
            log::info!("Processing incoming messages...");
            for entry in read_dir(&inbox_dir).unwrap() {
                match entry {
                    Err(e) => {
                        log::error!("Error reading inbox: {e}");
                    }
                    Ok(entry) => {
                        match stdin_base64_process_proto_msg(
                            &mut provider,
                            Ok(Base64.encode(read(entry.path()).unwrap())),
                            ciphersuite,
                            32,
                        ) {
                            Err(e) => {
                                log::error!(
                                    "Error processing inbox file {}: {e}",
                                    entry.path().display()
                                );
                            }
                            Ok(processed_msg) => {
                                log::info!("Processed inbox file {}", entry.path().display());
                                match remove_file(entry.path()) {
                                    Ok(_) => {
                                        log::info!("Removed inbox file {}", entry.path().display());
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "Error removing inbox file {}: {e}",
                                            entry.path().display()
                                        );
                                    }
                                }
                                if let Some(plaintext) = processed_msg {
                                    // print base64-encoded message
                                    println!("{}", Base64.encode(plaintext));
                                }
                            }
                        }
                    }
                }
            }
        }
        MainCommands::Encrypt {} => {
            // warn on opening stdin for reading base64-encoded plaintext messages
            log::warn!(
                "Reading base64-encoded plaintext messages from stdin (one message per line)... press Ctrl+D to end input"
            );
            // encrypt via base64-encoded plaintext messages from stdin
            for line in stdin().lock().lines() {
                match stdin_base64_decode(line) {
                    Err(e) => {
                        log::error!("Error decoding base64 plaintext message: {e}");
                    }
                    Ok(plaintext) => {
                        // save tls-encoded application message to file with timestamp-based uuid as filename
                        let message_uuid = Uuid::now_v7();
                        let mut message_file =
                            File::create_new(outbox_dir.join(message_uuid.to_string())).unwrap();
                        message_file
                            .write_all(
                                &create_message(&provider, &plaintext).unwrap()
                                    .tls_serialize_detached()
                                    .unwrap(),
                            )
                            .unwrap();
                    }
                }
            }
        }
    }
    // save state
    log::info!("State before saving: {:?}", provider.state());
    let mut state_file = File::create(&state_path).unwrap();
    state_file
        .write_all(json_encode(provider.state()).unwrap().as_bytes())
        .unwrap();
    // done!
}
