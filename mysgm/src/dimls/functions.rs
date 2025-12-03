use super::provider::DiMlsProvider;
use core::error::Error;
use openmls::{
    credentials::{BasicCredential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{ApplicationMessage, MlsMessageOut, ProcessedMessage, ProtocolMessage, Sender},
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedCommit, StagedWelcome},
    key_packages::KeyPackage,
    messages::{
        Welcome,
        proposals::{PreSharedKeyProposal, Proposal},
    },
    prelude::Capabilities,
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::LeafNodeParameters,
};
use openmls_traits::{OpenMlsProvider, types::Ciphersuite};

/// Build a minimal `CredentialWithKey` from the provider's signature public key.
///
/// The credential identity used here is the first 8 bytes of the signature public key. This
/// is sufficient for the examples in this crate but not suitable for production identity
/// management.
///
/// Example:
///
/// ```ignore
/// let cred = cred_with_key(&provider);
/// ```
pub fn cred_with_key(provider: &DiMlsProvider) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(Vec::new()).into(),
        signature_key: provider
            .state()
            .signature_key_pair()
            .public_key_raw()
            .into(),
    }
}

/// Return the current send-group (the group's id stored in `DiMlsState`) loaded from storage.
///
/// Returns an error if no send-group id is set or if the group cannot be loaded.
///
/// Example:
///
/// ```ignore
/// let group = send_group(&provider)?;
/// ```
pub fn send_group(provider: &DiMlsProvider) -> Result<MlsGroup, Box<dyn Error>> {
    match provider.state().send_group_id() {
        None => Err("No send group exists".into()),
        Some(send_group_id) => Ok(MlsGroup::load(provider.storage(), &send_group_id)?.unwrap()),
    }
}

pub fn gen_send_group_and_add(
    provider: &mut DiMlsProvider,
    ciphersuite: Ciphersuite,
    kps: &[KeyPackage],
) -> Result<(MlsGroup, MlsMessageOut), Box<dyn Error>> {
    let sg = gen_send_group(provider, ciphersuite)?;
    Ok((sg, force_add_members(provider, kps)?))
}

/// Create a new send-group and persist its id to state. Returns an error if a send-group already exists.
///
/// This function sets `send_group_id` in the provider state so subsequent calls to `send_group`
/// will return the correct group instance.
///
/// Example:
///
/// ```ignore
/// let sg = gen_send_group(&mut provider, ciphersuite)?;
/// ```
pub fn gen_send_group(
    provider: &mut DiMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<MlsGroup, Box<dyn Error>> {
    match provider.state().send_group_id() {
        None => {
            let group = MlsGroup::new(
                provider,
                provider,
                &MlsGroupCreateConfig::builder()
                    .ciphersuite(ciphersuite)
                    .use_ratchet_tree_extension(true)
                    .capabilities(Capabilities::new(
                        None,
                        None,
                        Some(&[ExtensionType::LastResort]),
                        None,
                        Some(&[CredentialType::Basic]),
                    ))
                    .build(),
                cred_with_key(provider),
            )?;
            provider
                .state_mut()
                .set_send_group_id(group.group_id().clone());
            Ok(group)
        }
        Some(_) => Err("Send group already exists".into()),
    }
}

/// Generate a reusable KeyPackage for the provider's credential.
///
/// Example:
///
/// ```ignore
/// let kp_msg = gen_reusable_kp_message(&provider, ciphersuite)?;
/// println!("{:?}", kp_msg);
/// ```
pub fn gen_reusable_kp_message(
    provider: &DiMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<MlsMessageOut, Box<dyn Error>> {
    Ok(MlsMessageOut::from(
        KeyPackage::builder()
            .mark_as_last_resort()
            .leaf_node_capabilities(Capabilities::new(
                None,
                None,
                Some(&[ExtensionType::LastResort]),
                None,
                Some(&[CredentialType::Basic]),
            ))
            .build(ciphersuite, provider, provider, cred_with_key(provider))?
            .key_package()
            .clone(),
    ))
}

/// Derive an exporter PSK from the group's exporter and store it in the local PSK store.
///
/// Returns the PSK identifier (a byte vector) for later injection. The PSK id is constructed
/// from the group's epoch and group id. The derived PSK secret is stored using the OpenMLS
/// PSK storage API so it can be looked up by other operations.
///
/// Example:
///
/// ```ignore
/// let psk_id = store_exporter_psk(&mut provider, &group, ciphersuite, 32)?;
/// // psk_id can be serialized and saved with state if desired
/// ```
pub fn store_exporter_psk(
    provider: &mut DiMlsProvider,
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // psk id = epoch + group id
    let mut psk_id_vec = Vec::from(group.epoch().as_u64().to_be_bytes());
    psk_id_vec.extend(group.group_id().to_vec());
    // psk secret
    let psk_secret = group.export_secret(
        provider.crypto(),
        "exporter_psk",
        &psk_id_vec,
        exporter_length,
    )?;
    // store psk
    PreSharedKeyId::new(
        ciphersuite,
        provider.rand(),
        Psk::External(ExternalPsk::new(psk_id_vec.clone())),
    )?
    .store(provider, &psk_secret)?;
    // done; return psk id
    Ok(psk_id_vec)
}

/// Force a self-update in the send-group and return the staged commit message.
///
/// The commit is produced by calling `self_update` on the group, staged, merged, and its
/// corresponding exporter PSK will be stored. The resulting `MlsMessageOut` should be sent
/// to other group members to finalize the update.
///
/// Example:
///
/// ```ignore
/// let staged_commit = force_self_update(&mut provider, ciphersuite, 32)?;
/// ```
pub fn force_self_update(
    provider: &mut DiMlsProvider,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<MlsMessageOut, Box<dyn Error>> {
    let mut group = send_group(provider)?;
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let (commit, _, _) = group
        .self_update(provider, provider, LeafNodeParameters::builder().build())?
        .into_messages();
    group.merge_pending_commit(provider)?;
    drop(store_exporter_psk(
        provider,
        &group,
        ciphersuite,
        exporter_length,
    )?);
    Ok(commit)
}

/// Force-add the provided key packages and return the `MlsMessageOut` Welcome message.
///
/// The caller should serialize this message and deliver it to the joiner(s) who will call
/// `process_welcome` to convert it into a group instance.
///
/// Example:
///
/// ```ignore
/// let welcome = force_add_members(&provider, &kps)?;
/// ```
pub fn force_add_members(
    provider: &DiMlsProvider,
    kps: &[KeyPackage],
) -> Result<MlsMessageOut, Box<dyn Error>> {
    let mut group = send_group(provider)?;
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let (_, welcome, _) = group.add_members_without_update(provider, provider, kps)?;
    group.merge_pending_commit(provider)?;
    Ok(welcome)
}

/// Inject queued PSKs into the send-group and return the staged commit message.
///
/// This returns an `MlsMessageOut` which can be serialized and sent on the wire. The
/// commit will be merged into the `group` state before returning.
///
/// Example:
///
/// ```ignore
/// let commit = inject_psks(&mut provider, &mut group, ciphersuite)?;
/// let commit_bytes = commit.tls_serialize_detached()?;
/// ```
pub fn inject_psks(
    provider: &mut DiMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<MlsMessageOut, Box<dyn Error>> {
    let mut group = send_group(provider)?;
    group.clear_pending_commit(provider.storage())?;
    group.clear_pending_proposals(provider.storage())?;
    let mut commit_builder = group.commit_builder();
    for psk_id_vec in provider.state_mut().clear_exporter_psk_ids().into_iter() {
        let proposal =
            Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(PreSharedKeyId::new(
                ciphersuite,
                provider.rand(),
                Psk::External(ExternalPsk::new(psk_id_vec)),
            )?)));
        commit_builder = commit_builder.add_proposal(proposal);
    }
    let (commit, _, _) = commit_builder
        .load_psks(provider.storage())?
        .build(provider.rand(), provider.crypto(), provider, |_| true)?
        .stage_commit(provider)?
        .into_messages();
    group.merge_pending_commit(provider)?;
    Ok(commit)
}

/// Derive a key to uniquely identify a commit generated using the current send-group state.
///
/// The commit key is simply an exporter using the current group state and the label "commit".
pub fn commit_key(
    provider: &DiMlsProvider,
    group: &MlsGroup,
    key_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(group.export_secret(provider.crypto(), "commit", &[], key_length)?)
}

pub fn try_join(
    provider: &mut DiMlsProvider,
    welcome: Welcome,
) -> Result<MlsGroup, Box<dyn Error>> {
    let group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::builder().build(),
        welcome,
        None,
    )?
    .into_group(provider)?;
    // add group id to state
    provider
        .state_mut()
        .add_other_group_id(group.group_id().clone());
    // done
    Ok(group)
}

pub fn send_group_commit_key(
    provider: &DiMlsProvider,
    key_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    commit_key(provider, &send_group(provider)?, key_length)
}

pub fn other_group_commit_keys(
    provider: &DiMlsProvider,
    key_length: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut commit_keys = Vec::new();
    for group_id in provider.state().other_group_ids().into_iter() {
        let group = MlsGroup::load(provider.storage(), &group_id)?.unwrap();
        commit_keys.push(commit_key(provider, &group, key_length)?);
    }
    Ok(commit_keys)
}

/// Load the local group matching the proto message group id and process the protocol message.
///
/// Returns the group (loaded before processing) and the `ProcessedMessage` result which the
/// caller can inspect to handle application messages or staged commits.
///
/// Example:
///
/// ```ignore
/// let (group, processed) = process_proto_msg(&provider, proto_msg)?;
/// ```
pub fn process_proto_msg(
    provider: &DiMlsProvider,
    proto_msg: ProtocolMessage,
) -> Result<(MlsGroup, ProcessedMessage), Box<dyn Error>> {
    match MlsGroup::load(provider.storage(), proto_msg.group_id())? {
        Some(mut g) => {
            let m = g.process_message(provider, proto_msg)?;
            match m.sender() {
                Sender::Member(leaf_idx) if leaf_idx.usize() == 0 => Ok((g, m)),
                _ => Err("Message not sent by the send group owner".into()),
            }
        }
        None => Err("No local group found with the given Group ID".into()),
    }
}

/// Convert an application message payload into a UTF-8 string.
///
/// Panics if the payload is not valid UTF-8; the function returns an `Err` in that case.
///
/// Example:
///
/// ```ignore
/// let s = plaintext(app_msg)?;
/// println!("plaintext: {}", s);
/// ```
pub fn plaintext(app_msg: ApplicationMessage) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(app_msg.into_bytes())
}

/// Apply a staged commit to the group and, if the group remains active, store the derived
/// exporter PSK and queue its id for later injection.
///
/// If the commit results in the local leaf being evicted, the group is deleted from storage.
///
/// Example:
///
/// ```ignore
/// apply_commit(&mut provider, &mut group, staged_commit, ciphersuite, 32)?;
/// ```
pub fn apply_commit(
    provider: &mut DiMlsProvider,
    group: &mut MlsGroup,
    commit: StagedCommit,
    ciphersuite: Ciphersuite,
    exporter_length: usize,
) -> Result<(), Box<dyn Error>> {
    group.merge_staged_commit(provider, commit)?;
    if group.is_active() {
        // store exporter-psk
        let psk_id_vec = store_exporter_psk(provider, group, ciphersuite, exporter_length)?;
        // enqueue this psk id to be injected on next commit
        provider.state_mut().push_exporter_psk_id(psk_id_vec);
        Ok(())
    } else {
        // delete group if evicted
        group.delete(provider.storage())?;
        Ok(())
    }
}

/// Directly create an `MlsMessageOut` application message from raw plaintext bytes.
///
/// This is the lower-level primitive behind `stdin_create_message_base64` and returns the
/// `MlsMessageOut` ready for serialization.
///
/// Example:
///
/// ```ignore
/// let msg = create_message(&provider, &mut group, b"Hello")?;
/// ```
pub fn create_message(
    provider: &DiMlsProvider,
    plaintext: &[u8],
) -> Result<MlsMessageOut, Box<dyn Error>> {
    Ok(send_group(provider)?.create_message(provider, provider, plaintext)?)
}
