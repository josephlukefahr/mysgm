use super::provider::DiMlsProvider;
use core::error::Error;
use openmls::{
    credentials::{BasicCredential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{
        ApplicationMessage, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessage,
        ProtocolMessage, Sender,
    },
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedCommit, StagedWelcome},
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    messages::{
        Welcome,
        proposals::{PreSharedKeyProposal, Proposal},
    },
    prelude::Capabilities,
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
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
