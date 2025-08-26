use super::{
    keys::SignatureKeyPair, opendht::OpenDhtRestAdapter, provider::MySgmProvider, state::MySgmState,
};
use core::error::Error;
use hex::encode as hex_encode;
use openmls::{
    ciphersuite::signature::SignaturePublicKey,
    credentials::{BasicCredential, Credential, CredentialType, CredentialWithKey},
    extensions::ExtensionType,
    framing::{
        ApplicationMessage, ContentType, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        ProcessedMessage, ProcessedMessageContent, ProtocolMessage, Sender as MlsSender,
    },
    group::{
        GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, QueuedProposal, StagedCommit,
        StagedWelcome,
    },
    key_packages::{KeyPackage, key_package_in::KeyPackageIn},
    messages::{Welcome, group_info::VerifiableGroupInfo, proposals::Proposal},
    prelude::Capabilities,
    schedule::PreSharedKeyId,
    treesync::LeafNodeParameters,
    versions::ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand, types::Ciphersuite};
use serde_json::{from_str as json_decode, to_string as json_encode};
use std::fs::{read_to_string as read_file_to_string, write as write_string_to_file};
use tls_codec::{Deserialize, Serialize, DeserializeBytes};

#[derive(Debug)]
pub struct MySgmAgent {
    adapter: OpenDhtRestAdapter,
    provider: MySgmProvider,
    capabilities: Capabilities,
    group_config: MlsGroupCreateConfig,
}

impl MySgmAgent {
    pub fn init(provider: MySgmProvider) -> Self {
        // opendht adapter
        let adapter = OpenDhtRestAdapter::new("localhost", 8000);
        // capabilities
        let capabilities = Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::LastResort]),
            None,
            Some(&[CredentialType::Basic]),
        );
        // config
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(provider.state().my_ciphersuite())
            .use_ratchet_tree_extension(true)
            .capabilities(capabilities.clone())
            .build();
        // done
        Self {
            adapter,
            provider,
            capabilities,
            group_config,
        }
    }
    pub fn new(pid: &str) -> Result<Self, Box<dyn Error>> {
        // crypto
        let crypto: RustCrypto = Default::default();
        // ciphersuite
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        // signature key pair
        let signature_key_pair = SignatureKeyPair::from_crypto(&crypto, ciphersuite.into())?;
        // new provider; done
        Ok(MySgmAgent::init(MySgmProvider::new(
            MySgmState::new(
                format!(
                    "{}__{}",
                    pid,
                    hex_encode(signature_key_pair.public_key_raw())
                        .chars()
                        .take(8)
                        .collect::<String>()
                ),
                signature_key_pair,
                ciphersuite,
                ProtocolVersion::Mls10,
            ),
            crypto,
        )))
    }
    pub fn load(file_path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(MySgmAgent::init(MySgmProvider::new(
            json_decode(&read_file_to_string(file_path)?)?,
            Default::default(),
        )))
    }
}

impl MySgmAgent {
    pub fn save(&self, file_path: &str) -> Result<(), Box<dyn Error>> {
        Ok(write_string_to_file(
            file_path,
            json_encode(self.provider.state())?,
        )?)
    }
    pub fn credential_str(&self) -> &str {
        self.provider.state().credential_str()
    }
    pub fn agent_ids(&self) -> Vec<String> {
        self.provider.state().agent_ids()
    }
    pub fn group_ids(&self) -> Vec<String> {
        self.provider.state().group_ids()
    }
    pub fn exporter(
        &self,
        gid_transformed: &str,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(gid_transformed.as_bytes()),
        )?
        .ok_or("Group not found")?
        .export_secret(&self.provider, label, context, length)?)
    }
    pub fn create_group(&mut self, gid_label: &str) -> Result<String, Box<dyn Error>> {
        let gid_transformed = format!(
            "{}__{}",
            gid_label,
            hex::encode(self.provider.rand().random_vec(4).unwrap())
        );
        let _ = MlsGroup::new_with_group_id(
            &self.provider,
            &self.provider,
            &self.group_config,
            GroupId::from_slice(gid_transformed.as_bytes()),
            self.new_credential_with_key(),
        )?;
        self.provider
            .state_mut()
            .add_group_id(gid_transformed.clone());
        Ok(gid_transformed)
    }
    pub fn advertise(&mut self) -> Result<(), Box<dyn Error>> {
        let kp_bytes = self.new_key_package()?.tls_serialize_detached()?;
        let mut kp_counter = self.provider.state().key_package_log().len();
        loop {
            match self
                .adapter
                .put_checked(&format!("kp_{kp_counter}"), &kp_bytes)
            {
                Ok(()) => {
                    return Ok(());
                }
                Err(e) => {
                    if e.to_string() == "Key already exists" {
                        kp_counter += 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
    pub fn process_next_welcome_message(&mut self) -> Result<(), Box<dyn Error>> {
        let welcome_counter = self.provider.state().welcome_counter();
        match self.adapter.get(&format!("wm_{welcome_counter}"))? {
            None => Err("NoNewWelcomeMessages".into()),
            Some(wm_bytes) => {
                self.provider.state_mut().increment_welcome_counter();
                eprintln!("Welcome message bytes: {}", hex_encode(&wm_bytes));
                let (wm_in, extra_bytes) = Welcome::tls_deserialize_bytes(&wm_bytes)?;
                eprintln!("Extra bytes after Welcome deserialization: {}", hex_encode(&extra_bytes));
                let welcome = StagedWelcome::new_from_welcome(
                    &self.provider,
                    self.group_config.join_config(),
                    wm_in,
                    None,
                )?;
                let group = welcome.into_group(&self.provider)?;
                self.provider
                    .state_mut()
                    .add_group_id(String::from_utf8_lossy(group.group_id().as_slice()).to_string());
                Ok(())
            }
        }
    }
    pub fn process_next_key_package(&mut self) -> Result<(), Box<dyn Error>> {
        let kp_counter = self.provider.state().key_package_log().len();
        match self.adapter.get(&format!("kp_{kp_counter}"))? {
            None => Err("NoNewKeyPackages".into()),
            Some(kp_bytes) => {
                let kp_in = KeyPackageIn::tls_deserialize_exact(&kp_bytes).inspect_err(|_| {
                    let _ = self.provider.state_mut().log_key_package(None);
                })?;
                let kp = kp_in
                    .validate(self.provider.crypto(), self.provider.state().mls_version())
                    .inspect_err(|_| {
                        let _ = self.provider.state_mut().log_key_package(None);
                    })?;
                let cred = BasicCredential::try_from(kp.leaf_node().credential().clone())
                    .inspect_err(|_| {
                        let _ = self.provider.state_mut().log_key_package(None);
                    })?;
                let log_index = self.provider.state_mut().log_key_package(Some(kp));
                self.provider.state_mut().set_key_package_log_index(
                    &String::from_utf8_lossy(cred.identity()),
                    log_index,
                );
                Ok(())
            }
        }
    }
    pub fn group_members(&self, gid_transformed: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let group = MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(gid_transformed.as_bytes()),
        )?
        .ok_or("Group not found")?;
        let mut member_ids: Vec<String> = Vec::new();
        for member in group.members() {
            let cred = BasicCredential::try_from(member.credential.clone())?;
            member_ids.push(String::from_utf8_lossy(cred.identity()).to_string());
        }
        Ok(member_ids)
    }
    pub fn add_to_group(
        &mut self,
        gid_transformed: &str,
        pids: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        let mut group = MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(gid_transformed.as_bytes()),
        )?
        .ok_or("Group not found")?;
        let exporter = group.export_secret(&self.provider, "post_commit", &[], 32)?;
        let mut kps: Vec<KeyPackage> = Vec::new();
        for pid in pids {
            kps.push(
                self.get_key_package(pid)
                    .ok_or("Key package not found")?
                    .clone(),
            );
        }
        let (commit, welcome, _) =
            group.add_members_without_update(&self.provider, &self.provider, &kps)?;
        // post commit
        self.adapter.put_checked(
            &format!("cm_{}", hex_encode(exporter)),
            &commit.tls_serialize_detached()?,
        )?;
        // apply commit
        group.merge_pending_commit(&self.provider)?;
        // post welcome
        let mut wm_counter = self.provider.state().welcome_counter();
        loop {
            match self.adapter.put_checked(
                &format!("wm_{wm_counter}"),
                &welcome.tls_serialize_detached()?,
            ) {
                Ok(()) => {
                    break;
                }
                Err(e) => {
                    if e.to_string() == "Key already exists" {
                        wm_counter += 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
    /*
    pub fn add_to_group(
        &mut self,
        gid_transformed: &str,
        pids: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        let group = MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(gid_transformed.as_bytes()),
        )?
        .ok_or("group not found".into())?;
        let mut kps: Vec<KeyPackage> = Vec::new();
        for pid in pids {
            kps.push(
                self.provider
                    .state()
                    .key_package_log()
                    .get(
                        self.provider
                            .state()
                            .get_key_package(pid)
                            .ok_or("agent id not found".into())?,
                    )
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .clone(),
            );
        }
        log::debug!("Key packages to include in commit: {kps:?}");
        let (commit, welcome, _) =
            group.add_members_without_update(&self.provider, &self.provider, &kps)?;
        Ok(())
    }
        */
}

impl MySgmAgent {
    fn new_credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(
                self.provider.state().credential_str().as_bytes().to_vec(),
            )
            .into(),
            signature_key: self
                .provider
                .state()
                .signature_key_pair()
                .public_key_raw()
                .into(),
        }
    }
    fn new_key_package(&self) -> Result<KeyPackage, Box<dyn Error>> {
        Ok(KeyPackage::builder()
            .leaf_node_capabilities(self.capabilities.clone())
            .mark_as_last_resort()
            .build(
                self.provider.state().my_ciphersuite(),
                &self.provider,
                &self.provider,
                self.new_credential_with_key(),
            )?
            .key_package()
            .clone())
    }
    fn get_key_package(&self, pid: &str) -> Option<&KeyPackage> {
        self.provider
            .state()
            .get_key_package_log_index(pid)
            .and_then(|log_index| {
                self.provider
                    .state()
                    .key_package_log()
                    .get(log_index)
                    .unwrap()
                    .as_ref()
            })
    }
}
