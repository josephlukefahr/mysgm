//! Persistent application state for a DiMls agent.
//!
//! `DiMlsState` stores the local signing key pair, an optional send-group id (the group this agent
//! uses for sending application messages), a queue of exporter PSK identifiers produced during commits,
//! and the `OpenMlsKeyValueStore` that holds all OpenMLS group state and secrets.
//!
//! The state is serializable and designed to be written to disk (as a JSON file) between runs of the
//! example agent; the CLI demonstrates writing and reading this JSON file to persist identity and
//! group membership across invocations.
//!
//! Example (pseudo-Rust):
//!
//! ```ignore
//! // create new state with generated signature key pair
//! let state = DiMlsState::new(signature_key_pair);
//! // set send group id after creating a group
//! state.set_send_group_id(group.group_id().clone());
//! // persist to disk using serde_json
//! let json = serde_json::to_string(&state)?;
//! ```

use super::{openmls_keys::SignatureKeyPair, openmls_kvstore::OpenMlsKeyValueStore};
use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use openmls::group::GroupId;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::mem::take;

/// The main persistent state struct for a DiMls agent.
///
/// Holds the current OpenMLS protocol version and a key-value store for all OpenMLS-related values.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct DiMlsState {
    #[serde_as(as = "Base64")]
    send_group_id: Vec<u8>,
    #[serde_as(as = "Vec<Base64>")]
    other_group_ids: Vec<Vec<u8>>,
    #[serde_as(as = "Vec<Base64>")]
    exporter_psk_queue: Vec<Vec<u8>>,
    signature_key_pair: SignatureKeyPair,
    /// The in-memory, thread-safe key-value store for all OpenMLS values.
    openmls_values: OpenMlsKeyValueStore,
}

impl core::fmt::Debug for DiMlsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DiMlsState")
            .field(
                "send_group_id",
                &Base64.encode(&self.send_group_id).to_string(),
            )
            .field(
                "other_group_ids",
                &self
                    .other_group_ids
                    .iter()
                    .map(|v| Base64.encode(v).to_string())
                    .collect::<Vec<String>>(),
            )
            .field(
                "exporter_psk_queue",
                &self
                    .exporter_psk_queue
                    .iter()
                    .map(|v| Base64.encode(v).to_string())
                    .collect::<Vec<String>>(),
            )
            .field("signature_key_pair", &self.signature_key_pair)
            .field("openmls_values", &self.openmls_values)
            .finish()
    }
}

impl AsRef<OpenMlsKeyValueStore> for DiMlsState {
    fn as_ref(&self) -> &OpenMlsKeyValueStore {
        self.openmls_values()
    }
}

impl AsRef<SignatureKeyPair> for DiMlsState {
    fn as_ref(&self) -> &SignatureKeyPair {
        self.signature_key_pair()
    }
}

impl DiMlsState {
    /// Creates a new `DiMlsState` with the specified MLS protocol version.
    ///
    /// # Returns
    /// A new `DiMlsState` instance with an empty key-value store.
    pub fn new(signature_key_pair: SignatureKeyPair) -> Self {
        // done
        Self {
            exporter_psk_queue: Vec::new(),
            other_group_ids: Vec::new(),
            send_group_id: Vec::new(),
            signature_key_pair,
            openmls_values: Default::default(),
        }
    }
}

impl DiMlsState {
    /// Set the send-group id for this state.
    ///
    /// The send-group id is used by helper functions to locate the group used for sending
    /// application messages. The id is stored as bytes in the state and will be used by
    /// `send_group()` to load the `MlsGroup` instance.
    pub fn set_send_group_id(&mut self, send_group_id: GroupId) {
        self.send_group_id = send_group_id.as_slice().to_vec();
    }
    /// Get the send-group id for this state, if set.
    ///
    /// Returns `None` if no send-group id has been set. Otherwise, returns the `GroupId`.
    pub fn send_group_id(&self) -> Option<GroupId> {
        if self.send_group_id.is_empty() {
            None
        } else {
            Some(GroupId::from_slice(&self.send_group_id))
        }
    }
    pub fn add_other_group_id(&mut self, group_id: GroupId) {
        self.other_group_ids.push(group_id.as_slice().to_vec());
    }
    pub fn remove_other_group_id(&mut self, group_id: &GroupId) {
        self.other_group_ids
            .retain(|gid_bytes| GroupId::from_slice(gid_bytes) != *group_id);
    }
    pub fn other_group_ids(&self) -> Vec<GroupId> {
        self.other_group_ids
            .iter()
            .map(|gid_bytes| GroupId::from_slice(gid_bytes))
            .collect()
    }
    /// Push an exporter PSK identifier onto the local queue.
    ///
    /// Exporter PSK ids are produced when handling commits that rotate keys. These ids are
    /// queued for later injection into the group using `inject_psks` helpers.
    pub fn push_exporter_psk_id(&mut self, psk: Vec<u8>) {
        self.exporter_psk_queue.push(psk);
    }
    /// Clear and return all queued exporter PSK identifiers.
    ///
    /// This consumes the queue and returns the queued PSK ids for processing or injection.
    pub fn clear_exporter_psk_ids(&mut self) -> Vec<Vec<u8>> {
        take(&mut self.exporter_psk_queue)
    }
    /// Returns a reference to the internal signature key pair.
    pub fn signature_key_pair(&self) -> &SignatureKeyPair {
        &self.signature_key_pair
    }
    /// Returns a reference to the internal OpenMLS key-value store.
    pub fn openmls_values(&self) -> &OpenMlsKeyValueStore {
        &self.openmls_values
    }
}
