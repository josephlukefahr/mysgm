//! An in-memory key-value store that implements the OpenMLS `StorageProvider` trait.
//!
//! This store is intentionally simple and designed for example/demo use. It stores all keys and values
//! as base64-encoded strings inside a `HashMap<String, String>` protected by a `RwLock` for basic
//! concurrent access. Binary data (group state, secrets, key packages) is serialized with Serde and then
//! base64-encoded before insertion.
//!
//! Important notes:
//! - This store is serializable via Serde making it easy to persist or snapshot for tests.
//! - Encoding everything as base64 keeps the map string-only and avoids issues with binary keys/values.
//! - The implementation focuses on correctness and readability for learning; it's not optimized for
//!   production use or large-scale storage.
//!
//! Example use (pseudo-Rust):
//!
//! ```ignore
//! let store = OpenMlsKeyValueStore::default();
//! // write a group state
//! store.write_group_state(&group_id, &group_state)?;
//! // read it back
//! let gs = store.group_state(&group_id)?;
//! ```

use base64::{Engine, engine::general_purpose::STANDARD as Base64};
// use log;
use openmls_traits::storage::{CURRENT_VERSION, Entity, StorageProvider, traits};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
// use serde_json;
use std::{collections::HashMap, sync::RwLock};

/// A key-value store for OpenMLS state, using base64 encoding for all keys and values.
///
/// This store is thread-safe and serializable, and is intended for use as a backend for the
/// OpenMLS `StorageProvider` trait. All data is stored in a `HashMap<String, String>`, where both
/// keys and values are base64-encoded. This allows for safe storage of binary data in a string-based map.
#[derive(Debug, Default)]
pub struct OpenMlsKeyValueStore {
    /// The underlying map of base64-encoded keys and values, protected by a read-write lock for thread safety.
    values: RwLock<HashMap<String, String>>,
}

/// Implements deep cloning for the key-value store, duplicating all stored data.
impl Clone for OpenMlsKeyValueStore {
    /// Creates a deep clone of the key-value store, including all stored key-value pairs.
    fn clone(&self) -> Self {
        let values = self.values.read().unwrap();
        Self {
            values: RwLock::new(values.clone()),
        }
    }
}

/// Enables serialization of the key-value store using Serde.
impl Serialize for OpenMlsKeyValueStore {
    /// Serializes the internal map using Serde.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let values = self.values.read().unwrap();
        values.serialize(serializer)
    }
}

/// Enables deserialization of the key-value store using Serde.
impl<'de> Deserialize<'de> for OpenMlsKeyValueStore {
    /// Deserializes the internal map using Serde.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = HashMap::deserialize(deserializer)?;
        Ok(Self {
            values: RwLock::new(values),
        })
    }
}

impl OpenMlsKeyValueStore {
    /// Writes a single value to the store, encoding both key and value as base64.
    /// Internal helper to abstract write operations.
    #[inline(always)]
    /// Stores a value for a given label and key, using the provided version.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    /// * `value` - The value to store, as a vector of bytes.
    ///
    /// # Returns
    /// * `Result<(), ...>` - Returns Ok on success, or an error if the operation fails.
    fn write<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        log::trace!("{}", std::backtrace::Backtrace::capture());

        values.insert(Base64.encode(storage_key), Base64.encode(value));
        Ok(())
    }

    /// Appends a value to a list stored at the given label and key, using the provided version.
    ///
    /// If the list does not exist, it is created. The value is pushed to the end of the list.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    /// * `value` - The value to append, as a vector of bytes.
    ///
    /// # Returns
    /// * `Result<(), ...>` - Returns Ok on success, or an error if the operation fails.
    fn append<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        log::trace!("{}", std::backtrace::Backtrace::capture());

        // fetch value from db, falling back to an empty list if doens't exist
        let list_bytes = values
            .entry(Base64.encode(storage_key))
            .or_insert("[]".to_owned());

        // parse old value and push new data
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(&Base64.decode(&list_bytes).unwrap())?;
        list.push(value);

        // write back, reusing the old buffer
        list_bytes.truncate(0);
        let encoded = Base64.encode(serde_json::to_vec(&list)?);
        list_bytes.push_str(&encoded);

        Ok(())
    }

    /// Removes a specific value from a list stored at the given label and key, using the provided version.
    ///
    /// If the value is found in the list, it is removed. If the list does not exist, nothing happens.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    /// * `value` - The value to remove, as a vector of bytes.
    ///
    /// # Returns
    /// * `Result<(), ...>` - Returns Ok on success, or an error if the operation fails.
    fn remove_item<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        log::trace!("{}", std::backtrace::Backtrace::capture());

        // fetch value from db, falling back to an empty list if doens't exist
        let list_bytes = values
            .entry(Base64.encode(storage_key))
            .or_insert("[]".to_owned());

        // parse old value, find value to delete and remove it from list
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(&Base64.decode(&list_bytes).unwrap())?;
        if let Some(pos) = list.iter().position(|stored_item| stored_item == &value) {
            list.remove(pos);
        }

        // write back, reusing the old buffer
        list_bytes.truncate(0);
        let encoded = Base64.encode(serde_json::to_vec(&list)?);
        list_bytes.push_str(&encoded);

        Ok(())
    }

    /// Internal helper to abstract read operations.
    #[inline(always)]
    /// Reads a value from the store for the given label and key, using the provided version.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    ///
    /// # Returns
    /// * `Result<Option<V>, ...>` - Returns Some(value) if found, or None if not found.
    fn read<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let values = self.values.read().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value = values.get(&Base64.encode(storage_key));

        if let Some(value) = value {
            serde_json::from_slice(&Base64.decode(value).unwrap())
                .map_err(|_| OpenMlsKeyValueStoreError::SerializationError)
                .map(|v| Some(v))
        } else {
            Ok(None)
        }
    }

    /// Internal helper to abstract read operations.
    #[inline(always)]
    /// Reads a list of values from the store for the given label and key, using the provided version.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    ///
    /// # Returns
    /// * `Result<Vec<V>, ...>` - Returns a vector of values if found, or an empty vector if not found.
    fn read_list<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let values = self.values.read().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value: Vec<Vec<u8>> = match values.get(&Base64.encode(storage_key)) {
            Some(list_bytes) => {
                serde_json::from_slice(&Base64.decode(list_bytes).unwrap()).unwrap()
            }
            None => vec![],
        };

        value
            .iter()
            .map(|value_bytes| serde_json::from_slice(value_bytes))
            .collect::<Result<Vec<V>, _>>()
            .map_err(|_| OpenMlsKeyValueStoreError::SerializationError)
    }

    /// Internal helper to abstract delete operations.
    #[inline(always)]
    /// Deletes a value from the store for the given label and key, using the provided version.
    ///
    /// # Arguments
    /// * `label` - A byte slice representing the label for the key.
    /// * `key` - A byte slice representing the key.
    ///
    /// # Returns
    /// * `Result<(), ...>` - Returns Ok on success, or an error if the operation fails.
    fn delete<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        log::trace!("{}", std::backtrace::Backtrace::capture());

        values.remove(&Base64.encode(storage_key));

        Ok(())
    }
}

/// Errors thrown by the key store.
/// Errors that can be returned by the OpenMlsKeyValueStore.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OpenMlsKeyValueStoreError {
    // UnsupportedValueTypeBytes,
    // UnsupportedMethod,
    SerializationError,
}

/// Implements Display for OpenMlsKeyValueStoreError for readable error messages.
impl core::fmt::Display for OpenMlsKeyValueStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Implements the standard Error trait for OpenMlsKeyValueStoreError.
impl core::error::Error for OpenMlsKeyValueStoreError {}

/// Label for key package storage.
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
/// Label for pre-shared key (PSK) storage.
const PSK_LABEL: &[u8] = b"Psk";
/// Label for encryption key pair storage.
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
/// Label for signature key pair storage.
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
/// Label for epoch key pairs storage.
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";

// related to PublicGroup
/// Label for tree storage (related to PublicGroup).
const TREE_LABEL: &[u8] = b"Tree";
/// Label for group context storage (related to PublicGroup).
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
/// Label for interim transcript hash storage (related to PublicGroup).
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
/// Label for confirmation tag storage (related to PublicGroup).
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";

// related to MlsGroup
/// Label for MLS group join config storage (related to MlsGroup).
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
/// Label for own leaf nodes storage (related to MlsGroup).
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
/// Label for group state storage (related to MlsGroup).
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
/// Label for queued proposal storage (related to MlsGroup).
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
/// Label for proposal queue references storage (related to MlsGroup).
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
/// Label for own leaf node index storage (related to MlsGroup).
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
/// Label for epoch secrets storage (related to MlsGroup).
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
/// Label for resumption PSK store (related to MlsGroup).
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
/// Label for message secrets storage (related to MlsGroup).
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

impl StorageProvider<CURRENT_VERSION> for OpenMlsKeyValueStore {
    type Error = OpenMlsKeyValueStoreError;

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        // write proposal to key (group_id, proposal_ref)
        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        let value = serde_json::to_vec(proposal)?;
        self.write::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key, value)?;

        // update proposal list for group_id
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.append::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        Ok(())
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            TREE_LABEL,
            &serde_json::to_vec(&group_id).unwrap(),
            serde_json::to_vec(&tree).unwrap(),
        )
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(INTERIM_TRANSCRIPT_HASH_LABEL, group_id);
        let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

        values.insert(Base64.encode(key), Base64.encode(value));
        Ok(())
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(GROUP_CONTEXT_LABEL, group_id);
        let value = serde_json::to_vec(&group_context).unwrap();

        values.insert(Base64.encode(key), Base64.encode(value));
        Ok(())
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(CONFIRMATION_TAG_LABEL, group_id);
        let value = serde_json::to_vec(&confirmation_tag).unwrap();

        values.insert(Base64.encode(key), Base64.encode(value));
        Ok(())
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let key =
            build_key::<CURRENT_VERSION, &SignaturePublicKey>(SIGNATURE_KEY_PAIR_LABEL, public_key);
        let value = serde_json::to_vec(&signature_key_pair).unwrap();

        values.insert(Base64.encode(key), Base64.encode(value));
        Ok(())
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;

        refs.into_iter()
            .map(|proposal_ref| -> Result<_, _> {
                let key = (group_id, &proposal_ref);
                let key = serde_json::to_vec(&key)?;

                let proposal = self.read(QUEUED_PROPOSAL_LABEL, &key)?.unwrap();
                Ok((proposal_ref, proposal))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let values = self.values.read().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(TREE_LABEL, group_id);

        let Some(value) = values.get(&Base64.encode(key)) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap();

        Ok(value)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let values = self.values.read().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(GROUP_CONTEXT_LABEL, group_id);

        let Some(value) = values.get(&Base64.encode(key)) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap();

        Ok(value)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let values = self.values.read().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(INTERIM_TRANSCRIPT_HASH_LABEL, group_id);

        let Some(value) = values.get(&Base64.encode(key)) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap();

        Ok(value)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let values = self.values.read().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(CONFIRMATION_TAG_LABEL, group_id);

        let Some(value) = values.get(&Base64.encode(key)) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap();

        Ok(value)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let values = self.values.read().unwrap();

        let key =
            build_key::<CURRENT_VERSION, &SignaturePublicKey>(SIGNATURE_KEY_PAIR_LABEL, public_key);

        let Some(value) = values.get(&Base64.encode(key)) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap();

        Ok(value)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();
        let value = serde_json::to_vec(&key_package).unwrap();

        self.write::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &key, value)
            .unwrap();

        Ok(())
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            PSK_LABEL,
            &serde_json::to_vec(&psk_id).unwrap(),
            serde_json::to_vec(&psk).unwrap(),
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
            serde_json::to_vec(key_pair).unwrap(),
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();
        self.read(KEY_PACKAGE_LABEL, &key)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read(PSK_LABEL, &serde_json::to_vec(&psk_id).unwrap())
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
        )
    }

    fn delete_signature_key_pair<
        SignaturePublicKeuy: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
        )
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &serde_json::to_vec(&hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(PSK_LABEL, &serde_json::to_vec(&psk_id)?)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read(GROUP_STATE_LABEL, &serde_json::to_vec(&group_id)?)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_state)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(message_secrets)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs)?;
        log::debug!("Writing encryption epoch key pairs");

        self.write::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key, value)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, key);
        log::debug!("Reading encryption epoch key pairs");

        let values = self.values.read().unwrap();
        let value = values.get(&Base64.encode(storage_key));

        if let Some(value) = value {
            return Ok(serde_json::from_slice(&Base64.decode(value).unwrap()).unwrap());
        }

        Ok(vec![])
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        // Get all proposal refs for this group.
        let proposal_refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;
        let mut values = self.values.write().unwrap();
        for proposal_ref in proposal_refs {
            // Delete all proposals.
            let key = serde_json::to_vec(&(group_id, proposal_ref))?;
            values.remove(&Base64.encode(key));
        }

        // Delete the proposal refs from the store.
        let key = build_key::<CURRENT_VERSION, &GroupId>(PROPOSAL_QUEUE_REFS_LABEL, group_id);
        values.remove(&Base64.encode(key));

        Ok(())
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id).unwrap();
        let value = serde_json::to_vec(config).unwrap();

        self.write::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &key, value)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(leaf_node)?;
        self.append::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(TREE_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id).unwrap(),
        )
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id).unwrap())
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id).unwrap(),
        )
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id).unwrap();
        let value = serde_json::to_vec(proposal_ref).unwrap();

        self.remove_item::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key = serde_json::to_vec(&(group_id, proposal_ref)).unwrap();
        self.delete::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key)
    }
}

/// Builds a key by concatenating the label, key, and version as bytes.
///
/// # Arguments
/// * `label` - A byte slice representing the label.
/// * `key` - The key as a vector of bytes.
///
/// # Returns
/// * `Vec<u8>` - The constructed key as a vector of bytes.
fn build_key_from_vec<const V: u16>(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut key_out = label.to_vec();
    key_out.extend_from_slice(&key);
    key_out.extend_from_slice(&u16::to_be_bytes(V));
    key_out
}

/// Build a storage key from a label and a serializable key, returning a deterministic byte vector.
///
/// This is used to create unique map keys for different OpenMLS entities by appending a version
/// number and serializing the key argument. The resulting byte vector is then base64-encoded for
/// insertion into the internal map.
///
/// Example:
///
/// ```ignore
/// let storage_key = build_key::<CURRENT_VERSION, _>(b"GroupState", &group_id);
/// ```
fn build_key<const V: u16, K: Serialize>(label: &[u8], key: K) -> Vec<u8> {
    build_key_from_vec::<V>(label, serde_json::to_vec(&key).unwrap())
}

/// Builds a unique key for epoch key pairs by serializing the group ID, epoch, and leaf index.
///
/// # Arguments
/// * `group_id` - The group ID implementing the GroupId trait.
/// * `epoch` - The epoch implementing the EpochKey trait.
/// * `leaf_index` - The leaf index as a u32.
///
/// # Returns
/// * `Result<Vec<u8>, ...>` - The constructed key as a vector of bytes, or an error if serialization fails.
fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, <OpenMlsKeyValueStore as StorageProvider<CURRENT_VERSION>>::Error> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

/// Converts Serde JSON errors into OpenMlsKeyValueStoreError::SerializationError.
impl From<serde_json::Error> for OpenMlsKeyValueStoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::SerializationError
    }
}
