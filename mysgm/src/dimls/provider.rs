//! DiMls provider implementation wiring OpenMLS crypto and storage to application state.
//!
//! `DiMlsProvider` is the glue between the `DiMlsState` (persistent application state), the
//! `OpenMlsKeyValueStore` (storage backend), and the cryptographic provider (`RustCrypto`).
//! It implements the `OpenMlsProvider` trait required by the OpenMLS library and the `Signer`
//! trait used when producing credentials or signing commits.
//!
//! Example (pseudo-Rust):
//!
//! ```ignore
//! let provider = DiMlsProvider::new(state, RustCrypto::default());
//! let storage = provider.storage();
//! let signature = provider.sign(payload)?;
//! ```

use super::{openmls_kvstore::OpenMlsKeyValueStore, state::DiMlsState};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    OpenMlsProvider,
    crypto::OpenMlsCrypto,
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};

/// The main provider struct for DiMls, implementing the OpenMLS provider interface.
///
/// Example usage of `DiMlsProvider`:
///
/// ```ignore
/// let state = DiMlsState::new(signature_key_pair);
/// let provider = DiMlsProvider::new(state, RustCrypto::default());
/// let storage = provider.storage();
/// ```
#[derive(Debug)]
pub struct DiMlsProvider {
    /// The persistent DiMls state, including protocol version and key-value store.
    state: DiMlsState,
    /// The cryptographic backend (RustCrypto) for OpenMLS operations.
    crypto: RustCrypto,
}

#[allow(clippy::from_over_into)]
impl Into<DiMlsState> for DiMlsProvider {
    fn into(self) -> DiMlsState {
        self.state
    }
}

impl DiMlsProvider {
    /// Creates a new `DiMlsProvider` with the given state and cryptographic backend.
    ///
    /// # Arguments
    /// * `state` - The persistent DiMls state.
    /// * `crypto` - The cryptographic backend (RustCrypto).
    ///
    /// # Returns
    /// A new `DiMlsProvider` instance.
    pub fn new(state: DiMlsState, crypto: RustCrypto) -> Self {
        Self { state, crypto }
    }
    /// Returns a reference to the internal DiMls state.
    pub fn state(&self) -> &DiMlsState {
        &self.state
    }
    /// Returns a mutable reference to the internal DiMls state.
    pub fn state_mut(&mut self) -> &mut DiMlsState {
        &mut self.state
    }
}

/// Implements the OpenMLS provider trait for DiMls, wiring up crypto, random, and storage providers.
impl OpenMlsProvider for DiMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = OpenMlsKeyValueStore;
    /// Returns a reference to the OpenMLS storage provider (key-value store).
    fn storage(&self) -> &Self::StorageProvider {
        self.state.openmls_values()
    }
    /// Returns a reference to the cryptographic backend (RustCrypto).
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    /// Returns a reference to the random provider (RustCrypto).
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Signer for DiMlsProvider {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(
                self.state.signature_key_pair().signature_scheme(),
                payload,
                self.state.signature_key_pair().private_key_raw(),
            )
            .map_err(SignerError::CryptoError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        self.state.signature_key_pair().signature_scheme()
    }
}
