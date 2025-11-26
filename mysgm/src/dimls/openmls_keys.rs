//! Custom data structures for signing keys used by OpenMLS.
//!
//! This module provides lightweight wrappers around raw signature key bytes and exposes them
//! as types compatible with the OpenMLS storage traits. The goal is to demonstrate how a
//! simple, serializable key pair type can be implemented and integrated into the provider.
//!
//! The `SignatureKeyPair` type supports creation from an `OpenMlsCrypto` impl and exposes
//! the raw bytes for signing operations. The `SignaturePublicKey` type provides a compact
//! serializable representation suitable for storage and lookup.
//!
//! Example (pseudo-Rust):
//!
//! ```ignore
//! let (priv, pub) = crypto.signature_key_gen(SignatureScheme::ED25519)?;
//! let skp = SignatureKeyPair::from_raw(priv, pub, SignatureScheme::ED25519);
//! let pub_key = skp.public_key();
//! ```

use base64::{Engine, engine::general_purpose::STANDARD as Base64};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    storage::{CURRENT_VERSION, Entity, Key, traits},
    types::{CryptoError, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

/// A public signature key to be used instead of the default provided data structure.
///
/// This structure represents a public signature key, which is used in cryptographic
/// operations within MLS credentials. It provides methods to access the key's value
/// and implements necessary traits for storage and conversion.
#[serde_as]
#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct SignaturePublicKey {
    /// The raw bytes of the public key, serialized as base64.
    #[serde_as(as = "Base64")]
    value: Vec<u8>,
}

impl core::fmt::Debug for SignaturePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignaturePublicKey")
            .field("value", &Base64.encode(&self.value).to_string())
            .finish()
    }
}

impl Key<CURRENT_VERSION> for SignaturePublicKey {}

impl traits::SignaturePublicKey<CURRENT_VERSION> for SignaturePublicKey {}

impl From<SignaturePublicKey> for Vec<u8> {
    /// Converts a `SignaturePublicKey` into a `Vec<u8>`.
    ///
    /// This method allows for easy conversion of the public key into a byte vector,
    /// which can be useful for serialization or other operations requiring raw bytes.
    fn from(key: SignaturePublicKey) -> Vec<u8> {
        key.value
    }
}

impl SignaturePublicKey {
    /// Returns a reference to the bytes of the signature public key.
    ///
    /// This method provides access to the raw byte representation of the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

/// Create a `SignaturePublicKey` from raw bytes.
impl From<Vec<u8>> for SignaturePublicKey {
    fn from(value: Vec<u8>) -> Self {
        SignaturePublicKey { value }
    }
}

/// A signature key pair to be used instead of the default provided data structure.
///
/// This structure represents a pair of private and public keys used for signing
/// operations within MLS credentials. It includes methods to access the keys and
/// the signature scheme used to generate them.
#[serde_as]
#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct SignatureKeyPair {
    /// The raw bytes of the private key, serialized as base64.
    #[serde_as(as = "Base64")]
    private: Vec<u8>,
    /// The raw bytes of the public key, serialized as base64.
    #[serde_as(as = "Base64")]
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl core::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &Base64.encode(&self.private).to_string())
            .field("public", &Base64.encode(&self.public).to_string())
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Entity<CURRENT_VERSION> for SignatureKeyPair {}

impl traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}

impl SignatureKeyPair {
    /// Creates a new `SignatureKeyPair` from raw private and public keys and a signature scheme.
    ///
    /// # Parameters
    ///
    /// - `private`: The raw private key bytes.
    /// - `public`: The raw public key bytes.
    /// - `signature_scheme`: The signature scheme used to generate the keys.
    ///
    /// # Returns
    ///
    /// A new `SignatureKeyPair` instance.
    pub fn from_raw(private: Vec<u8>, public: Vec<u8>, signature_scheme: SignatureScheme) -> Self {
        Self {
            private,
            public,
            signature_scheme,
        }
    }
    /// Generates a new `SignatureKeyPair` using the provided cryptographic provider and signature scheme.
    ///
    /// # Parameters
    ///
    /// - `crypto`: The cryptographic provider implementing `OpenMlsCrypto`.
    /// - `signature_scheme`: The signature scheme to be used for key generation.
    ///
    /// # Returns
    ///
    /// A result containing the new `SignatureKeyPair` instance or a `CryptoError`.
    pub fn from_crypto<T: OpenMlsCrypto>(
        crypto: &T,
        signature_scheme: SignatureScheme,
    ) -> Result<Self, CryptoError> {
        let (private, public) = crypto.signature_key_gen(signature_scheme)?;
        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }
}

/// Additional ergonomic constructors and helpers for `SignatureKeyPair`.
impl SignatureKeyPair {
    /// Create a keypair directly from the cryptographic provider and return its base64-encoded
    /// public key for easy storage or display.
    ///
    /// Example:
    ///
    /// ```ignore
    /// let skp = SignatureKeyPair::from_crypto(&crypto, SignatureScheme::ED25519)?;
    /// let pub_b64 = base64::engine::general_purpose::STANDARD.encode(skp.public_key_raw());
    /// ```
    pub fn public_key_b64(&self) -> String {
        Base64.encode(&self.public)
    }
}

impl SignatureKeyPair {
    /// Returns a reference to the bytes of the signature private key.
    ///
    /// This method provides access to the raw byte representation of the private key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the private key.
    pub fn private_key_raw(&self) -> &[u8] {
        self.private.as_slice()
    }
    /// Returns a reference to the bytes of the signature public key.
    ///
    /// This method provides access to the raw byte representation of the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    pub fn public_key_raw(&self) -> &[u8] {
        self.public.as_slice()
    }
    /// Returns the `SignatureScheme` used to generate this key pair.
    ///
    /// This method provides access to the signature scheme associated with this key pair,
    /// which defines the cryptographic algorithm used for signing operations.
    ///
    /// # Returns
    ///
    /// The `SignatureScheme` used to generate this key pair.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
    /// Returns a copy of the signature public key structure.
    ///
    /// This method creates a new `SignaturePublicKey` instance containing the same
    /// public key value as this key pair.
    ///
    /// # Returns
    ///
    /// A `SignaturePublicKey` instance with the same public key value.
    pub fn public_key(&self) -> SignaturePublicKey {
        SignaturePublicKey {
            value: self.public.clone(),
        }
    }
}
