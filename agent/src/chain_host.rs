//! What the signed chains need from the host that writes them (Wave 4
//! restructure, R04a, lab PR 241).
//!
//! The chain code — the canonical form, the writers, the verifiers — holds
//! no key: the writers sign with a [`ChainSigner`], which the host
//! implements (the agent: `crate::keys::AgentSigningKey`).

use ed25519_dalek::{Signature, VerifyingKey};

/// The key a chain writer signs with.
pub trait ChainSigner {
    /// Sign `msg` (a chain line's 32-byte digest).
    fn sign(&self, msg: &[u8]) -> Signature;

    /// The public half, the verifiers' key.
    fn verifying_key(&self) -> VerifyingKey;
}
