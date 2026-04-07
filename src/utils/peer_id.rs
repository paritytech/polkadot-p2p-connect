use alloc::string::String;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::utils::varint;
use crate::utils::protobuf;

// ---------------------------------------------------------------------------
// Identity (our public + private keypair)
// ---------------------------------------------------------------------------

/// Ed25519 identity keypair for libp2p peer authentication.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Instantiate a new identity. the bytes given should be randomly generated.
    pub fn from_random_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes)
        }
    }

    /// Raw 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Derive the PeerId from this identity's public key.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_ed25519_public_key(self.public_key_bytes())
    }

    /// Sign a message with Ed25519. Returns a 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// PeerId (a representation of a public key; can come from our identity or a multiaddr string)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PeerIdFromBase58Error {
    #[error("peer ID does not seem to be an ed25519 key")]
    NotEd25519,
    #[error("base58 decode error: {0:?}")]
    Base58(bs58::decode::Error),
    #[error("expected key length {expected} but got {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("cannot decode varint: {0}")]
    CannotDecodeVarint(varint::Error),
}

/// The expected length of a PeerId in bytes.
const PEER_ID_LEN: usize = 38;

/// A libp2p PeerId — the multihash of a protobuf-encoded public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerId {
    multihash: [u8; PEER_ID_LEN],
}

impl PeerId {
    // Take an ed25519 public key and convert it to a PeerId.
    pub (crate) fn from_ed25519_public_key(key: [u8; 32]) -> Self {
        let mut buf = [0u8; PEER_ID_LEN];

        // 0x00 is an Identity type (for ed25519 keys).
        buf[0] = 0x00;

        // Now we varint encode the length of the key (36).
        varint::encode(36, &mut buf[1..]);

        // Now we protobuf encode the key.
        protobuf::encode(&mut buf[2..])
            .encode_varint(1, 1u8)
            .encode_data(2, &key)
            .num_encoded();

        PeerId { multihash: buf }
    }

    /// Parse a PeerId from a base58-encoded string (as found in multiaddrs).
    pub fn from_base58(s: &str) -> Result<Self, PeerIdFromBase58Error> {
        let mut buf = [0u8; PEER_ID_LEN];
        let num_bytes_decoded = bs58::decode(s)
            .onto(&mut buf)
            .map_err(PeerIdFromBase58Error::Base58)?;

        if num_bytes_decoded != PEER_ID_LEN {
            return Err(PeerIdFromBase58Error::WrongLength { expected: PEER_ID_LEN, actual: num_bytes_decoded })
        }

        // Validate multihash structure (see encoding above).
        {
            let cursor: &mut &[u8] = &mut &buf[..];

            // Hash function code: only 0x00 (identity) is valid for Ed25519 PeerIds.
            let code = varint::decode(cursor).map_err(PeerIdFromBase58Error::CannotDecodeVarint)?;
            if code != 0x00 {
                return Err(PeerIdFromBase58Error::NotEd25519);
            }

            // Length of the remaining bytes must be 36.
            let digest_len = varint::decode(cursor).map_err(PeerIdFromBase58Error::CannotDecodeVarint)?;
            if cursor.len() != 36 && digest_len != 36 {
                return Err(PeerIdFromBase58Error::WrongLength { expected: 36, actual: cursor.len() })
            }
        }

        Ok(PeerId { multihash: buf })
    }

    /// Convert a [`PeerId`] to a base58 string.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.multihash).into_string()
    }
}

impl core::fmt::Display for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl core::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PeerId({})", self.to_base58())
    }
}
