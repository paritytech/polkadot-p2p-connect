use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::utils::varint;
use crate::utils::protobuf;

// ---------------------------------------------------------------------------
// Noise handshake (exchanging of public keys)
// ---------------------------------------------------------------------------

/// The noise handshake payload that we send/receive to confirm eachothers identity
/// and share public keys so that we can generate a shared private key.
pub struct NoiseHandshakePayload {
    // An ed25519 public key
    pub key: [u8; 32],
    // A signature over a payload against the above key
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseHandshakeFromProtobufError {
    #[error("protobuf error decoding noise handshake payload: {0}")]
    Protobuf(#[from] protobuf::Error),
    #[error("invalid noise handshake payload, got bytes: {0:?}")]
    InvalidNoisePayload(Vec<u8>),
    #[error("invalid key shape in noise handshake payload, got bytes: {0:?}")]
    InvalidKey(Vec<u8>),
    #[error("invalid key length in noise handshake payload, got {0} but expected 32")]
    InvalidKeyLength(usize),
    #[error("invalid signature length in noise handshake payload, got {0} but expected 64")]
    InvalidSignatureLength(usize),
}

impl NoiseHandshakePayload {
    pub fn to_protobuf(&self, out: &mut [u8]) -> usize {
        // First, protobuf-encode the 32 byte key.
        let (encoded_key, encoded_key_len) = {
            let mut k = [0u8; 128];
            let len = protobuf::encode(&mut k)
                .encode_varint(1, 1u8)
                .encode_data(2, &self.key)
                .num_encoded();
            (k, len)
        };

        // Now encode the outer payload which is the key + signature,
        // and return the number of bytes we encoded (ie wrote to out)
        protobuf::encode(out)
            .encode_data(1, &encoded_key[..encoded_key_len])
            .encode_data(2, &self.signature)
            .num_encoded()
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, NoiseHandshakeFromProtobufError> {
        // First we decode the bytes into an identity key and signature.
        let (key_protobuf, signature) = Self::decode_outer_noise_payload_protobuf(bytes)?;

        // The key is also a protobuf encoded thing from which we
        // extract the ed25519 key bytes (or error if a different format).
        let key = Self::decode_ed25519_public_key_protobuf(key_protobuf)?;

        Ok(Self {
            key,
            signature,
        })
    }

    /// Decode the outermost noise payload message into a protobuf encoded key and a signature.
    fn decode_outer_noise_payload_protobuf(data: &[u8]) -> Result<(&[u8], [u8; 64]), NoiseHandshakeFromProtobufError> {
        struct NoiseVisitor<'a> {
            identity_key: Option<&'a [u8]>,
            identity_sig: Option<&'a [u8]>,
        }
        impl <'input> protobuf::Visitor<'input> for NoiseVisitor<'input> {
            fn data(&mut self, field_id: u64, bytes: &'input [u8]) {
                if field_id == 1 {
                    self.identity_key = Some(bytes);
                } else if field_id == 2 {
                    self.identity_sig = Some(bytes)
                }
            }
        }
    
        let mut visitor = NoiseVisitor { identity_key: None, identity_sig: None };
        protobuf::decode(&mut &*data, &mut visitor)?;
    
        let signature: [u8; 64] = if let Some(sig_bytes) = visitor.identity_sig {
            sig_bytes.try_into().map_err(|_| NoiseHandshakeFromProtobufError::InvalidSignatureLength(sig_bytes.len()))?
        } else {
            return Err(NoiseHandshakeFromProtobufError::InvalidNoisePayload(data.to_vec()))
        };

        let key: &[u8] = if let Some(key_bytes) = visitor.identity_key {
            key_bytes
        } else {
            return Err(NoiseHandshakeFromProtobufError::InvalidNoisePayload(data.to_vec()))
        };

        Ok((key, signature))
    }

    /// Decode a protobuf encoded `PublicKey`, returning the raw 32-byte Ed25519 key.
    fn decode_ed25519_public_key_protobuf(data: &[u8]) -> Result<[u8; 32], NoiseHandshakeFromProtobufError> {
        struct KeyVisitor<'a> {
            ty: Option<u64>,
            value: Option<&'a [u8]>
        }
        impl <'input> protobuf::Visitor<'input> for KeyVisitor<'input> {
            fn varint(&mut self, field_id: u64, n: u64) {
                if field_id == 1 {
                    self.ty = Some(n);
                }
            } 
            fn data(&mut self, field_id: u64, bytes: &'input [u8]) {
                if field_id == 2 {
                    self.value = Some(bytes);
                }
            }
        }

        let mut visitor = KeyVisitor { ty: None, value: None };
        protobuf::decode(&mut &*data, &mut visitor)?;

        let (Some(1), Some(key_data)) = (visitor.ty, visitor.value) else {
            return Err(NoiseHandshakeFromProtobufError::InvalidKey(data.to_vec()))
        };
        if key_data.len() != 32 {
            return Err(NoiseHandshakeFromProtobufError::InvalidKeyLength(key_data.len()));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(key_data);
        Ok(out)
    }
}

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
// PeerId (a representation of a public key)
// ---------------------------------------------------------------------------

/// A libp2p PeerId — the multihash of a protobuf-encoded public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerId {
    multihash: Vec<u8>,
}

impl PeerId {
    // Take an ed25519 public key and convert it to a PeerId.
    pub (crate) fn from_ed25519_public_key(key: [u8; 32]) -> Self {
        let mut multihash = Vec::with_capacity(36);
        multihash.push(0x00);

        // Encode the length of the protobuf ed25519 key, which is 36:
        // - 1 byte: field 1, type varint.
        //   - 1 byte: field 1 value: 1u8.
        // - 1 byte: field 2, type data.
        //   - 1 byte: field 2 data length (32).
        //   - 32 bytes: field 2 data (key bytes).
        // See decode_ed25519_public_key_protobuf which follows this.
        varint::encode_to_vec(36, &mut multihash);

        let mut buf = [0u8; 36];
        let n = protobuf::encode(&mut buf)
            .encode_varint(1, 1u8)
            .encode_data(2, &key)
            .num_encoded();
        multihash.extend_from_slice(&buf[..n]);

        PeerId { multihash }
    }

    /// Parse a PeerId from a base58-encoded string (as found in multiaddrs).
    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;

        //// TODO: Validate multihash structure: code (varint) + length (varint) + digest
        // {
        //     let cursor = &mut &*bytes;
        //     let code = varint::decode(cursor)?;
        //     let digest_len = varint::decode(cursor)?;
        //     // The remaining bytes should equal the length.
        //     if cursor.len() != digest_len {
        //         // TODO: Validate
        //     }
        // }

        Ok(PeerId { multihash: bytes })
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
