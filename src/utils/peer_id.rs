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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known_peer_ids_are_valid() {
        let known_ids = [
            // From an AssetHub chain spec:
            "12D3KooWG3GrM6XKMM4gp3cvemdwUvu96ziYoJmqmetLZBXE8bSa",
            "12D3KooWMRyTLrCEPcAQD6c4EnudL3vVzg9zji3whvsMYPUYevpq",
            "12D3KooWLHqbcQtoBygf7GJgVjVa3TaeLuf7VbicNdooaCmQM2JZ",
            "12D3KooWNDrKSayoZXGGE2dRSFW2g1iGPq3fTZE2U39ma9yZGKd3",
            "12D3KooWApa2JW4rbLtgzuK7fjLMupLS9HZheX9cdkQKyu6AnGrP",
            "12D3KooWRsVeHqRs2iKmjLiguxp8myL4G2mDAWhtX2jHwyWujseV",
            "12D3KooWFrQjYaPZSSLLxEVmoaHFcrF6VoY4awG4KRSLaqy3JCdQ",
            "12D3KooWLwiJuvqQUB4kYaSjLenFKH9dWZhGZ4qi7pSb3sUYU651",
            "12D3KooWKgwQfAeDoJARdtxFNNWfbYmcu6s4yUuSifnNoDgzHZgm",
            "12D3KooWL8CyLww3m3pRySQGGYGNJhWDMqko3j5xi67ckP7hDUvo",
            "12D3KooW9uybhguhDjVJc3U3kgZC3i8rWmAnSpbnJkmuR7C6ZsRW",
            "12D3KooWByohP9FXn7ao8syS167qJsbFdpa7fY2Y24xbKtt3r7Ls",
            "12D3KooWEFrNuNk8fPdQS2hf34Gmqi6dGSvrETshGJUrqrvfRDZr",
            // From a Polkadot RC chain spec:
            "12D3KooWSz8r2WyCdsfWHgPyvD8GKQdJ1UAiRmrcrs8sQB3fe2KU",
            "12D3KooWFN2mhgpkJsDBuNuE5427AcDrsib8EoqGMZmkxWwx3Md4",
            "12D3KooWKvdDyRKqUfSAaUCbYiLwKY8uK3wDWpCuy2FiDLbkPTDJ",
            "12D3KooWCZKEvAMJRk9nwTHJcTjgVw6bDEqryQ3B7n7scNtfNqPB",
            "12D3KooWMFwJV935CyJXE8twfkKxRDnNWeEFd8jZWaoWZF22Hv8S",
            "12D3KooWS9ZcvRxyzrSf6p63QfTCWs12nLoNKhGux865crgxVA4H",
            "12D3KooWT2HyZx5C6BBeLbCKhYG2SqJYuiu7sLMxGzUcQBko3BMr",
            "12D3KooWPAVUgBaBk6n8SztLrMk8ESByncbAfRKUdxY1nygb9zG3",
            "12D3KooWK4E16jKk9nRhvC4RfrDVgcZzExg8Q3Q2G7ABUUitks1w",
            "12D3KooWRjHFApinuqSBjoaDjQHvxwubQSpEVy5hrgC9Smvh92WF",
            "12D3KooWHJBMZgt7ymAdTRtadPcGXpJw79vBGe8z53r9JMkZW7Ha",
            "12D3KooWFFqjBKoSdQniRpw1Y8W6kkV7takWv1DU2ZMkaA81PYVq",
            "12D3KooWNwWNRrPrTk4qMah1YszudMjxNw2qag7Kunhw3Ghs9ea5",
            "12D3KooWAb5MyC1UJiEQJk4Hg4B2Vi3AJdqSUhTGYUqSnEqCFMFg",
            "12D3KooWPyEvPEXghnMC67Gff6PuZiSvfx3fmziKiPZcGStZ5xff",
            "12D3KooWEjk6QXrZJ26fLpaajisJGHiz6WiQsR8k7mkM9GmWKnRZ",
            "12D3KooWAdyiVAaeGdtBt6vn5zVetwA4z4qfm9Fi2QCSykN1wTBJ",
            "12D3KooWT1PWaNdAwYrSr89dvStnoGdH3t4LNRbcVNN4JCtsotkR",
            "12D3KooWEymrFRHz6c17YP3FAyd8kXS5gMRLgkW4U77ZJD2ZNCLZ",
        ];

        for id in known_ids {
            let decoded_id = match PeerId::from_base58(id) {
                Ok(id) => id,
                Err(e) => {
                    panic!("Peer ID {id} could not be decoded: {e}");
                }
            };

            assert_eq!(decoded_id.to_base58(), id, "Round-trip decode/encode PeerId does not result in the same output");
        }
    }

    #[test]
    fn verify_ed25519_valid_signature() {
        let identity = Identity::from_random_bytes([42u8; 32]);
        let message = b"hello world";
        let signature = identity.sign(message);
        let pubkey = identity.public_key_bytes();

        assert!(verify_ed25519(&pubkey, message, &signature));
    }

    #[test]
    fn verify_ed25519_wrong_message() {
        let identity = Identity::from_random_bytes([42u8; 32]);
        let signature = identity.sign(b"hello world");
        let pubkey = identity.public_key_bytes();

        assert!(!verify_ed25519(&pubkey, b"wrong message", &signature));
    }

    #[test]
    fn verify_ed25519_wrong_key() {
        let identity = Identity::from_random_bytes([42u8; 32]);
        let other = Identity::from_random_bytes([99u8; 32]);
        let message = b"hello world";
        let signature = identity.sign(message);

        assert!(!verify_ed25519(&other.public_key_bytes(), message, &signature));
    }

    #[test]
    fn verify_ed25519_tampered_signature() {
        let identity = Identity::from_random_bytes([42u8; 32]);
        let message = b"hello world";
        let mut signature = identity.sign(message);
        signature[0] ^= 0xff;

        assert!(!verify_ed25519(&identity.public_key_bytes(), message, &signature));
    }
}