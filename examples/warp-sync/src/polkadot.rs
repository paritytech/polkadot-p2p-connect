//! Hardcoded configuration and types for the Polkadot Relay Chain.

use parity_scale_codec::{Decode, Encode};

/// Polkadot genesis hash.
pub const GENESIS_HASH: [u8; 32] =
    hex_literal::hex!("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3");

/// Polkadot genesis GRANDPA authorities (set_id = 0).
pub const GENESIS_AUTHORITIES: [([u8; 32], u64); 6] = [
    (hex_literal::hex!("dea6f4a727d3b2399275d6ee8817881f10597471dc1d27f144295ad6fb933c7a"), 1),
    (hex_literal::hex!("48b623941c2a4d41cf25ef495408690fc853f777192498c0922eab1e9df4f061"), 1),
    (hex_literal::hex!("f72daf2e560e4f0f22fb5cbb04ad1d7fee850aab238fd014c178769e7e3a9b84"), 1),
    (hex_literal::hex!("1c151c11cb72334d26d70769e3af7bbff3801a4e2dca2b09b7cce0af8dd81307"), 1),
    (hex_literal::hex!("680d278213f908658a49a1025a7f466c197e8fb6fabb5e62220a7bd75f860cab"), 1),
    (hex_literal::hex!("8e59368700ea89e2bf8922cc9e4b86d6651d1c689a0d57813f9768dbaadecf71"), 1),
];

pub type BlockHash = [u8; 32];
pub type Hash = [u8; 32];

/// Polkadot block headers.
#[derive(Clone, Debug, Encode, Decode)]
pub struct BlockHeader {
    pub parent_hash: BlockHash,
    #[codec(compact)]
    pub number: u32,
    pub state_root: Hash,
    pub extrinsics_root: Hash,
    pub digest: BlockDigest,
}

impl BlockHeader {
    pub fn hash(&self) -> BlockHash {
        use blake2::digest::consts::U32;
        use blake2::{Blake2b, Digest};
        Blake2b::<U32>::digest(&self.encode()).into()
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct BlockDigest {
    pub logs: Vec<BlockDigestItem>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum BlockDigestItem {
    #[codec(index = 0)]
    Other(Vec<u8>),
    #[codec(index = 4)]
    Consensus(ConsensusEngineId, Vec<u8>),
    #[codec(index = 5)]
    Seal(ConsensusEngineId, Vec<u8>),
    #[codec(index = 6)]
    PreRuntime(ConsensusEngineId, Vec<u8>),
    #[codec(index = 8)]
    RuntimeEnvironmentUpdated,
}

/// Consensus engine ID.
#[derive(Clone, Copy, Debug, Encode, Decode)]
pub struct ConsensusEngineId([u8; 4]);

impl ConsensusEngineId {
    pub fn is_grandpa(&self) -> bool {
        self.0 == *b"FRNK"
    }
}
