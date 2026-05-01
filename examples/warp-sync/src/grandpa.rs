use std::collections::{HashMap, HashSet};
use crate::polkadot::{Hash, BlockHash, BlockHeader, BlockDigestItem};
use parity_scale_codec::{Decode, Encode};

/// The current GRANDPA state that we are aware of.
pub struct GrandpaState {
    /// A list of authority public keys that we trust, and their weights (normally 1)
    pub authorities: Vec<(AuthorityId, u64)>,
    /// The set ID. This increments by 1 each time the authorities (validators) change,
    /// and begins at 0 at genesis.
    pub set_id: u64,
    /// The block height / number of the finalized block. At genesis this is 0.
    pub finalized_number: u32,
    /// The block hash of the finalized block. At genesis this is the genesis hash.
    pub finalized_hash: BlockHash,
}

/// The ed25519 public key for an authority.
pub type AuthorityId = [u8; 32];

impl GrandpaState {
    /// Update our GRANDPA state given some warp sync response bytes from a peer. Returns
    /// an error if something went wrong during the updates (while still updating as much 
    /// as possible). If things go OK, returns a boolean indicating whether we are "done"
    /// (if false, then we should request another warp sync response from the latest finalized 
    /// block hash to update further).
    pub fn update_with_warp_sync_response(
        &mut self, 
        response_bytes: &[u8]
    ) -> Result<bool, String> {
        let response = wire_format::WarpSyncResponse::decode(&mut &response_bytes[..])
            .map_err(|e| format!("failed to decode warp sync response: {}", e))?;

        // Go through each fragment we received and validate it, progressing our knowledge
        // of what the latest finalized block and authority set is.
        let num_fragments = response.fragments.len();
        for (i, fragment) in response.fragments.into_iter().enumerate() {
            let is_last = response.is_finished && i == num_fragments - 1;
            self.process_warp_sync_fragment(fragment, is_last)?;
        }

        Ok(response.is_finished)
    }

    fn process_warp_sync_fragment(
        &mut self,
        fragment: wire_format::WarpSyncFragment,
        is_last_fragment: bool,
    ) -> Result<(), String> {
        let header = &fragment.header;
        let justification = &fragment.justification;

        // Each fragment should advance to a higher header number. 
        // Reject any attempts to revert to a lower one.
        if header.number <= self.finalized_number {
            return Err(format!(
                "fragment block #{} does not advance finality (current #{})",
                header.number,
                self.finalized_number,
            ));
        }

        // The justification target hash must reference the header
        // we we given, else an attacker could provide a different 
        // header containing invalid details (eg invalid authority set change)
        let header_hash = header.hash();
        if justification.target_hash != header_hash {
            return Err(format!(
                "justification target_hash ({}) does not match header hash ({})",
                hex::encode(&header_hash),
                hex::encode(&justification.target_hash),
            ));
        }

        // The block numbers should also line up.
        if justification.target_number != header.number {
            return Err(format!(
                "justification target_number mismatch: header #{}, justification #{}",
                header.number, 
                justification.target_number,
            ));
        }

        // Now, verify this justification against our current authority
        // set details. If valid, we are good to use it to advance our warp sync.
        self.verify_warp_sync_justification(justification)?;

        // Now we've verified the justification, we trust that the block header
        // we were given is a valid finalized block, so now we extract the new
        // authorities from it. All but the last fragment should have an
        // authority set change.
        let new_authorities = find_warp_sync_grandpa_authority_change(header);
        if new_authorities.is_none() && !is_last_fragment {
            return Err(format!(
                "non-final fragment at #{} has no authority change, but we expect one for all but the last fragment",
                header.number,
            ));
        }

        self.finalized_hash = header_hash;
        self.finalized_number = header.number;
        if let Some(authorities) = new_authorities {
            // Authority set change means we increment the set ID.
            self.set_id += 1;
            self.authorities = authorities;
        }

        Ok(())
    }

    fn verify_warp_sync_justification(
        &self,
        justification: &wire_format::GrandpaJustification,
    ) -> Result<(), String> {
        // Build a set of all block hashes which are valid targets.
        // These are any block hashes that are children of the target hash.
        // We do this because GRANDPA authorities can vote for blocks in
        // forks, but the actual block we finalize can be the most voted for
        // common parent of these blocks.
        let valid_targets = build_ancestry_set(justification);

        let authority_set: HashMap<[u8; 32], u64> = self
            .authorities
            .iter()
            .map(|(k, w)| (*k,*w))
            .collect();
        let total_weight: u64 = self.authorities.iter().map(|(_, w)| w).sum();

        // Byzantine fault tolerance requires strictly more than 2/3 of total weight.
        // Integer equivalent: signed_weight > floor(2*total/3), i.e. >= floor(2*total/3)+1.
        let threshold = (total_weight * 2) / 3;

        // Now, add valid signatures to the signed weight, 
        // disallowing duplicate authorities.
        let mut signed_weight: u64 = 0;
        let mut seen_authorities = HashSet::new();

        for precommit in &justification.precommits {
            // Ignore precommits from public keys not in the current authority
            // set. Without this, an attacker could pad a justification with signatures
            // from arbitrary keypairs they control to reach the supermajority threshold.
            let Some(authority_weight) = authority_set.get(&precommit.authority_id) else {
                tracing::warn!(
                    "justification precommit invalid: authority {} is not in the authority set",
                    hex::encode(precommit.authority_id)
                );
                continue
            };

            // Ignore duplicate precommits from the same authority. Without
            // this, a single authority's vote could be counted multiple times, allowing
            // fewer than 2/3 of validators to finalize a block.
            if !seen_authorities.insert(precommit.authority_id) {
                tracing::warn!(
                    "justification precommit invalid: authority {} has already appeared in justification",
                    hex::encode(precommit.authority_id)
                );
                continue
            }

            // Only count weight for precommits targeting the justification block or a
            // provable descendant of it.
            if !valid_targets.contains(&precommit.target_hash) {
                tracing::debug!(
                    "justification precommit ignored: authority {} signing target hash {} which is not the finalized block or a child of it",
                    hex::encode(precommit.authority_id),
                    hex::encode(precommit.target_hash),
                );
                continue;
            }

            // Verify the ed25519 signature. The signed message binds the vote to a
            // specific (round, set_id) pair, preventing cross-round/cross-set replays.
            if let Err(_e) = verify_precommit_signature(
                precommit,
                justification.round,
                self.set_id,
            ) {
                tracing::debug!(
                    "justification precommit invalid: precommit by authority {} has an invalid signature",
                    hex::encode(precommit.authority_id),
                );
                continue;
            }

            // Everything valid, so add to our signed weight.
            signed_weight += *authority_weight;

            // If we have enough weight now we are done. We could validate the rest of
            // the signatures and check that nothing weird exists, but we have seen
            // enough valid signatures that can't be faked, and we trust the threshold
            // that we are aiming for, so bail and save some effort.
            if signed_weight > threshold {
                return Ok(())
            }
        }

        // if we got this far then we didn't gather enough weight,
        // so bail with an error.
        Err(format!(
            "insufficient precommit weight: {} <= {}",
            signed_weight, threshold,
        ))
    }

}

/// Extract GRANDPA authority change from a header digest, ignoring the delay.
/// This is used during warp sync where the delay is not relevant (the proof includes
/// the block where the change is enacted).
fn find_warp_sync_grandpa_authority_change(header: &BlockHeader) -> Option<Vec<([u8; 32], u64)>> {
    for log in &header.digest.logs {
        if let BlockDigestItem::Consensus(engine, data) = log {
            if engine.is_grandpa() && let Ok(msg) = GrandpaConsensusMessage::decode(&mut &**data) {
                match msg {
                    GrandpaConsensusMessage::ScheduledChange { authorities, .. }
                    | GrandpaConsensusMessage::ForcedChange { authorities, .. } => {
                        return Some(authorities);
                    }
                }
            }
        }
    }
    None
}

/// Verify a single precommit ed25519 signature.
fn verify_precommit_signature(
    precommit: &wire_format::SignedPrecommit,
    round: u64,
    set_id: u64,
) -> Result<(), String> {
    let payload_bytes = SignerPayload {
        vote_type: 1u8, // Precommit enum variant,
        target_hash: precommit.target_hash,
        target_number: precommit.target_number,
        round,
        set_id,
    }.encode();

    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&precommit.authority_id)
        .map_err(|e| format!("invalid public key: {}", e))?;
    let signature = ed25519_dalek::Signature::from_bytes(&precommit.signature);

    public_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|e| format!("signature verification failed: {}", e))
}

/// Work out which block hashes are valid targets given the `target_hash` of some justification.
/// All block hashes for blocks which are descendents of the target hash are valid.
fn build_ancestry_set(justification: &wire_format::GrandpaJustification) -> HashSet<[u8; 32]> {
    let mut valid_block_hashes = HashSet::new();

    // The target hash is a valid hash for authorities to commit to
    valid_block_hashes.insert(justification.target_hash);

    // Pre-compute hashes for all ancestry headers.
    let ancestry: Vec<([u8; 32], [u8; 32])> = justification
        .votes_ancestries
        .iter()
        .map(|h| (h.hash(), h.parent_hash))
        .collect();

    // Iteratively expand the valid set: a header is a valid descendant if its
    // parent_hash is already in the set. Repeat until no new entries are added.
    loop {
        let mut added = false;
        for (hash, parent_hash) in &ancestry {
            if valid_block_hashes.contains(parent_hash) && valid_block_hashes.insert(*hash) {
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    valid_block_hashes
}

#[derive(Decode)]
pub enum GrandpaConsensusMessage {
    #[codec(index = 1)]
    ScheduledChange {
        authorities: Vec<(AuthorityId, u64)>,
        _delay: u32,
    },
    #[codec(index = 2)]
    ForcedChange {
        _reset_block_height: u32,
        authorities: Vec<(AuthorityId, u64)>,
        _delay: u32,
    },
}

/// The bytes that were signed for a [`SignedPrecommit`].
#[derive(Encode)]
struct SignerPayload {
    vote_type: u8, // should be 1u8 for Precommits.
    target_hash: Hash,
    target_number: u32,
    round: u64,
    set_id: u64,
}

// The shape of the bytes we receive when asking for warp sync details.
mod wire_format {
    use super::AuthorityId;
    use parity_scale_codec::{Encode, Decode};
    use crate::polkadot::{BlockHeader, BlockHash};

    #[derive(Encode, Decode, Debug)]
    pub struct WarpSyncResponse {
        pub fragments: Vec<WarpSyncFragment>,
        pub is_finished: bool,
    }

    #[derive(Encode, Decode, Debug)]
    pub struct WarpSyncFragment {
        pub header: BlockHeader,
        pub justification: GrandpaJustification,
    }

    #[derive(Encode, Decode, Debug)]
    pub struct GrandpaJustification {
        pub round: u64,
        pub target_hash: BlockHash,
        pub target_number: u32,
        pub precommits: Vec<SignedPrecommit>,
        pub votes_ancestries: Vec<BlockHeader>,
    }

    #[derive(Encode, Decode, Debug)]
    pub struct SignedPrecommit {
        pub target_hash: BlockHash,
        pub target_number: u32,
        pub signature: Signature,
        pub authority_id: AuthorityId,
    }

    pub type Signature = [u8; 64];
}