mod grandpa;
mod polkadot;

use core::pin::Pin;
use core::time::Duration;
use parity_scale_codec::Encode;
use polkadot_p2p_connect::{
    AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError, Configuration, Message, PlatformT,
    RequestProtocol, RequestResponse, RequestResponseError, SubscriptionProtocol,
    SubscriptionResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use grandpa::GrandpaState;
use polkadot::{GENESIS_AUTHORITIES, GENESIS_HASH};

/// Provide a tokio-based [`AsyncRead`] implementation.
struct TokioTcpReader(tokio::net::tcp::OwnedReadHalf);
impl AsyncRead for TokioTcpReader {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), AsyncReadError> {
        AsyncReadExt::read_exact(&mut self.0, buf)
            .await
            .map(|_| ())
            .map_err(AsyncReadError::new)
    }
}

/// Provide a tokio-based [`AsyncWrite`] implementation.
struct TokioTcpWriter(tokio::net::tcp::OwnedWriteHalf);
impl AsyncWrite for TokioTcpWriter {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), AsyncWriteError> {
        AsyncWriteExt::write_all(&mut self.0, data)
            .await
            .map_err(AsyncWriteError::new)
    }
}

/// Provide a tokio-based [`PlatformT`] implementation.
struct TokioPlatform;
impl PlatformT for TokioPlatform {
    type Sleep = Pin<Box<tokio::time::Sleep>>;

    fn fill_with_random_bytes(bytes: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(bytes);
    }

    fn sleep(duration: Duration) -> Self::Sleep {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let genesis_hex = hex::encode(GENESIS_HASH);

    // Configure the protocols we need.
    let mut config: Configuration<TokioPlatform> = Configuration::new();

    // Block announces subscription (required for the peer to consider us connected).
    let block_announce_id = config.add_protocol(SubscriptionProtocol::new(
        format!("/{genesis_hex}/block-announces/1"),
        // Handshake: (role=2 light client, best_number=0, best_hash=genesis, genesis_hash)
        (2u8, 0u32, GENESIS_HASH, GENESIS_HASH).encode(),
        // Validate their handshake: check that the genesis hash matches.
        move |remote_hs| remote_hs.len() >= 69 && remote_hs[37..69] == GENESIS_HASH,
    ));

    // GRANDPA notification protocol. The peer will try to open this substream and
    // will reject us if we don't support it, so we must configure it even though
    // we don't use the GRANDPA notifications during warp sync.
    let _grandpa_id = config.add_protocol(SubscriptionProtocol::new(
        format!("/{genesis_hex}/grandpa/1"),
        // Handshake is a single NodeRole byte (2 = Light).
        vec![2u8],
        // Accept any valid handshake (just a single role byte).
        |remote_hs| remote_hs.len() == 1,
    ));

    // Warp sync request-response protocol.
    let warp_sync_id = config.add_protocol(
        RequestProtocol::new(format!("/{genesis_hex}/sync/warp"))
            .with_max_response_size(16 * 1024 * 1024) // 16 MB
            .with_timeout(Duration::from_secs(60)),
    );

    // Connect to a Polkadot bootnode via TCP.
    eprintln!("Connecting to polkadot-bootnode-0.polkadot.io:30333...");
    let tcp = TcpStream::connect(("polkadot-bootnode-0.polkadot.io", 30333)).await?;
    let (read_half, write_half) = tcp.into_split();
    let mut conn = config
        .connect(TokioTcpReader(read_half), TokioTcpWriter(write_half))
        .await?;

    eprintln!(
        "Connected! Us: {}, Them: {}",
        conn.our_id(),
        conn.their_id()
    );

    // Subscribe to block announces (needed for the peer to maintain the connection).
    conn.subscribe(block_announce_id)?;

    // Initialize GRANDPA state from genesis.
    let mut grandpa_state = GrandpaState {
        authorities: GENESIS_AUTHORITIES.to_vec(),
        set_id: 0,
        finalized_number: 0,
        finalized_hash: GENESIS_HASH,
    };

    // Drive the connection event loop. We wait for the block-announces subscription
    // to open (indicating the peer considers us connected), then begin making warp
    // sync requests until we've caught up to the latest finalized block.
    while let Some(result) = conn.next().await {
        match result? {
            // Block announce subscription events:
            Message::Notification {
                protocol_id,
                res: SubscriptionResponse::Opened,
            } if protocol_id == block_announce_id => {
                eprintln!("Block announce subscription opened, starting warp sync...");
                eprintln!("Requesting warp sync from #{}", grandpa_state.finalized_number);
                conn.request(warp_sync_id, grandpa_state.finalized_hash.to_vec())?;
            }
            Message::Notification {
                protocol_id,
                res: SubscriptionResponse::Closed,
            } if protocol_id == block_announce_id => {
                anyhow::bail!("Block announce subscription closed by peer");
            }
            Message::Notification {
                protocol_id,
                res: SubscriptionResponse::Error(e),
            } if protocol_id == block_announce_id => {
                anyhow::bail!("Block announce subscription error: {e}");
            }

            // Warp sync responses:
            Message::Response {
                protocol_id,
                res: RequestResponse::Value(bytes),
                ..
            } if protocol_id == warp_sync_id => {
                let is_finished = grandpa_state
                    .update_with_warp_sync_response(&bytes)
                    .map_err(|e| anyhow::anyhow!(e))?;

                eprintln!(
                    "  Warp sync progress: block #{}, set_id={}, {} authorities",
                    grandpa_state.finalized_number,
                    grandpa_state.set_id,
                    grandpa_state.authorities.len(),
                );

                if is_finished {
                    eprintln!(
                        "Warp sync complete! Finalized block #{}, hash=0x{}",
                        grandpa_state.finalized_number,
                        hex::encode(grandpa_state.finalized_hash),
                    );
                    return Ok(());
                }

                // Not finished yet; request the next chunk from our new finalized hash.
                eprintln!("Requesting warp sync from #{}", grandpa_state.finalized_number);
                conn.request(warp_sync_id, grandpa_state.finalized_hash.to_vec())?;
            }
            Message::Response {
                protocol_id,
                res: RequestResponse::Error(
                    e @ (RequestResponseError::ProtocolRejected
                    | RequestResponseError::ClosedByRemote),
                ),
                ..
            } if protocol_id == warp_sync_id => {
                eprintln!("Warp sync request failed ({e}), retrying after delay...");
                tokio::time::sleep(Duration::from_secs(1)).await;
                conn.request(warp_sync_id, grandpa_state.finalized_hash.to_vec())?;
            }
            Message::Response {
                protocol_id,
                res: RequestResponse::Error(e),
                ..
            } if protocol_id == warp_sync_id => {
                anyhow::bail!("Warp sync request failed: {e}");
            }
            Message::Response {
                protocol_id,
                res: RequestResponse::Cancelled,
                ..
            } if protocol_id == warp_sync_id => {
                anyhow::bail!("Warp sync request was cancelled");
            }

            // Ignore all other messages (block announce values, etc).
            _ => {}
        }
    }

    anyhow::bail!("Connection closed before warp sync completed");
}
