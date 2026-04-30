use core::pin::Pin;
use core::time::Duration;
use parity_scale_codec::Encode;
use polkadot_p2p_connect::{
    AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError, Configuration, Message, PlatformT,
    SubscriptionProtocol, SubscriptionResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    // 1. We'll need to know the genesis hash of the chain we connect to
    let genesis_hex = "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3";
    let genesis: [u8; 32] = hex::decode(genesis_hex).unwrap().try_into().unwrap();

    // 2. Configure the protocols that we support.
    let mut config: Configuration<TokioPlatform> = Configuration::new();

    let block_announce_id = config.add_protocol(SubscriptionProtocol::new(
        // The block-announces protocol name.
        format!("/{genesis_hex}/block-announces/1"),
        // The handshake we provide when subscribing.
        (
            // Role (2 == light client)
            2u8,     // Best block number we know about
            0,       // Best hash we know about
            genesis, // Genesis hash forchain
            genesis,
        )
            .encode(),
        // Is their handshake valid? Here just a basic check that the genesis hash lines up.
        move |remote_hs| remote_hs.len() >= 69 && remote_hs[37..69] == genesis,
    ));

    // 3. Establish a TCP connection to a node.
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

    // 3. Subscribe to our block announce protocol.
    conn.subscribe(block_announce_id)?;

    // 4. Stream events back from the peer on our subscribed protocol.
    while let Some(result) = conn.next().await {
        match result? {
            // Block announce notifications (id == block_announce_id):
            Message::Notification {
                protocol_id: id,
                res,
            } if id == block_announce_id => match res {
                SubscriptionResponse::Opened => {
                    eprintln!("Block announce subscription opened.");
                }
                SubscriptionResponse::Value(mut data) => {
                    // Chain-specific data; empty encoded Vec<u8> for Polkadot so 0u8.
                    data.pop();
                    // 0 == normal, 1 == best block.
                    let block_type = match data.pop() {
                        Some(0) => "normal",
                        Some(1) => "best",
                        _ => "unknown",
                    };
                    // The rest is the header.
                    let block_hash = hex::encode(block_hash(&data));
                    println!("hash={block_hash} type={block_type}");
                }
                SubscriptionResponse::Closed => {
                    eprintln!("Block announce subscription closed.");
                    break;
                }
                SubscriptionResponse::Error(e) => {
                    eprintln!("Block-announces subscription error: {e}");
                    break;
                }
            },
            // We won't get any other messages.
            o => eprintln!("Unexpected message: {o:?}"),
        }
    }

    Ok(())
}

fn block_hash(header: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};
    Blake2b::<U32>::digest(header).into()
}
