# polkadot-p2p-connector

This is a no-std compatible library for communicating with peers on the Polkadot network. Being no-std, it can be wired up to work in the browser, run natively using tokio, or other. It is focused on connecting to a single peer and interacting with it. Other libraries could use this under the hood to manage multiple peer connections.

Here's an example of subscribing to block announcements from a peer:

```rust
use core::pin::Pin;
use core::time::Duration;
use parity_scale_codec::Encode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use polkadot_p2p_connector::{
    AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError, Configuration, Message, PlatformT,
    SubscriptionProtocol, SubscriptionResponse,
};

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
    let genesis: [u8; 32] = hex::decode(genesis_hex)
        .unwrap()
        .try_into()
        .unwrap();

    // 2. Configure the protocols that we support.
    let mut config: Configuration<TokioPlatform> = Configuration::new();

    let block_announce_id = config.add_protocol(SubscriptionProtocol::new(
        // The block-announces protocol name.
        format!("/{genesis_hex}/block-announces/1"),
        // The handshake we provide when subscribing.
        (
            // Role (2 == light client)
            2u8,
            // Best block number we know about
            0,
            // Best hash we know about
            genesis,
            // Genesis hash forchain
            genesis,
        ).encode(),
        // Is their handshake valid? Here just a basic check that the genesis hash lines up.
        move |remote_hs| remote_hs.len() >= 69 && remote_hs[37..69] == genesis,
    ));

    // 3. Establish a TCP connection to a node.
    let tcp = TcpStream::connect(("polkadot-bootnode-0.polkadot.io", 30333)).await?;
    let (read_half, write_half) = tcp.into_split();
    let mut conn = config.connect(TokioTcpReader(read_half), TokioTcpWriter(write_half)).await?;

    eprintln!("Connected! Us: {}, Them: {}", conn.our_id(), conn.their_id());

    // 3. Subscribe to our block announce protocol.
    conn.subscribe(block_announce_id)?;

    // 4. Stream events back from the peer on our subscribed protocol.
    while let Some(result) = conn.next().await {
        match result? {
            // Block announce notifications (id == block_announce_id):
            Message::Notification { protocol_id: id, res } if id == block_announce_id => match res {
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
                        _ => "unknown"
                    };
                    // The rest is the header.
                    let block_hash = hex::encode(&block_hash(&data));
                    println!("hash={block_hash} type={block_type}");
                },
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
            o => eprintln!("Unexpected message: {o:?}")
        }
    }

    Ok(())
}

fn block_hash(header: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};
    Blake2b::<U32>::digest(&header).into()
}
```

# Protocol Overview

Connecting to a peer on the polkadot network essentially involves these steps:

1. Agree on and establish noise encryption; this involves a key exchange, after which all communication is encrypted inside packets which are prefixed by a u16 denoting the packet length.
2. Inside this encrypted packet stream, agree on and establish a yamux session. Yamux is a lightweight protocol which allows multiple substreams to be opened and closed within this single stream of bytes.
3. Now, we use a simple multistream select protocol inside different Yamux substreams to agree on what sort of data will be sent in each substream.
4. On top of this, Polkadot has a couple of protocol types; "request-response" protocols which use a single substream to send a request and expect a response back on, and "notification" protocols which involve two substreams and bi-directional handshakes; these allow for the bidirectional streaming of data.

Given some way to read and write bytes to a stream (denoted by the `AsyncRead` and `AsyncWrite` traits), and a basic `Platform` implementation to provide some key functionality, this library handles all of the above steps and provides an API to request or subscribe on different protocols.

# FAQ

## Why do I have to provide implementations for things like `PlatformT`, `AsyncRead` and `AsyncWrite`?

This library is no-std (+alloc) (which is why `cargo check --target thumbv7em-none-eabi` will work in it). This means that it does not natively have access to things like randomness (which is required for the noise encryption for example), and has no way to time things. The `PlatformT` trait allows the user to provide this necessary funcionality for whichever platform they want to run this library in.

Being no-std also means no networking facilities, so once again the user must bring their own networking and implement `AsyncRead` and `AsyncWrite` for whichever stream of data they wish to connect to a peer on. This also makes it easy to test many parts of the codebase, and allows implementations to target pure TCP connections, or WebSocket connections (inside a browser or natively) easy to do. 

## Why do I have to define the protocols that I'll use up front?

When we connect to a peer, we are both a client _and_ a server. On the one hand, we can request data from the peer and open subscriptions to it, but on the other hand they can also do the same with us.

Configuring the protocols up front allow us to define things like whether the peer is allowed to open a subscription on some protocol (or whether it has to be initialised by us), as well as things like response size limits.

## Why is the library event based? Wouldn't it be easier to be directly handed back a stream of responses to some subscription, or a response to some request?

Because all of the data that we receive from a peer happens on a single stream, we have two options: (1) handling data as it arrives, regardless of what it is, or (2) ignoring all but the data we're interested in and either buffering or discarding the rest. 

This library opts for (1) in order to avoid needing to buffer a potentially unbounded amount of data on some substreams while the client is polling for data on another. This also keeps the backpressure story simple; awaiting on `.next()` will process new reads and writes, and if the user cannot await on `next()` in a timely fashion then we end up with backpressure going up to the provided read stream.

## How can I interleave commands like requesting data on some protocol with waiting for messages to arrive via `.next()`? `.next()` takes `&mut self` so I cannot do anything while it is waiting for messages.

The trick here is that `.next()` is cancel-safe, allowing the future that it returns to be dropped at any point. This allows it to be used in conjunction with things like `tokio::select!` to interrupt it if, for instance, some new command comes in on another channel, and safely resume it after reacting to said command.

An as example; this sort of thing will work fine:

```rust
let mut i = tokio::time::interval(core::time::Duration::from_millis(100))
loop {
    tokio::select! {
        message = conn.next() => {
            // Handle next message
        },
        interval = i.tick() => {
            // Do something else.
        }
    };
}
```

## How is it that most methods are _not_ async? wouldn't opening subscriptions and sending requests require async?

All reads and writes are handled concurrently inside the async `.next()` method; every other method simply queues up messages to be sent as needed when `.next()` is called again. One reason for this is that it makes it very easy for all reads and writes to happen concurrently, as opposed to the user having to interrupt `.next()` to call some other async function which blocks reading until it has finished writing. Another reason is that it makes it easy to progress multiple `Connection`s concurrently, ie inside a `tokio::select!` or something like a `FuturesUnordered`, or in separate threads.

One thing to be careful of is that there is no limit to how many writes can be queued up by the user. I don't think that this should normally be a big issue since the library is intended to be very read heavy (ie its primary target is to be used in light clients which are mostly consuming data).