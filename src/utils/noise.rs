use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use crate::PlatformT;
use crate::utils::async_stream::{self, AsyncStream};
use crate::utils::protobuf;
use crate::utils::peer_id::{
    Identity, PeerId,
    verify_ed25519,
};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const STATIC_KEY_DOMAIN: &[u8] = b"noise-libp2p-static-key:";
const MAX_NOISE_MSG: usize = 65535;
const MAX_PLAINTEXT: usize = MAX_NOISE_MSG - 16; // 65519 bytes after AEAD tag

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("error reading or writing to async stream: {0}")]
    AsyncStream(#[from] async_stream::Error),
    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),
    #[error("error decoding noise handshake from protobuf: {0}")]
    NoiseHandshakeFromProtobufError(#[from] NoiseHandshakeFromProtobufError),
    #[error("noise remote static key expected but unavailable")]
    RemoveStaticKeyNotAvailable,
    #[error("remote peer ID {got} is not the expected peer ID of {expected}")]
    RemotePeerIdMismatch {
        /// The Peer ID that we expected.
        expected: PeerId,
        /// The Peer ID that we were given.
        got: PeerId,
    },
    #[error("invalid identity signature from remote")]
    InvalidIdentitySignatureFromRemote
}

/// Perform the Noise XX handshake as the dialer (initiator).
///
/// Returns the encrypted transport stream and the authenticated remote PeerId.
pub async fn handshake_dialer<S: AsyncStream, P: PlatformT>(
    mut stream: S,
    identity: &Identity,
    expected_peer_id: Option<&PeerId>,
) -> Result<(NoiseStream<S>, PeerId), Error> {
    // Build a snow initiator using our Platform RNG so this works in no_std.
    let builder = snow::Builder::with_resolver(
        NOISE_PARAMS.parse()?,
        Box::new(CryptoResolver::from_platform::<P>()),
    );
    let dh_keys = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&dh_keys.private)
        .expect("has not been called previously")
        .build_initiator()?;

    
    // -- Message 1: -> e (empty payload) ------------------------------------
    {
        let mut buf = [0u8; MAX_NOISE_MSG];
        let len = noise.write_message(&[], &mut buf)?;
        send_frame(&mut stream, &buf[..len]).await?;
    }
    
    // -- Message 2: <- e, ee, s, es (listener identity) ---------------------
    let noise_payload = {
        let mut buf = [0u8; MAX_NOISE_MSG];
        let len = recv_frame(&mut stream, &mut buf).await?;
        let msg = &buf[..len];

        let mut buf = [0u8; MAX_NOISE_MSG];
        let len = noise.read_message(msg, &mut buf)?;
        NoiseHandshakePayload::from_protobuf(&buf[..len])?
    };

    // Verify the remote peer's identity.
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| Error::RemoveStaticKeyNotAvailable)?;
    let signed_msg: Vec<u8> = [STATIC_KEY_DOMAIN, remote_static].concat();
    if !verify_ed25519(&noise_payload.key, &signed_msg, &noise_payload.signature) {
        return Err(Error::InvalidIdentitySignatureFromRemote)
    }

    let remote_peer_id = PeerId::from_ed25519_public_key(noise_payload.key);
    if let Some(expected) = expected_peer_id && &remote_peer_id != expected {
        return Err(Error::RemotePeerIdMismatch { 
            expected: expected.clone(), 
            got: remote_peer_id
        });
    }

    // -- Message 3: -> s, se (our identity) ---------------------------------
    {
        let mut buf = [0u8; MAX_NOISE_MSG];
        let signed_msg: Vec<u8> = [STATIC_KEY_DOMAIN, dh_keys.public.as_slice()].concat();
        let len = NoiseHandshakePayload {
            key: identity.public_key_bytes(),
            signature: identity.sign(&signed_msg)
        }.to_protobuf(&mut buf);
        let msg = &buf[..len];

        let mut buf = [0u8; MAX_NOISE_MSG];
        let len = noise.write_message(msg, &mut buf)?;
        send_frame(&mut stream, &buf[..len]).await?;
    }


    // Transition to transport mode.
    let transport = noise.into_transport_mode()?;
    Ok((NoiseStream::new(stream, transport), remote_peer_id))
}

// ---------------------------------------------------------------------------
// Noise handshake
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
// Noise frame helpers (u16-BE length prefix)
// ---------------------------------------------------------------------------

async fn send_frame(stream: &mut impl AsyncStream, data: &[u8]) -> Result<(), async_stream::Error> {
    stream.write_all(&(data.len() as u16).to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

async fn recv_frame(stream: &mut impl AsyncStream, out: &mut [u8]) -> Result<usize, async_stream::Error> {
    // How many bytes will we read
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    // Read exactly that number of bytes to our buffer and return the length
    let bounded_out = &mut out[..len];
    stream.read_exact(bounded_out).await?;
    Ok(len)
}

// ---------------------------------------------------------------------------
// Encrypted transport stream
// ---------------------------------------------------------------------------

/// A Noise-encrypted byte stream wrapping an inner transport.
pub struct NoiseStream<S> {
    inner: S,
    transport: snow::TransportState,
    /// Buffer of decrypted plaintext not yet consumed by the caller.
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> NoiseStream<S> {
    fn new(inner: S, transport: snow::TransportState) -> Self {
        Self {
            inner,
            transport,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncStream> AsyncStream for NoiseStream<S> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), async_stream::Error> {
        let mut filled = 0;
        while filled < buf.len() {
            // Drain buffered plaintext first.
            if self.read_pos < self.read_buf.len() {
                let avail = self.read_buf.len() - self.read_pos;
                let n = avail.min(buf.len() - filled);
                buf[filled..filled + n]
                    .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                filled += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                continue;
            }

            // Read the next Noise frame from the wire.
            let mut len_buf = [0u8; 2];
            self.inner.read_exact(&mut len_buf).await?;
            let frame_len = u16::from_be_bytes(len_buf) as usize;

            let mut encrypted = vec![0u8; frame_len];
            self.inner.read_exact(&mut encrypted).await?;

            let mut decrypt_buf = vec![0u8; frame_len];
            let decrypted_len = self.transport.read_message(&encrypted, &mut decrypt_buf)
                .map_err(async_stream::Error::read_exact)?;
            self.read_buf = decrypt_buf[..decrypted_len].to_vec();
            self.read_pos = 0;
        }
        Ok(())
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), async_stream::Error> {
        let mut encrypt_buf = [0u8; MAX_NOISE_MSG];
        for chunk in data.chunks(MAX_PLAINTEXT) {
            let encrypted_len = self.transport.write_message(chunk, &mut encrypt_buf[..])
                .map_err(async_stream::Error::write_all)?;
            let mut frame = Vec::with_capacity(2 + encrypted_len);
            frame.extend_from_slice(&(encrypted_len as u16).to_be_bytes());
            frame.extend_from_slice(&encrypt_buf[..encrypted_len]);
            self.inner.write_all(&frame).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Use our RNG from PlatformT with snow for any noise bits
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct CryptoResolver(fn(&mut [u8]));

impl CryptoResolver {
    /// Bridge PlatformT's RNG into snow's [`snow::resolvers::CryptoResolver`] so that snow 
    /// can generate ephemeral keys even in a no_std environment without getrandom.
    fn from_platform<P: PlatformT>() -> Self {
        CryptoResolver(P::fill_with_random_bytes)
    }
}

impl snow::types::Random for CryptoResolver {
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), snow::Error> {
        (self.0)(out);
        Ok(())
    }
}

impl snow::resolvers::CryptoResolver for CryptoResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        Some(Box::new(*self))
    }
    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        snow::resolvers::DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        snow::resolvers::DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn snow::types::Cipher>> {
        snow::resolvers::DefaultResolver.resolve_cipher(choice)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Minimal single-threaded executor for tests.
    /// All our mock I/O completes immediately, so Pending is never expected.
    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        use alloc::task::Wake;
        use alloc::sync::Arc;
        use core::pin::pin;

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut f = pin!(f);
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future returned Pending in mock-I/O test"),
        }
    }

    /// In-memory byte buffer implementing AsyncStream.
    /// Writes append; reads consume from the front.
    struct MockStream {
        buf: Vec<u8>,
        read_pos: usize,
    }

    impl MockStream {
        fn new() -> Self {
            Self { buf: Vec::new(), read_pos: 0 }
        }
        fn from_bytes(bytes: Vec<u8>) -> Self {
            Self { buf: bytes, read_pos: 0 }
        }
    }

    impl AsyncStream for MockStream {
        async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), async_stream::Error> {
            let available = self.buf.len() - self.read_pos;
            if available < buf.len() {
                return Err(async_stream::Error::read_exact(MockStreamError));
            }
            buf.copy_from_slice(&self.buf[self.read_pos..self.read_pos + buf.len()]);
            self.read_pos += buf.len();
            Ok(())
        }
        async fn write_all(&mut self, data: &[u8]) -> Result<(), async_stream::Error> {
            self.buf.extend_from_slice(data);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MockStreamError;
    impl core::fmt::Display for MockStreamError {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            f.write_str("mock stream: not enough data")
        }
    }
    impl core::error::Error for MockStreamError {}

    /// Simple test RNG: fills bytes from an atomic counter.
    /// Not cryptographically secure, but sufficient for Noise handshake tests.
    fn test_fill_random(bytes: &mut [u8]) {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(1);
        for b in bytes.iter_mut() {
            *b = CTR.fetch_add(7, Ordering::Relaxed) as u8;
        }
    }

    fn test_resolver() -> CryptoResolver {
        CryptoResolver(test_fill_random)
    }

    /// Perform a Noise XX handshake entirely in memory and return a
    /// (initiator, responder) pair of `TransportState`s ready for data.
    fn make_transport_pair() -> (snow::TransportState, snow::TransportState) {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();

        let builder_i = snow::Builder::with_resolver(
            params.clone(), Box::new(test_resolver()),
        );
        let kp_i = builder_i.generate_keypair().unwrap();
        let mut initiator = snow::Builder::with_resolver(
            params.clone(), Box::new(test_resolver()),
        )
            .local_private_key(&kp_i.private)
            .unwrap()
            .build_initiator()
            .unwrap();

        let builder_r = snow::Builder::with_resolver(
            params.clone(), Box::new(test_resolver()),
        );
        let kp_r = builder_r.generate_keypair().unwrap();
        let mut responder = snow::Builder::with_resolver(
            params, Box::new(test_resolver()),
        )
            .local_private_key(&kp_r.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut buf = [0u8; MAX_NOISE_MSG];

        // -> e
        let len = initiator.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..len].to_vec();
        let mut tmp = [0u8; MAX_NOISE_MSG];
        responder.read_message(&msg1, &mut tmp).unwrap();

        // <- e, ee, s, es
        let len = responder.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..len].to_vec();
        let mut tmp = [0u8; MAX_NOISE_MSG];
        initiator.read_message(&msg2, &mut tmp).unwrap();

        // -> s, se
        let len = initiator.write_message(&[], &mut buf).unwrap();
        let msg3 = buf[..len].to_vec();
        let mut tmp = [0u8; MAX_NOISE_MSG];
        responder.read_message(&msg3, &mut tmp).unwrap();

        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    #[test]
    fn round_trip_small_message() {
        let (ti, tr) = make_transport_pair();

        let plaintext = b"hello, noise!";
        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(plaintext)).unwrap();

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, plaintext);
    }

    #[test]
    fn round_trip_exact_max_plaintext() {
        let (ti, tr) = make_transport_pair();

        let plaintext: Vec<u8> = (0..MAX_PLAINTEXT).map(|i| (i % 256) as u8).collect();
        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(&plaintext)).unwrap();

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_spans_multiple_frames() {
        let (ti, tr) = make_transport_pair();

        // Exceeds MAX_PLAINTEXT, so writer must produce 2 Noise frames.
        let plaintext: Vec<u8> = (0..(MAX_PLAINTEXT + 100)).map(|i| (i % 256) as u8).collect();
        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(&plaintext)).unwrap();

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn partial_reads_drain_buffer_correctly() {
        let (ti, tr) = make_transport_pair();

        let plaintext = b"abcdefghij"; // 10 bytes in one frame
        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(plaintext)).unwrap();

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        // Read 4 bytes (leaves 6 buffered)
        let mut first = [0u8; 4];
        block_on(reader.read_exact(&mut first)).unwrap();
        assert_eq!(&first, b"abcd");

        // Read remaining 6 bytes from the internal buffer (no new frame read)
        let mut second = [0u8; 6];
        block_on(reader.read_exact(&mut second)).unwrap();
        assert_eq!(&second, b"efghij");
    }

    #[test]
    fn multiple_writes_then_single_read() {
        let (ti, tr) = make_transport_pair();

        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(b"first")).unwrap();
        block_on(writer.write_all(b"second")).unwrap();
        block_on(writer.write_all(b"third")).unwrap();

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        // 5 + 6 + 5 = 16 bytes total across three frames, read all at once
        let mut out = vec![0u8; 16];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, b"firstsecondthird");
    }

    #[test]
    fn read_spanning_frame_boundary() {
        let (ti, tr) = make_transport_pair();

        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(b"AAA")).unwrap(); // frame 1: 3 bytes
        block_on(writer.write_all(b"BBBBB")).unwrap(); // frame 2: 5 bytes

        let wire = writer.inner.buf.clone();
        let mut reader = NoiseStream::new(MockStream::from_bytes(wire), tr);

        // Read 5 bytes: spans frame 1 (3 bytes) then starts frame 2 (2 bytes)
        let mut out = [0u8; 5];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, b"AAABB");

        // Read remaining 3 bytes from frame 2's buffer
        let mut out = [0u8; 3];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, b"BBB");
    }

    #[test]
    fn encrypted_bytes_differ_from_plaintext() {
        let (ti, _tr) = make_transport_pair();

        let plaintext = b"this should be encrypted on the wire";
        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(plaintext)).unwrap();

        // Skip the 2-byte length prefix; the encrypted payload must not contain
        // the plaintext substring.
        let payload = &writer.inner.buf[2..];
        assert!(!payload.windows(plaintext.len()).any(|w| w == plaintext));
    }

    #[test]
    fn empty_write_produces_no_output() {
        let (ti, _tr) = make_transport_pair();

        let mut writer = NoiseStream::new(MockStream::new(), ti);
        block_on(writer.write_all(b"")).unwrap();

        // chunks(MAX_PLAINTEXT) on an empty slice yields no chunks,
        // so nothing should be written to the inner stream.
        assert!(writer.inner.buf.is_empty());
    }
}