use crate::PlatformT;
use crate::utils::async_stream::{self, AsyncRead, AsyncWrite};
use crate::utils::peer_id::{Identity, PeerId, verify_ed25519};
use crate::utils::protobuf;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::RefCell;
use alloc::rc::Rc;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const STATIC_KEY_DOMAIN: &[u8] = b"noise-libp2p-static-key:";
const MAX_NOISE_MSG: usize = 65535;
const MAX_PLAINTEXT: usize = MAX_NOISE_MSG - 16; // 65519 bytes after AEAD tag

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("error reading from async stream: {0}")]
    AsyncRead(#[from] async_stream::AsyncReadError),
    #[error("error writing to async stream: {0}")]
    AsyncWrite(#[from] async_stream::AsyncWriteError),
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
    InvalidIdentitySignatureFromRemote,
}

/// Perform the Noise XX handshake as the dialer (initiator).
///
/// Returns the encrypted transport stream and the authenticated remote PeerId.
pub async fn handshake_dialer<R: AsyncRead, W: AsyncWrite, P: PlatformT>(
    mut reader: R,
    mut writer: W,
    identity: &Identity,
    expected_peer_id: Option<&PeerId>,
) -> Result<(NoiseReadStream<R>, NoiseWriteStream<W>, PeerId), Error> {
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

    // Pre-allocate the buffer space we'll need. We do this on the heap to reduce
    // the likelihood of stack overflows as they are fairly large.
    let mut buf = Box::new([0u8; MAX_NOISE_MSG * 2]);
    let (buf_a, buf_b) = buf.split_at_mut(MAX_NOISE_MSG);

    let mut frame_sender = FrameSender::new();

    // -- Message 1: -> e (empty payload) ------------------------------------
    {
        let len = noise.write_message(&[], buf_a)?;
        frame_sender.send_frame(&mut writer, &buf_a[..len]).await?;
    }

    // -- Message 2: <- e, ee, s, es (listener identity) ---------------------
    let noise_payload = {
        let len = recv_frame(&mut reader, buf_a).await?;
        let msg = &buf_a[..len];

        let len = noise.read_message(msg, buf_b)?;
        NoiseHandshakePayload::from_protobuf(&buf_b[..len])?
    };

    // Verify the remote peer's identity.
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| Error::RemoveStaticKeyNotAvailable)?;
    let signed_msg: Vec<u8> = [STATIC_KEY_DOMAIN, remote_static].concat();
    if !verify_ed25519(&noise_payload.key, &signed_msg, &noise_payload.signature) {
        return Err(Error::InvalidIdentitySignatureFromRemote);
    }

    let remote_peer_id = PeerId::from_ed25519_public_key(noise_payload.key);
    if let Some(expected) = expected_peer_id
        && &remote_peer_id != expected
    {
        return Err(Error::RemotePeerIdMismatch {
            expected: expected.clone(),
            got: remote_peer_id,
        });
    }

    // -- Message 3: -> s, se (our identity) ---------------------------------
    {
        let signed_msg: Vec<u8> = [STATIC_KEY_DOMAIN, dh_keys.public.as_slice()].concat();
        let len = NoiseHandshakePayload {
            key: identity.public_key_bytes(),
            signature: identity.sign(&signed_msg),
        }
        .to_protobuf(buf_a);
        let msg = &buf_a[..len];

        let len = noise.write_message(msg, buf_b)?;
        frame_sender.send_frame(&mut writer, &buf_b[..len]).await?;
    }

    // Transition to transport mode.
    let transport = Rc::new(RefCell::new(noise.into_transport_mode()?));

    // Create our read/write pair.
    let reader = NoiseReadStream::new(reader, transport.clone());
    let writer = NoiseWriteStream::new(writer, transport);

    Ok((reader, writer, remote_peer_id))
}

// ---------------------------------------------------------------------------
// Encrypted transport stream
// ---------------------------------------------------------------------------

pub struct NoiseReadStream<R> {
    reader: R,
    /// To avoid allocating on the stack too much we do one heap
    /// allocation and use it to buffer bytes where needed.
    intermediate_buf: Box<[u8; MAX_NOISE_MSG * 2]>,
    /// Buffer of decrypted plaintext not yet consumed by the caller.
    read_buf: VecDeque<u8>,
    /// Noise transport state. Shared between reader and writer, so
    /// must be careful not to borrow across await points.
    transport: Rc<RefCell<snow::TransportState>>,
}

impl<R: AsyncRead> NoiseReadStream<R> {
    fn new(reader: R, transport: Rc<RefCell<snow::TransportState>>) -> Self {
        NoiseReadStream {
            reader,
            intermediate_buf: Box::new([0u8; MAX_NOISE_MSG * 2]),
            read_buf: Default::default(),
            transport,
        }
    }
}

impl<R: AsyncRead> AsyncRead for NoiseReadStream<R> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), async_stream::AsyncReadError> {
        let mut buf_pos: usize = 0;
        while buf_pos < buf.len() {
            if !self.read_buf.is_empty() {
                //// Drain bytes from our internal buffer first.

                // How many bytes to read from our buffer?
                let n = usize::min(self.read_buf.len(), buf.len() - buf_pos);

                // Drain these bytes and push to the buffer
                for (i, b) in self.read_buf.drain(..n).enumerate() {
                    buf[buf_pos + i] = b;
                }

                buf_pos += n;
            } else {
                //// If the internal buffer is empty then read another frame on the wire.

                // Fetch a couple of buffers.
                let (encrypted_buf, decrypted_buf) =
                    self.intermediate_buf.split_at_mut(MAX_NOISE_MSG);

                // Read a frame.
                let frame_len = recv_frame(&mut self.reader, encrypted_buf).await?;

                // Decrypt them via snow
                let decrypted_len = self
                    .transport
                    .borrow_mut()
                    .read_message(&encrypted_buf[..frame_len], decrypted_buf)
                    .map_err(async_stream::AsyncReadError::new)?;

                // Push them to our buffer
                self.read_buf
                    .extend(decrypted_buf[..decrypted_len].iter().copied());
            }
        }
        Ok(())
    }
}

pub struct NoiseWriteStream<W> {
    writer: W,
    /// A small helper for sending frames.
    frame_sender: FrameSender,
    /// To avoid allocating on the stack too much we do one heap
    /// allocation and use it to buffer bytes where needed.
    intermediate_buf: Box<[u8; MAX_NOISE_MSG]>,
    /// Noise transport state. Shared between reader and writer, so
    /// must be careful not to borrow across await points.
    transport: Rc<RefCell<snow::TransportState>>,
}

impl<W: AsyncWrite> NoiseWriteStream<W> {
    fn new(writer: W, transport: Rc<RefCell<snow::TransportState>>) -> Self {
        NoiseWriteStream {
            writer,
            frame_sender: FrameSender::new(),
            intermediate_buf: Box::new([0u8; MAX_NOISE_MSG]),
            transport,
        }
    }
}

impl<W: AsyncWrite> AsyncWrite for NoiseWriteStream<W> {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), async_stream::AsyncWriteError> {
        let encrypt_buf = &mut self.intermediate_buf[0..MAX_NOISE_MSG];
        for chunk in data.chunks(MAX_PLAINTEXT) {
            // Encrypt each outgoing message.
            let encrypted_len = self
                .transport
                .borrow_mut()
                .write_message(chunk, &mut encrypt_buf[..])
                .map_err(async_stream::AsyncWriteError::new)?;

            // And then send it.
            self.frame_sender
                .send_frame(&mut self.writer, &encrypt_buf[..encrypted_len])
                .await?;
        }
        Ok(())
    }
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

        Ok(Self { key, signature })
    }

    /// Decode the outermost noise payload message into a protobuf encoded key and a signature.
    fn decode_outer_noise_payload_protobuf(
        data: &[u8],
    ) -> Result<(&[u8], [u8; 64]), NoiseHandshakeFromProtobufError> {
        struct NoiseVisitor<'a> {
            identity_key: Option<&'a [u8]>,
            identity_sig: Option<&'a [u8]>,
        }
        impl<'input> protobuf::Visitor<'input> for NoiseVisitor<'input> {
            fn data(&mut self, field_id: u64, bytes: &'input [u8]) {
                if field_id == 1 {
                    self.identity_key = Some(bytes);
                } else if field_id == 2 {
                    self.identity_sig = Some(bytes)
                }
            }
        }

        let mut visitor = NoiseVisitor {
            identity_key: None,
            identity_sig: None,
        };
        protobuf::decode(&mut &*data, &mut visitor)?;

        let signature: [u8; 64] = if let Some(sig_bytes) = visitor.identity_sig {
            sig_bytes.try_into().map_err(|_| {
                NoiseHandshakeFromProtobufError::InvalidSignatureLength(sig_bytes.len())
            })?
        } else {
            return Err(NoiseHandshakeFromProtobufError::InvalidNoisePayload(
                data.to_vec(),
            ));
        };

        let key: &[u8] = if let Some(key_bytes) = visitor.identity_key {
            key_bytes
        } else {
            return Err(NoiseHandshakeFromProtobufError::InvalidNoisePayload(
                data.to_vec(),
            ));
        };

        Ok((key, signature))
    }

    /// Decode a protobuf encoded `PublicKey`, returning the raw 32-byte Ed25519 key.
    fn decode_ed25519_public_key_protobuf(
        data: &[u8],
    ) -> Result<[u8; 32], NoiseHandshakeFromProtobufError> {
        struct KeyVisitor<'a> {
            ty: Option<u64>,
            value: Option<&'a [u8]>,
        }
        impl<'input> protobuf::Visitor<'input> for KeyVisitor<'input> {
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

        let mut visitor = KeyVisitor {
            ty: None,
            value: None,
        };
        protobuf::decode(&mut &*data, &mut visitor)?;

        let (Some(1), Some(key_data)) = (visitor.ty, visitor.value) else {
            return Err(NoiseHandshakeFromProtobufError::InvalidKey(data.to_vec()));
        };
        if key_data.len() != 32 {
            return Err(NoiseHandshakeFromProtobufError::InvalidKeyLength(
                key_data.len(),
            ));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(key_data);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Noise frame helpers (u16-BE length prefix)
// ---------------------------------------------------------------------------

/// Send frames. Can re-use this to reuse an internal buffer.
struct FrameSender {
    buf: Box<[u8; MAX_NOISE_MSG + 2]>,
}

impl FrameSender {
    fn new() -> Self {
        Self {
            buf: Box::new([0u8; MAX_NOISE_MSG + 2]),
        }
    }
    async fn send_frame(
        &mut self,
        stream: &mut impl AsyncWrite,
        data: &[u8],
    ) -> Result<(), async_stream::AsyncWriteError> {
        let buf = &mut self.buf[..];
        buf[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        buf[2..data.len() + 2].copy_from_slice(data);
        stream.write_all(&buf[..data.len() + 2]).await?;
        Ok(())
    }
}

async fn recv_frame(
    stream: &mut impl AsyncRead,
    out: &mut [u8],
) -> Result<usize, async_stream::AsyncReadError> {
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
    fn resolve_hash(
        &self,
        choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        snow::resolvers::DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(
        &self,
        choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        snow::resolvers::DefaultResolver.resolve_cipher(choice)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::testing::{MockStream, block_on as block_on_inner};
    use alloc::vec;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        block_on_inner(f).expect("future returned Pending in mock-I/O test")
    }

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
    fn make_transport_pair() -> (Rc<RefCell<snow::TransportState>>, Rc<RefCell<snow::TransportState>>) {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();

        let builder_i = snow::Builder::with_resolver(params.clone(), Box::new(test_resolver()));
        let kp_i = builder_i.generate_keypair().unwrap();
        let mut initiator = snow::Builder::with_resolver(params.clone(), Box::new(test_resolver()))
            .local_private_key(&kp_i.private)
            .unwrap()
            .build_initiator()
            .unwrap();

        let builder_r = snow::Builder::with_resolver(params.clone(), Box::new(test_resolver()));
        let kp_r = builder_r.generate_keypair().unwrap();
        let mut responder = snow::Builder::with_resolver(params, Box::new(test_resolver()))
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
            Rc::new(RefCell::new(initiator.into_transport_mode().unwrap())),
            Rc::new(RefCell::new(responder.into_transport_mode().unwrap())),
        )
    }

    #[test]
    fn round_trip_small_message() {
        let (ti, tr) = make_transport_pair();

        let plaintext = b"hello, noise!";
        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(plaintext)).unwrap();

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, plaintext);
    }

    #[test]
    fn round_trip_exact_max_plaintext() {
        let (ti, tr) = make_transport_pair();

        let plaintext: Vec<u8> = (0..MAX_PLAINTEXT).map(|i| (i % 256) as u8).collect();
        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(&plaintext)).unwrap();

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_spans_multiple_frames() {
        let (ti, tr) = make_transport_pair();

        // Exceeds MAX_PLAINTEXT, so writer must produce 2 Noise frames.
        let plaintext: Vec<u8> = (0..(MAX_PLAINTEXT + 100))
            .map(|i| (i % 256) as u8)
            .collect();
        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(&plaintext)).unwrap();

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

        let mut out = vec![0u8; plaintext.len()];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn partial_reads_drain_buffer_correctly() {
        let (ti, tr) = make_transport_pair();

        let plaintext = b"abcdefghij"; // 10 bytes in one frame
        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(plaintext)).unwrap();

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

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

        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(b"first")).unwrap();
        block_on(writer.write_all(b"second")).unwrap();
        block_on(writer.write_all(b"third")).unwrap();

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

        // 5 + 6 + 5 = 16 bytes total across three frames, read all at once
        let mut out = vec![0u8; 16];
        block_on(reader.read_exact(&mut out)).unwrap();
        assert_eq!(&out, b"firstsecondthird");
    }

    #[test]
    fn read_spanning_frame_boundary() {
        let (ti, tr) = make_transport_pair();

        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(b"AAA")).unwrap(); // frame 1: 3 bytes
        block_on(writer.write_all(b"BBBBB")).unwrap(); // frame 2: 5 bytes

        let wire = writer_handle.drain_all();
        let reader_mock = MockStream::new();
        let mut reader_handle = reader_mock.handle();
        reader_handle.extend(wire);
        let mut reader = NoiseReadStream::new(reader_mock, tr);

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
        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(plaintext)).unwrap();

        // Skip the 2-byte length prefix; the encrypted payload must not contain
        // the plaintext substring.
        let wire = writer_handle.drain_all();
        let payload = &wire[2..];
        assert!(!payload.windows(plaintext.len()).any(|w| w == plaintext));
    }

    #[test]
    fn empty_write_produces_no_output() {
        let (ti, _tr) = make_transport_pair();

        let writer_mock = MockStream::new();
        let writer_handle = writer_mock.handle();
        let mut writer = NoiseWriteStream::new(writer_mock, ti);
        block_on(writer.write_all(b"")).unwrap();

        // chunks(MAX_PLAINTEXT) on an empty slice yields no chunks,
        // so nothing should be written to the inner stream.
        assert!(writer_handle.drain_all().is_empty());
    }
}
