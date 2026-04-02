use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use crate::PlatformT;
use crate::utils::async_stream::{self, AsyncStream};
use crate::utils::peer_id::{
    Identity, PeerId,
    verify_ed25519, NoiseHandshakePayload, NoiseHandshakeFromProtobufError
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