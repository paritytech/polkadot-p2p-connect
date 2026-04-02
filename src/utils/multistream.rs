use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crate::utils::async_stream::{self, AsyncStream};
use crate::utils::varint;

const MULTISTREAM_HEADER: &[u8] = b"/multistream/1.0.0";
const MULTISTREAM_MAX_MSG_BYTES: u64 = 16384;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stream error: {0}")]
    Stream(#[from] async_stream::Error),
    #[error("varint error: {0}")]
    Varint(#[from] varint::Error),
    #[error("message too large; size is {0} bytes")]
    MessageTooLarge(u64),
    #[error("message does not end in a newline but it should: {0}")]
    MessageMustEndInNewline(String),
    #[error("bad multistream header from remote: {0}")]
    BadMultiStreamHeader(String),
    #[error("remote does not support /multistream/1.0.0")]
    MultistreamNotSupported,
    #[error("unexpected response negotiating protocol, got: {0}")]
    UnexpectedResponse(String),
    #[error("the proposed protocol is not valid utf8: {0:?}")]
    ProposedProtocolIsNotUtf8(Vec<u8>),
    #[error("the remote suggested protocol {0} but we do not support it")]
    ProtocolNotSupported(String)
}

/// Dialer-side multistream-select: propose a single protocol.
pub async fn negotiate_dialer(
    stream: &mut impl AsyncStream,
    protocol: &str,
) -> Result<(), Error> {
    // Send header + proposal in one write (common optimisation)
    let mut msgs = Vec::new();
    encode_msg(MULTISTREAM_HEADER, &mut msgs);
    encode_msg(protocol.as_bytes(), &mut msgs);
    stream.write_all(&msgs).await?;

    // Read header echo
    let resp = read_msg(stream).await?;
    if resp != MULTISTREAM_HEADER {
        return Err(Error::BadMultiStreamHeader(to_string(&resp)))
    }

    // Read protocol echo (accepted) or "na\n" (rejected)
    let resp = read_msg(stream).await?;
    if resp == b"na" {
        return Err(Error::MultistreamNotSupported)
    }
    if resp != protocol.as_bytes() {
        return Err(Error::UnexpectedResponse(to_string(&resp)))
    }

    Ok(())
}

// -- helpers ----------------------------------------------------------------

fn encode_msg(payload: &[u8], out: &mut Vec<u8>) {
    varint::encode(payload.len() as u64, out);
    out.extend_from_slice(payload);
    out.push(b'\n');
}

async fn read_msg(stream: &mut impl AsyncStream) -> Result<Vec<u8>, Error> {
    let length = varint::decode_from_stream(stream).await?;
    if length > MULTISTREAM_MAX_MSG_BYTES {
        return Err(Error::MessageTooLarge(length))
    }
    let mut buf = vec![0u8; length as usize];
    stream.read_exact(&mut buf).await?;

    // Expect and remove a newline at the end.
    let last_byte = buf.pop();
    if last_byte.is_none() || matches!(last_byte, Some(n) if n != b'\n') {
        return Err(Error::MessageMustEndInNewline(to_string(&buf)))
    }

    Ok(buf)
}

fn to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}
