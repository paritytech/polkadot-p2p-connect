//! This crate is used to establish a peer-to-peer connection with a node on the Polkadot network.
//!
//! For an easy start, look at the examples in the repository `/examples` folder.
//!
//! Essentially, the steps are:
//!
//! 1. Implement [`PlatformT`] for your platform of choice (be it web, native or other).
//! 2. Implement [`AsyncRead`] and [`AsyncWrite`] for some binary stream that you wish to use to communicate with a peer.
//!    This can be obtained through establishing either a WebSocket or plain TCP connection to some peer. See the examples.
//! 3. Configure the protocols that you wish to support (for Polkadot, the block announces protocol is the minimum that you
//!    must support in order to maintain a connection to a peer).
//!    - See [`RequestProtocol`] to configure a simple request-response protocol.
//!    - See [`SubscriptionProtocol`] to configure a subscription based protocol (like block announces).
//!    - See [`Configuration`] for global connection configuration and adding the above protocols once defined.
//! 4. Connect to the peer via [`Configuration::connect`] or [`Configuration::connect_to_peer`], both of which hand back a
//!    [`Connection`] type that you can then use to request/subscribe and so on.
//! 5. Drive the connection with [`Connection::next()`], which concurrently processes reads and writes, and hands back
//!    messages as they become available.
//!
//! # Example
//!
//! ```rust,ignore
#![doc = include_str!("../examples/basic.rs")]
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

mod configuration;
mod connection;
mod error;
mod layers;
mod platform;
mod protocol;
mod utils;

pub use crate::error::{ConnectionError, ProtocolError, StreamError};
pub use crate::utils::async_stream::{AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError};
pub use crate::utils::peer_id::PeerId;

pub use configuration::Configuration;
pub use connection::{
    Connection, Message, Request, RequestId, RequestResponse, RequestResponseError, ResponseId,
    SubscriptionResponse, SubscriptionResponseError,
};
pub use platform::PlatformT;
pub use protocol::{
    Protocol, RequestProtocol, RequestProtocolId, SubscriptionProtocol, SubscriptionProtocolId,
};
