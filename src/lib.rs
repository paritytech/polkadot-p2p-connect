//! This crate is used to establish a peer-to-peer connection with a node on the Polkadot network.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

mod error;
mod layers;
mod utils;
mod platform;
mod protocol;
mod configuration;
mod connection;

pub use crate::error::{ConnectionError, ProtocolError, StreamError};
pub use crate::utils::async_stream::{AsyncStream, Error as AsyncStreamError};
pub use crate::utils::peer_id::PeerId;

pub use platform::PlatformT;
pub use protocol::{Protocol, RequestProtocol, RequestProtocolId, SubscriptionProtocol, SubscriptionProtocolId};
pub use configuration::Configuration;
pub use connection::{ Connection, Message, Request, RequestId, RequestResponse, RequestResponseError, ResponseId, SubscriptionResponse, SubscriptionResponseError };
