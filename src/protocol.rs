use crate::utils::debug_ignore::DebugIgnore;
use crate::utils::opaque_id::OpaqueId;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

/// This is implemented for [`RequestProtocol`] and [`SubscriptionProtocol`], to
/// allow them to be used in [`crate::Configuration::add_protocol`]. It cannot be implemented by
/// others as it references private types.
#[allow(private_interfaces)]
pub trait Protocol {
    /// The unique ID type for this protocol. [`RequestProtocol`]
    /// and [`SubscriptionProtocol`] have different ID types to prevent
    /// their IDs from being used in the wrong contexts.
    type Id: From<OpaqueId>;

    /// Convert our different protocols into a unified type that we can
    /// pass to the configuration.
    fn into_any_protocol(self) -> AnyProtocol;
}

#[derive(Debug, Clone)]
pub enum AnyProtocol {
    Request(RequestProtocol),
    Subscription(SubscriptionProtocol),
}

impl AnyProtocol {
    pub fn as_request(&self) -> Option<&RequestProtocol> {
        match self {
            AnyProtocol::Request(p) => Some(p),
            AnyProtocol::Subscription(_) => None,
        }
    }
    pub fn as_subscription(&self) -> Option<&SubscriptionProtocol> {
        match self {
            AnyProtocol::Request(_) => None,
            AnyProtocol::Subscription(p) => Some(p),
        }
    }
}

/// Define a "request-response" protocol using this. "request-response" protocols
/// entail one side making a single request containing some payload, and the other
/// side returning a single response on the same substream.
#[derive(Debug, Clone)]
pub struct RequestProtocol {
    pub(crate) name: String,
    pub(crate) allow_inbound: bool,
    pub(crate) timeout: Option<Duration>,
    pub(crate) max_response_size_in_bytes: usize,
}

impl RequestProtocol {
    /// Create a new [`RequestProtocol`], providing the
    /// multistream protocol name that it will match on.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            allow_inbound: false,
            timeout: None,
            max_response_size_in_bytes: usize::MAX,
        }
    }

    /// Allow inbound connections? This default to false. Allowing inbound
    /// connections will accept and provide request payloads in our events,
    /// allowing us to respond to them.
    pub fn allow_inbound(mut self, allow: bool) -> Self {
        self.allow_inbound = allow;
        self
    }

    /// Set the maximum size of incoming messages for this protocol, in bytes.
    pub fn with_max_response_size(mut self, max_response_size_in_bytes: usize) -> Self {
        self.max_response_size_in_bytes = max_response_size_in_bytes;
        self
    }

    /// Configure the request timeout. If outgoing requests take more than this
    /// amount of time to receive a response then an error will be returned instead.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// The ID for a single [`RequestProtocol`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestProtocolId(pub(crate) usize);

impl core::fmt::Display for RequestProtocolId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<OpaqueId> for RequestProtocolId {
    fn from(value: OpaqueId) -> Self {
        RequestProtocolId(value.get())
    }
}

#[allow(private_interfaces)]
impl Protocol for RequestProtocol {
    type Id = RequestProtocolId;
    fn into_any_protocol(self) -> AnyProtocol {
        AnyProtocol::Request(self)
    }
}

/// Define a "subscription" protocol using this. Subscription protocols
/// entail one side making a single request containing an initial handshake,
/// and then validating a handshake from the other side, and then receiving
/// a stream of notifications back.
#[derive(Debug, Clone)]
pub struct SubscriptionProtocol {
    pub(crate) name: String,
    pub(crate) allow_inbound: bool,
    pub(crate) max_response_size_in_bytes: usize,
    pub(crate) our_handshake: Vec<u8>,
    pub(crate) validate_their_handshake: DebugIgnore<Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>>,
}

impl SubscriptionProtocol {
    /// Create a new [`SubscriptionProtocol`], providing the
    /// multistream protocol name that it will match on.
    pub fn new<F: 'static + Fn(Vec<u8>) -> bool + Send + Sync>(
        name: impl Into<String>,
        our_handshake: Vec<u8>,
        validate_their_handshake: F,
    ) -> Self {
        let validater: Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync> =
            Arc::new(validate_their_handshake);
        Self {
            name: name.into(),
            allow_inbound: true,
            max_response_size_in_bytes: usize::MAX,
            our_handshake,
            validate_their_handshake: validater.into(),
        }
    }

    /// Allow the remote to open this subscription? If set to false then attempts
    /// by the remote to establish this subscription will fail until we try to
    /// initiate it on our end. Defaults to true (ie allow).
    pub fn allow_inbound(mut self, allow: bool) -> Self {
        self.allow_inbound = allow;
        self
    }

    /// Set the maximum size of incoming messages for this protocol, in bytes.
    pub fn with_max_response_size(mut self, max_response_size_in_bytes: usize) -> Self {
        self.max_response_size_in_bytes = max_response_size_in_bytes;
        self
    }
}

/// The ID for a single [`SubscriptionProtocol`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionProtocolId(pub(crate) usize);

impl core::fmt::Display for SubscriptionProtocolId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<OpaqueId> for SubscriptionProtocolId {
    fn from(value: OpaqueId) -> Self {
        SubscriptionProtocolId(value.get())
    }
}

#[allow(private_interfaces)]
impl Protocol for SubscriptionProtocol {
    type Id = SubscriptionProtocolId;
    fn into_any_protocol(self) -> AnyProtocol {
        AnyProtocol::Subscription(self)
    }
}
