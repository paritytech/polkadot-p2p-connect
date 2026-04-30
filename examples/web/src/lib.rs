// Build:  wasm-pack build --target web   (run from examples/web/)
// Serve:  python3 -m http.server          (run from examples/web/)
// Open:   http://localhost:8000

use core::cell::{Cell, RefCell};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::VecDeque;
use std::rc::Rc;

use parity_scale_codec::Encode;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, MessageEvent, WebSocket};

use polkadot_p2p_connector::{
    AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError, Configuration, Message, PlatformT,
    SubscriptionProtocol, SubscriptionResponse,
};

// ---------------------------------------------------------------------------
// Error helper (must be Send + Sync for AsyncReadError / AsyncWriteError)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Oops(String);

impl core::fmt::Display for Oops {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Oops {}

// ---------------------------------------------------------------------------
// WebSocket → AsyncRead / AsyncWrite bridge
// ---------------------------------------------------------------------------

struct WsState {
    buffer: VecDeque<u8>,
    waker: Option<Waker>,
    opened: bool,
    closed: bool,
    error: Option<String>,
}

struct WsReader(Rc<RefCell<WsState>>);

impl AsyncRead for WsReader {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), AsyncReadError> {
        core::future::poll_fn(|cx| {
            let mut st = self.0.borrow_mut();
            if let Some(err) = st.error.take() {
                return Poll::Ready(Err(AsyncReadError::new(Oops(err))));
            }
            if st.buffer.len() >= buf.len() {
                for b in buf.iter_mut() {
                    *b = st.buffer.pop_front().unwrap();
                }
                Poll::Ready(Ok(()))
            } else if st.closed {
                Poll::Ready(Err(AsyncReadError::new(Oops("connection closed".into()))))
            } else {
                st.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

struct WsWriter(WebSocket);

impl AsyncWrite for WsWriter {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), AsyncWriteError> {
        self.0
            .send_with_u8_array(data)
            .map_err(|e| AsyncWriteError::new(Oops(format!("{e:?}"))))
    }
}

// ---------------------------------------------------------------------------
// Browser PlatformT
// ---------------------------------------------------------------------------

struct WasmSleep {
    done: Rc<Cell<bool>>,
    waker: Rc<Cell<Option<Waker>>>,
}

// SAFETY: WASM is single-threaded; these are trivially safe.
unsafe impl Send for WasmSleep {}
impl Unpin for WasmSleep {}

impl core::future::Future for WasmSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        if self.done.get() {
            Poll::Ready(())
        } else {
            self.waker.set(Some(cx.waker().clone()));
            Poll::Pending
        }
    }
}

struct BrowserPlatform;

impl PlatformT for BrowserPlatform {
    type Sleep = WasmSleep;

    fn fill_with_random_bytes(bytes: &mut [u8]) {
        let array = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
        web_sys::window()
            .unwrap()
            .crypto()
            .unwrap()
            .get_random_values_with_array_buffer_view(&array)
            .unwrap();
        array.copy_to(bytes);
    }

    fn sleep(duration: Duration) -> WasmSleep {
        let done = Rc::new(Cell::new(false));
        let waker: Rc<Cell<Option<Waker>>> = Rc::new(Cell::new(None));
        let (d, w) = (done.clone(), waker.clone());
        let cb = Closure::once(move || {
            d.set(true);
            if let Some(wk) = w.take() {
                wk.wake();
            }
        });
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                duration.as_millis() as i32,
            )
            .unwrap();
        cb.forget();
        WasmSleep { done, waker }
    }
}

// ---------------------------------------------------------------------------
// Logging (console + DOM)
// ---------------------------------------------------------------------------

fn log(msg: &str) {
    web_sys::console::log_1(&msg.into());
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("log"))
    {
        let prev = el.text_content().unwrap_or_default();
        el.set_text_content(Some(&format!("{prev}{msg}\n")));
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[wasm_bindgen(start)]
pub fn start() {
    wasm_bindgen_futures::spawn_local(async {
        if let Err(e) = run().await {
            log(&format!("Error: {e}"));
        }
    });
}

async fn run() -> Result<(), String> {
    log("Connecting to Polkadot bootnode...");

    // 1. Open a WebSocket to the node's libp2p WS transport.
    //    Use ws://…:30334 when serving over plain HTTP,
    //    or wss://…:443 if the bootnode exposes a TLS endpoint.
    let ws = WebSocket::new("ws://polkadot-bootnode-0.polkadot.io:30334")
        .map_err(|e| format!("{e:?}"))?;
    ws.set_binary_type(BinaryType::Arraybuffer);

    let state = Rc::new(RefCell::new(WsState {
        buffer: VecDeque::new(),
        waker: None,
        opened: false,
        closed: false,
        error: None,
    }));

    // Wire up WebSocket events → shared state.
    {
        let s = state.clone();
        let cb = Closure::once(move || {
            let mut st = s.borrow_mut();
            st.opened = true;
            if let Some(w) = st.waker.take() { w.wake(); }
        });
        ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
    {
        let s = state.clone();
        let cb = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(buf) = e.data().dyn_into::<js_sys::ArrayBuffer>() {
                let arr = js_sys::Uint8Array::new(&buf);
                let mut st = s.borrow_mut();
                st.buffer.extend(arr.to_vec());
                if let Some(w) = st.waker.take() { w.wake(); }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
    {
        let s = state.clone();
        let cb = Closure::wrap(Box::new(move |_: JsValue| {
            let mut st = s.borrow_mut();
            st.closed = true;
            if let Some(w) = st.waker.take() { w.wake(); }
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onclose(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
    {
        let s = state.clone();
        let cb = Closure::wrap(Box::new(move |_: JsValue| {
            let mut st = s.borrow_mut();
            st.error = Some("WebSocket error".into());
            if let Some(w) = st.waker.take() { w.wake(); }
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // Wait for the WebSocket to open (or fail).
    core::future::poll_fn(|cx| {
        let mut st = state.borrow_mut();
        if st.opened {
            Poll::Ready(Ok(()))
        } else if st.error.is_some() || st.closed {
            Poll::Ready(Err(st.error.take().unwrap_or("failed to connect".into())))
        } else {
            st.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    })
    .await?;

    log("WebSocket open. Starting handshake...");

    // 2. Configure protocols (same as the basic example).
    let genesis_hex = "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3";
    let genesis: [u8; 32] = hex::decode(genesis_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "bad genesis hex".to_string())?;

    let mut config: Configuration<BrowserPlatform> = Configuration::new();
    let block_announce_id = config.add_protocol(SubscriptionProtocol::new(
        format!("/{genesis_hex}/block-announces/1"),
        (2u8, 0, genesis, genesis).encode(),
        move |remote_hs| remote_hs.len() >= 69 && remote_hs[37..69] == genesis,
    ));

    // 3. Connect.
    let mut conn = config
        .connect(WsReader(state), WsWriter(ws))
        .await
        .map_err(|e| e.to_string())?;

    log(&format!("Connected! Us: {}, Them: {}", conn.our_id(), conn.their_id()));

    // 4. Subscribe to block announcements.
    conn.subscribe(block_announce_id).map_err(|e| e.to_string())?;

    // 5. Stream blocks.
    while let Some(result) = conn.next().await {
        match result.map_err(|e| e.to_string())? {
            Message::Notification { protocol_id, res } if protocol_id == block_announce_id => {
                match res {
                    SubscriptionResponse::Opened => {
                        log("Block announce subscription opened.");
                    }
                    SubscriptionResponse::Value(mut data) => {
                        data.pop(); // chain-specific data
                        let block_type = match data.pop() {
                            Some(0) => "normal",
                            Some(1) => "best",
                            _ => "unknown",
                        };
                        let hash = hex::encode(block_hash(&data));
                        log(&format!("hash={hash} type={block_type}"));
                    }
                    SubscriptionResponse::Closed => {
                        log("Subscription closed.");
                        break;
                    }
                    SubscriptionResponse::Error(e) => {
                        log(&format!("Subscription error: {e}"));
                        break;
                    }
                }
            }
            o => log(&format!("Unexpected: {o:?}")),
        }
    }

    Ok(())
}

fn block_hash(header: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};
    Blake2b::<U32>::digest(header).into()
}
