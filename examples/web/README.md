# Web Example

This is the browser equivalent of the `basic` example. It connects to a Polkadot bootnode over WebSocket and streams block hashes to the page.

## Prerequisites

Install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/):

```
cargo install wasm-pack
```

## Build

From this directory (`examples/web/`):

```
wasm-pack build --target web
```

This produces a `pkg/` directory containing the compiled WASM and a JS wrapper.

## Run

Serve this directory with any HTTP server. For example:

```
python3 -m http.server
```

Then open http://localhost:8000 in your browser. Block hashes will appear on the page as they arrive. You can also open the browser console to see the same output.

## Notes

- The WebSocket URL defaults to `ws://polkadot-bootnode-0.polkadot.io:30334` (the bootnode's libp2p WS transport port). This works when the page is served over plain HTTP. For HTTPS you would need a `wss://` endpoint.
- The library is `no_std`, so the example provides browser implementations of `AsyncRead`/`AsyncWrite` (over `WebSocket`) and `PlatformT` (using `crypto.getRandomValues` and `setTimeout`).
