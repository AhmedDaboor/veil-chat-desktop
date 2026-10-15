# Historical Veil Chat worker IPC contract, version 1

This document describes the superseded initial prototype only. The current
worker protocol is version 2; see [worker-ipc-v2.md](worker-ipc-v2.md).

Status: offline process-supervision prototype. The desktop Core service uses this
contract to launch and query the Rust worker. The worker implements only hello
and an explicitly unimplemented privacy status; neither component performs
networking.

## Framing and limits

- Transport is UTF-8 JSON Lines over the worker's private stdin/stdout pipes.
- One JSON object per line; LF ends a frame. CRLF is accepted. The 65,536-byte
  frame limit applies before LF and includes a possible CR. Output includes LF.
- JSON nesting depth is limited to 8. Duplicate or unknown envelope properties,
  missing required properties, extra payload fields, and empty request UUIDs are
  rejected. Request IDs use canonical UUID text and are correlation IDs, not
  authentication credentials.
- The C# reader buffers in fixed 4 KiB chunks and stores no more than one frame.
  An oversized or truncated frame is a protocol error; the worker emits a fixed
  safe error when framing still permits it, then terminates the pipe.
- Responses have fixed typed result variants and a 65,536-byte serialized-body
  ceiling. If serialization ever exceeds the limit, the encoder returns a small
  `OUTPUT_TOO_LARGE` response. No raw exception text or request content is echoed.

## Request schema

~~~json
{"v":1,"kind":"request","id":"d41c435b-24c8-458a-b873-3ca1d77c2c34","method":"worker.hello","payload":{}}
~~~

Supported methods are `worker.hello` and `privacy.status`; both require an empty
object payload. `worker.hello` returns the supported protocol version.
`privacy.status` returns `state: not_implemented` and `networkAccess: none`; it
does not inspect a proxy or claim Tor protection. Unknown methods fail closed.

## Response and errors

Every response carries protocol version 1, `kind: response`, the request UUID
(or null when it cannot be parsed), and an `ok` boolean. Successful responses
contain one of the fixed result variants. Errors contain only one of these codes:

- `INVALID_REQUEST`
- `MALFORMED_REQUEST`
- `FRAME_TOO_LARGE`
- `TRUNCATED_FRAME`
- `UNSUPPORTED_VERSION`
- `UNKNOWN_METHOD`
- `OUTPUT_TOO_LARGE`
- `CANCELLED`
- `WORKER_UNAVAILABLE`
- `INTERNAL_ERROR`

Error codes are intentionally generic. Do not log request or response bodies,
message text, credentials, or raw exceptions. The current contract code has no
logging calls and no message-content field. Future logging must use event names,
request UUIDs, and safe error codes only.

## Lifecycle and cancellation boundary

The .NET host owns one worker process per service instance and uses inherited
stdin/stdout pipes. It sends hello before status work, allows one in-flight
request, enforces a per-request timeout, and terminates the child if a frame,
correlation ID, handshake, cancellation, or pipe check fails. The executable path
is explicitly configured; no discovery or transport fallback is performed.
Stderr is drained to a sink. A .NET cancellation token cancels the local pipe
operation and invalidates that process; there is no remote-operation cancel
method. Request IDs do not provide replay protection. The service is disposed
when the desktop application exits.

This prototype contains no Matrix SDK, sockets, DNS calls, login/session state,
secrets, or Tor behavior. C# tests cover typed envelope parsing and framing,
service failure/lifecycle paths, and an integration run against the compiled Rust
worker. They prove no security property of cryptography or a future network route.
