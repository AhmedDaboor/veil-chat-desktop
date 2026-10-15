# Veil Chat worker IPC contract, version 2

The .NET Core service and Rust worker communicate over the child process's private stdin/stdout pipes. Version 2 adds Matrix and Tor commands while retaining strict JSON Lines framing and one outstanding request at a time.

## Envelope and limits

Requests have exactly `v`, `kind`, `id`, `method`, and `payload` properties. Responses have exactly `v`, `kind`, `id`, `ok`, `result`, and `error`. IDs are non-empty canonical UUID strings and must match the active request. Duplicate and unknown properties are rejected. JSON must be valid UTF-8, contain no comments/trailing commas, and nest no more than eight containers.

Each frame is at most 65,536 bytes before LF; CRLF is accepted. C# reads bounded frames and the Rust worker terminates after oversized or truncated input. Output also has a 65,536-byte limit. stdout is protocol-only; stderr is drained and discarded. Errors use fixed codes and never echo input or raw exception text.

## Methods

| Method | Payload | Worker behavior |
| --- | --- | --- |
| `worker.hello` | `{}` | Returns protocol version. |
| `privacy.status` | `{}` | Reports SDK E2EE support and `tor_required`; this does not mean an account or route is active. |
| `tor.status` | `{}` | Reports configured/not-started, authenticated bootstrap plus SOCKS listener readiness, or unavailable. Does not start Tor by itself. |
| `matrix.login` | `homeserver`, `username`, `password`, `storePassphrase`, `storeId` | Requires HTTPS and verified Tor; logs in through the official SDK and creates the encrypted SDK store. |
| `matrix.restore` | `homeserver`, `session`, `storePassphrase`, `storeId` | Restores SDK session/store through verified Tor. |
| `matrix.logout` | `{}` | Requires verified Tor and asks the SDK to log out. |
| `rooms.list` | `{}` | Syncs once and returns only joined rooms marked direct, confirmed encrypted, with exactly two active members including the current user. Each result includes the peer user ID and the SDK's cached cross-signing identity status (`unknown`, `unverified`, `verified`, `previously_verified`, or `verification_violation`). Missing identities remain `unknown`; the worker does not manually trust or pin identities. |
| `invites.list` | `{}` | Syncs once and returns bounded invitation metadata, including directness and whether encryption is known and enabled. |
| `room.create_dm` | `userId` | Creates an SDK direct room; C# accepts it only when encryption is confirmed. |
| `room.accept_invite` | `roomId` | Joins only a direct invite with known encryption enabled, syncs, rechecks encryption and exactly two active members, and records the room in the recipient's `m.direct` account data. Leaves the room if post-join checks or direct-room registration fail. Returns `DIRECT_MESSAGE_REQUIRED` when membership is not exactly one peer plus the current user. |
| `room.messages` | `roomId` | Returns bounded text events only after checking encryption. |
| `room.send_text` | `roomId`, `body` | Sends through the SDK only after checking the room encryption state. |
| `peer_verification.start` | `peerUserId` | Starts one SDK-managed SAS verification for a peer with an encrypted direct room. The worker advertises SAS only and keeps the verification handle in memory. |
| `peer_verification.status` | `peerUserId`, `flowId` | Syncs through Tor and returns the SDK state, SAS emoji/decimal data when ready, and current cached peer identity state. |
| `peer_verification.confirm` | `peerUserId`, `flowId` | Confirms only after the SDK reports that the SAS can be presented. The UI calls this only after the user selects “The SAS matches.” |
| `peer_verification.cancel` | `peerUserId`, `flowId` | Cancels the active request or SAS flow through the SDK. |

All methods that can reach Matrix require an active worker-owned Tor process, authenticated control port, complete bootstrap, and the expected loopback SOCKS listener. The Matrix client uses `socks5h` with proxy bypass disabled. No worker method provides a direct-network fallback. IPC payload validation is not a substitute for Matrix authentication or end-to-end cryptography; the SDK performs those operations.

## Lifecycle and failure handling

The .NET service lazily starts an explicitly configured absolute executable, performs the hello handshake, and permits one in-flight request. It enforces response shape and request-ID correlation, a timeout, and cleanup on cancellation, unexpected extra output, worker exit, malformed response, or disposal. A process launch uses an argument list without a shell and a minimal environment allowlist. The worker owns Tor over a SAFECOOKIE-authenticated control connection; Tor shuts down when the owned connection closes.

Request cancellation stops the local worker process rather than attempting to cancel a remote Matrix action. A request may already have reached the homeserver before the caller observes cancellation. Request IDs correlate frames but are not replay protection.

## Security limits

Passwords cross the local private pipe only for login and are not stored by the app. Session tokens and the SDK store passphrase are persisted only through Windows current-user DPAPI or Linux Secret Service. Message bodies are limited and never written to application logs. Peer verification is SAS-only, initiated by this client, and held in worker memory; the other side must accept from a compatible Matrix client. The app does not expose incoming verification requests or QR flows. Users must compare all displayed SAS symbols over a trusted separate channel and must cancel on any mismatch. Real Tor bootstrap, Tor-only egress, Matrix login, encrypted messaging, and interactive verification still require live platform verification; the no-Tor denial test proves only fail-closed behavior when Tor is absent.
