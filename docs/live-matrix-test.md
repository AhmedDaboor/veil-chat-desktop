# Two-account live Matrix and Tor smoke test

This opt-in Linux x86_64/Ubuntu-24.04 WSL test uses the already-built worker and an already-installed Tor executable. It installs nothing. The Python runner uses only the standard library and asks for both account passwords with hidden prompts; it does not save credentials or print IPC payloads.

The runner starts two independent workers, each with its own supervised Tor process, Tor data, and encrypted Matrix SDK store. It checks:

1. IPC v2 hello and login for two different controlled Matrix accounts.
2. SAFECOOKIE authentication, complete Tor bootstrap, and the expected loopback SOCKS listener for both workers.
3. Encrypted one-to-one room creation and recipient invitation discovery.
4. Recipient-side acceptance only after the SDK reports a direct invite with known encryption enabled, followed by post-join encryption and exactly-two-active-member checks.
5. Encrypted text send and visibility in sender and recipient SDK history. Recipient history must contain the unique marker as decrypted text.

The runner creates a fresh owner-only `--data-dir` with separate `sender` and `recipient` subdirectories. It leaves these directories in place. Per-run SDK-store passphrases and returned session tokens are not saved, so preserve any diagnostics before deleting this dedicated test data.

## Preconditions

- Build the worker with `cargo build --manifest-path rust-worker/Cargo.toml --release --locked --offline`.
- Have a trusted Tor executable already installed and an HTTPS Matrix homeserver reachable through Tor.
- Use two controlled Matrix accounts. `--recipient` must be the full Matrix user ID of the account used at the recipient password prompt.
- Choose a fresh absolute data directory below a parent directory that already exists. The runner refuses to use an existing directory.
- Run the script from Linux or Ubuntu-24.04 WSL. This does not verify Windows-native behavior.

Run this from the desktop project root (in the larger monorepo, first `cd desktop`; in the standalone repository, use its root). Replace the homeserver, recipient, and Tor path:

```sh
python3 scripts/live-matrix-smoke.py \
  --worker "$PWD/rust-worker/target/release/veil-chat-ipc-worker" \
  --tor /usr/bin/tor \
  --data-dir "$HOME/VeilChat-live-smoke-$(date +%Y%m%d-%H%M%S)" \
  --homeserver https://matrix.example.org \
  --recipient @bob:matrix.example.org
```

The script prompts for both usernames and passwords. Passwords are not accepted as arguments. It prints the two user IDs, room ID, and a unique marker only after both SDK clients retrieve that marker from encrypted room history.

## Evidence limits and egress observation

A passing run is evidence that the recipient Matrix SDK processed the event into the expected plaintext after joining the encrypted room. It does not establish that a UI rendered it correctly, verify either user's device identity, establish anonymity, or independently prove that the host sent no direct network traffic. The app's interactive SAS verification is a separate user-driven flow; the runner does not initiate or confirm it.

For Tor-only egress evidence, run in a dedicated test environment with an independently observed process-aware network policy or connection trace. Confirm both worker processes connect only to their own loopback SOCKS listener, with Tor processes owning external relay connections, and that neither worker has a direct homeserver connection. Preserve the policy/trace without credentials or tokens.

Record these fields for each run:

| Field | Result |
| --- | --- |
| OS / distribution and architecture | |
| Rust worker build revision and binary hash | |
| Tor version and executable path | |
| Homeserver and test-account IDs (no credentials) | |
| Both Tor bootstrap checks | |
| Encrypted invitation, acceptance, and post-join encryption check | |
| Sender history and recipient-decrypted marker | |
| Independent direct-egress observation and method | |
| Failures and worker error codes | |

## Known release blockers

- No live Tor/Matrix run is recorded by this repository yet. Complete this test before claiming runtime support.
- Peer SAS verification is initiated in Veil Chat, but the recipient must accept in a compatible Matrix client. Compare all SAS symbols over an independent trusted channel. Incoming requests and per-device/QR flows are not exposed; the live runner does not verify identity.
- The pinned official `matrix-sdk 0.19.1` package depends directly on `anymap2 0.13.0`. RustSec marks it unmaintained (informational, not a reported vulnerability), with no patched version. The official release list still shows 0.19.1 as latest. Do not patch the dependency locally or suppress the advisory; reassess when upstream publishes a reviewed stable resolution.
- Windows packaging, Windows live Tor/Matrix behavior, and native Linux .NET runtime tests need separate verification.
