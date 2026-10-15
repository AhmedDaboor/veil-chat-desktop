# Veil Chat desktop

This folder is the desktop project root in the larger workspace. Run the commands below from this folder; when working from the larger monorepo, first run `cd desktop`. In the standalone `veil-chat-desktop` repository, this folder is the repository root.

Veil Chat is a Windows/Linux desktop Matrix client built with .NET 10, Avalonia, and an isolated Rust worker. Matrix protocol and cryptographic operations use the pinned official Matrix Rust SDK 0.19.1, with E2EE, encrypted SQLite storage, Rustls TLS, SOCKS transport, and automatic room-key forwarding explicitly selected in Cargo. The worker accepts only typed IPC v2 commands and serializes requests so each response is correlated to one request.

The current client supports login/session restore/logout, encrypted Matrix SQLite storage, discovery/creation/acceptance of one-to-one rooms reported encrypted by the SDK, and text history/send. Invitations can be accepted only when the SDK reports a direct room with known encryption; after joining, the worker rechecks encryption and requires exactly two active members before registering the room in the recipient's `m.direct` account data. For each room, the UI displays the peer identity state available in the SDK's cross-signing store, and warns if identity trust is missing, stale, or violated. Users can initiate Matrix SAS verification through the official SDK, compare the displayed emoji or number string with the peer over a trusted separate channel, then confirm or cancel. The peer must accept the request in a compatible Matrix client; this app does not yet accept incoming verification requests or support QR verification. The SDK's verified state is shown only after it reports completion. The client can display history decrypted by the SDK, but the real two-account flow still requires live verification. It does not support groups, calls, attachments, push notifications, analytics, or advertising. Unauthenticated screens use visibly labeled local sample content. A message can be sent only after the worker confirms an authenticated session, an SDK-reported encrypted room, and an active Tor route. The app has no direct-network fallback.

## Security and deployment status

- The worker starts Tor only from an explicitly configured absolute executable path, with app-owned empty defaults/config files that exclude system or user torrc settings. It uses the Tor SAFECOOKIE control protocol, takes ownership of the Tor process through its authenticated control connection, checks bootstrap progress, and confirms that the configured loopback SOCKS endpoint is reported by that Tor process before granting a route to the Matrix client.
- Matrix HTTP uses the SDK's supplied HTTP client configured with `socks5h`, explicit proxy use, and disabled system/environment proxy bypass. The worker rechecks Tor before each Matrix operation. A missing, exited, unbootstrapped, or inconsistent Tor service blocks the operation.
- Matrix login passwords are not stored. Access/session data and the encrypted SDK-store passphrase are kept in Windows current-user DPAPI or Linux Secret Service. Linux requires an available `secret-tool` client and an unlocked Secret Service. There is no plaintext fallback.
- Room encryption status is enforced before history or send. The SDK-managed SAS flow can verify a peer cross-signing identity; it does not verify identities until both sides compare and confirm the same string. New device verification and incoming-request acceptance are not yet exposed.
- The pinned SDK directly depends on `anymap2 0.13.0`. [RUSTSEC-2026-0319](https://rustsec.org/advisories/RUSTSEC-2026-0319.html) is an informational unmaintained-dependency advisory, not a reported vulnerability; it has no patched version. It remains unsuppressed. Review this supply-chain risk before production.
- This environment has no Tor executable or Linux Secret Service client, so live login, encrypted messaging, Tor bootstrap, and egress behavior have not been exercised here. The code-level fail-closed checks and the no-Tor denial path are tested, but that is not evidence of production Tor anonymity or complete platform security.
- The packaging scripts build a framework-dependent app and place its matching Rust worker beside it. They do not bundle Tor, sign artifacts, or create native installers.

See [SECURITY_STATUS.md](SECURITY_STATUS.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/worker-ipc-v2.md](docs/worker-ipc-v2.md).
For a reproducible, opt-in live Tor and Matrix check, see [docs/live-matrix-test.md](docs/live-matrix-test.md).

## Configuration

The application does not search the filesystem for a worker or Tor binary. Use trusted binaries and set explicit paths before launch.

For a native Windows or Linux worker, set:

- `VEIL_CHAT_WORKER_EXECUTABLE`: absolute path to `veil-chat-ipc-worker` (`.exe` on Windows).
- `VEIL_CHAT_TOR_EXECUTABLE`: absolute path to Tor. The worker starts and supervises this process; a system Tor process is not silently reused.
- `VEIL_CHAT_DATA_DIRECTORY`: optional absolute path for the worker's Tor data and encrypted Matrix stores. Native default is the OS LocalApplicationData `VeilChat` directory. On Windows, use this default or ensure a custom directory ACL grants access only to the current user; the worker does not rewrite Windows ACLs. On Linux, the worker applies owner-only directory permissions.

For a Windows app using a Linux worker in WSL, set all four values:

- `VEIL_CHAT_WORKER_LINUX_EXECUTABLE`: absolute Linux path to the worker.
- `VEIL_CHAT_WORKER_WSL_DISTRO`: exact installed distribution name.
- `VEIL_CHAT_LINUX_DATA_DIRECTORY`: absolute Linux path for worker data.
- `VEIL_CHAT_TOR_LINUX_EXECUTABLE`: absolute Linux path to Tor.

WSL starts the configured distribution with `wsl.exe --distribution … --exec /usr/bin/env …`; the app does not select a distribution or invoke a shell. If worker/Tor configuration is absent or invalid, network operations stay blocked.

Build the worker with the installed Rust toolchain and locked offline dependencies:

```sh
cargo build --manifest-path rust-worker/Cargo.toml --release --locked --offline
```

On Linux x86_64, `bash scripts/package-linux.sh` builds a framework-dependent package at `artifacts/linux-x64`. On Windows x64, run `scripts/package-windows.ps1`; it writes `artifacts/win-x64`. Both scripts use `--locked --offline` for Cargo and `--no-restore` for .NET, and refuse to overwrite an existing output directory. They require the .NET 10 runtime on the target system. Launch with the package's `launch-linux.sh` or `launch-windows.cmd`; set `VEIL_CHAT_TOR_EXECUTABLE` to an installed trusted Tor executable first. The app remains open without Tor, but Matrix operations stay blocked.

Build and test the .NET solution with already restored packages:

```sh
dotnet build VeilChat.Desktop.sln --no-restore -m:1 -p:UseSharedCompilation=false
dotnet test VeilChat.Desktop.sln --no-restore -m:1 -p:UseSharedCompilation=false
```

Rust tests use `cargo test --manifest-path rust-worker/Cargo.toml --locked --offline`; they include a fake Tor executable that exercises SAFECOOKIE control authentication, bootstrap verification, readiness checks, and owned-process shutdown. The .NET integration suite launches the compiled worker and verifies every Matrix network method is denied when Tor is not configured. The standard-library-only opt-in live runner is at `scripts/live-matrix-smoke.py`; its test plan is included at `docs/live-matrix-test.md` in generated packages. On the current host, .NET tests run with Windows .NET through WSL interop, not a Linux-native .NET runtime. Platform signing, a native Linux .NET test run, and actual live Tor/Matrix smoke tests remain deployment prerequisites.
