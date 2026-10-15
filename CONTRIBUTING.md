# Contributing

Veil Chat is pre-production. Check [SECURITY_STATUS.md](SECURITY_STATUS.md) before making security or deployment claims.

Run development commands from this project root. In the larger workspace, first change to `desktop/`.

```sh
cargo fmt --manifest-path rust-worker/Cargo.toml -- --check
cargo test --manifest-path rust-worker/Cargo.toml --locked --offline
cargo build --manifest-path rust-worker/Cargo.toml --locked --offline
dotnet build VeilChat.Desktop.sln --no-restore -m:1 -p:UseSharedCompilation=false
dotnet test VeilChat.Desktop.sln --no-restore -m:1 -p:UseSharedCompilation=false
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

Keep Matrix operations fail-closed behind the supervised Tor route and SDK-reported room encryption. Use the official Matrix Rust SDK APIs; do not add custom cryptography or direct-network fallback. Keep credentials, session stores, logs, and package outputs out of source control. Review dependency advisories and preserve the documented `anymap2` advisory until an upstream stable resolution is verified.

Live Matrix and Tor checks require controlled accounts, installed Tor, and a dedicated test environment. Never include account credentials or session data in a change, test output, or issue.
