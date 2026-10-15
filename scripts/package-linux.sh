#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd -- "$script_dir/.." && pwd)"
repo_root="$(cd -- "$desktop_dir/.." && pwd)"
output_dir="${VEIL_CHAT_PACKAGE_OUTPUT:-$desktop_dir/artifacts/linux-x64}"
dotnet_command="${DOTNET_EXE:-dotnet}"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) echo "Packaging supports Linux x86_64 on the current host only." >&2; exit 2 ;;
esac

command -v cargo >/dev/null || { echo "Rust Cargo is required." >&2; exit 2; }
command -v "$dotnet_command" >/dev/null || { echo "The .NET 10 SDK command is unavailable." >&2; exit 2; }

if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi
if [[ -e "$output_dir" ]]; then
  echo "Output already exists; choose a new VEIL_CHAT_PACKAGE_OUTPUT path: $output_dir" >&2
  exit 2
fi

dotnet_output_dir="$output_dir"
if [[ "$dotnet_command" == *.exe ]]; then
  command -v wslpath >/dev/null || { echo "wslpath is required when using Windows dotnet.exe from WSL." >&2; exit 2; }
  dotnet_output_dir="$(wslpath -w "$output_dir")"
fi

cd "$desktop_dir"
cargo build --manifest-path rust-worker/Cargo.toml --release --locked --offline
"$dotnet_command" publish src/VeilChat.Desktop/VeilChat.Desktop.csproj \
  --configuration Release --runtime linux-x64 --self-contained false --no-restore \
  --output "$dotnet_output_dir"

mkdir -p "$output_dir/worker" "$output_dir/docs" "$output_dir/scripts"
install -m 0755 rust-worker/target/release/veil-chat-ipc-worker \
  "$output_dir/worker/veil-chat-ipc-worker"
install -m 0755 scripts/launch-linux.sh "$output_dir/launch-linux.sh"
install -m 0644 scripts/live-matrix-smoke.py "$output_dir/scripts/live-matrix-smoke.py"
install -m 0644 docs/live-matrix-test.md "$output_dir/docs/live-matrix-test.md"
install -m 0644 README.md SECURITY.md SECURITY_STATUS.md CONTRIBUTING.md "$output_dir/"
echo "Created framework-dependent Linux package at $output_dir"
echo "Set VEIL_CHAT_TOR_EXECUTABLE to a trusted Tor binary before launching."
