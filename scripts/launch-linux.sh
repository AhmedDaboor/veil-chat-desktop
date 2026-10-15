#!/usr/bin/env sh
set -eu

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker="$package_dir/worker/veil-chat-ipc-worker"
app="$package_dir/VeilChat.Desktop"

if [ ! -x "$worker" ] || [ ! -x "$app" ]; then
  echo "The Veil Chat Linux package is incomplete." >&2
  exit 2
fi

VEIL_CHAT_WORKER_EXECUTABLE="$worker"
export VEIL_CHAT_WORKER_EXECUTABLE
exec "$app" "$@"
