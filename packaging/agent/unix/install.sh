#!/usr/bin/env bash
set -euo pipefail

os_name="${HOOSHIX_AGENT_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_binary="${HOOSHIX_AGENT_BINARY:-$script_dir/hooshix-agent}"
no_service=false
rollback=false

case "$os_name" in
  linux)
    prefix="${HOOSHIX_AGENT_PREFIX:-$HOME/.local/bin}"
    state_dir="${HOOSHIX_AGENT_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/hooshixagent}"
    service_path="${HOOSHIX_AGENT_SERVICE_PATH:-$HOME/.config/systemd/user/hooshix-agent.service}"
    ;;
  darwin)
    prefix="${HOOSHIX_AGENT_PREFIX:-$HOME/Library/Application Support/HooshiXAgent/bin}"
    state_dir="${HOOSHIX_AGENT_STATE_DIR:-$HOME/Library/Application Support/HooshiXAgent}"
    service_path="${HOOSHIX_AGENT_SERVICE_PATH:-$HOME/Library/LaunchAgents/com.hooshix.agent.plist}"
    ;;
  *)
    echo "unsupported Agent installer OS: $os_name" >&2
    exit 2
    ;;
esac

while (($#)); do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --state-dir) state_dir="$2"; shift 2 ;;
    --service-path) service_path="$2"; shift 2 ;;
    --no-service) no_service=true; shift ;;
    --rollback) rollback=true; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

target="$prefix/hooshix-agent"
previous="$target.previous"
mkdir -p "$prefix" "$state_dir"
chmod 700 "$state_dir"

restart_persistence() {
  if [[ "$no_service" == true ]]; then
    return
  fi
  case "$os_name" in
    linux)
      if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable --now hooshix-agent.service
        systemctl --user restart hooshix-agent.service
      fi
      ;;
    darwin)
      if command -v launchctl >/dev/null 2>&1; then
        launchctl bootout "gui/$(id -u)" "$service_path" >/dev/null 2>&1 || true
        launchctl bootstrap "gui/$(id -u)" "$service_path"
        launchctl kickstart -k "gui/$(id -u)/com.hooshix.agent"
      fi
      ;;
  esac
}

if [[ "$rollback" == true ]]; then
  if [[ ! -f "$previous" ]]; then
    echo "no previous Agent binary is available for rollback" >&2
    exit 1
  fi
  tmp="$target.rollback-new"
  if [[ -f "$target" ]]; then
    mv "$target" "$tmp"
  fi
  mv "$previous" "$target"
  chmod 755 "$target"
  rm -f "$tmp"
  restart_persistence
  echo "HooshiX Agent rollback restored $target"
  exit 0
fi

if [[ ! -f "$source_binary" ]]; then
  echo "Agent binary not found: $source_binary" >&2
  exit 1
fi

if [[ -f "$target" ]]; then
  cp "$target" "$previous"
  chmod 755 "$previous"
fi
install -m 0755 "$source_binary" "$target"

if [[ "$no_service" != true ]]; then
  mkdir -p "$(dirname "$service_path")"
  "$target" service-spec --state-dir "$state_dir" --binary "$target" >"$service_path"
  chmod 600 "$service_path"
  restart_persistence
fi

echo "HooshiX Agent installed at $target"
echo "Agent state directory: $state_dir"
