#!/usr/bin/env bash
set -euo pipefail

os_name="${HOOSHIX_AGENT_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
purge_state=false
no_service=false

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
    echo "unsupported Agent uninstaller OS: $os_name" >&2
    exit 2
    ;;
esac

while (($#)); do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --state-dir) state_dir="$2"; shift 2 ;;
    --service-path) service_path="$2"; shift 2 ;;
    --no-service) no_service=true; shift ;;
    --purge-state) purge_state=true; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "$no_service" != true ]]; then
  case "$os_name" in
    linux)
      if command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now hooshix-agent.service >/dev/null 2>&1 || true
        rm -f "$service_path"
        systemctl --user daemon-reload >/dev/null 2>&1 || true
      else
        rm -f "$service_path"
      fi
      ;;
    darwin)
      if command -v launchctl >/dev/null 2>&1; then
        launchctl bootout "gui/$(id -u)" "$service_path" >/dev/null 2>&1 || true
      fi
      rm -f "$service_path"
      ;;
  esac
fi

rm -f "$prefix/hooshix-agent" "$prefix/hooshix-agent.previous"
if [[ "$purge_state" == true ]]; then
  rm -rf "$state_dir"
fi

echo "HooshiX Agent uninstalled"
if [[ "$purge_state" != true ]]; then
  echo "State preserved at $state_dir"
fi
