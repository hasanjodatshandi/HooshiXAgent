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

guard_purge_state() {
  local candidate="$1"
  if [[ -z "$candidate" || "$candidate" != /* ]]; then
    echo "refusing unsafe Agent state purge path: $candidate" >&2
    exit 2
  fi
  if [[ "$candidate" == *"/../"* || "$candidate" == */.. || "$candidate" == ../* ]]; then
    echo "refusing Agent state purge path containing parent traversal: $candidate" >&2
    exit 2
  fi
  local trimmed="${candidate%/}"
  if [[ -z "$trimmed" || "$trimmed" == "/" || "$trimmed" == "${HOME%/}" ]]; then
    echo "refusing unsafe Agent state purge path: $candidate" >&2
    exit 2
  fi
  local relative="${trimmed#/}"
  if [[ "$relative" != */* ]]; then
    echo "refusing shallow Agent state purge path: $candidate" >&2
    exit 2
  fi
  if [[ -L "$candidate" ]]; then
    echo "refusing symlink Agent state purge path: $candidate" >&2
    exit 2
  fi
  if [[ -e "$candidate" ]]; then
    local resolved
    resolved="$(cd "$candidate" && pwd -P)"
    if [[ "$resolved" == "/" || "$resolved" == "$HOME" ]]; then
      echo "refusing resolved unsafe Agent state purge path: $resolved" >&2
      exit 2
    fi
    if find "$candidate" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
      local marker="$candidate/.hooshix-agent-state"
      if [[ ! -f "$marker" || -L "$marker" ]] || [[ "$(cat "$marker")" != "hooshix-agent-state-v1" ]]; then
        echo "refusing to purge unowned non-empty Agent state directory without a valid real marker: $candidate" >&2
        exit 2
      fi
    fi
  fi
}

if [[ "$purge_state" == true ]]; then
  guard_purge_state "$state_dir"
fi

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
