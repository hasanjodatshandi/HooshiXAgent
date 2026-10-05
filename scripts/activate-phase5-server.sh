#!/bin/sh
set -eu

release=${1:-/home/hooshixadmin/releases/phase5-20260928}
panel=/home/hooshixadmin/hooshix-panel
gateway=/opt/hooshix/hooshix-gateway
panel_env=/etc/hooshix/panel.env
override_dir=/etc/systemd/system/hooshix-gateway.service.d
override=$override_dir/public-tcp.conf
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/hooshix/phase5-$stamp

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
for path in "$release/hooshix-gateway" "$release/panel/dist" "$release/panel/node_modules" "$release/public-tcp.conf"; do
  if [ ! -e "$path" ]; then
    echo "missing staged release path: $path" >&2
    exit 1
  fi
done
if [ "$(realpath "$panel")" != "$panel" ] || [ -L "$panel/dist" ] || [ -L "$panel/node_modules" ]; then
  echo "unsafe panel path" >&2
  exit 1
fi

. "$panel_env"
db=${HOOSHIX_PANEL_DB:-/var/lib/hooshix/panel.db}
db_dir=$(realpath "$(dirname "$db")")
case "$db_dir" in /var/lib/hooshix|/var/lib/hooshix/*) ;; *) echo "unsafe panel database path: $db" >&2; exit 1 ;; esac
case "$(basename "$db")" in ''|.|..) echo "unsafe panel database name" >&2; exit 1 ;; esac
for suffix in '' -wal -shm; do
  if [ -L "$db$suffix" ]; then echo "symlinked panel database path: $db$suffix" >&2; exit 1; fi
done
mkdir -p "$backup"
install_started=0
rollback() {
  set +e
  echo "activation failed; restoring $backup" >&2
  systemctl stop hooshix-gateway.service hooshix-gateway-b.service hooshix-panel.service || true
  if [ "$install_started" -eq 1 ]; then
    install -o root -g root -m 0755 "$backup/hooshix-gateway" "$gateway"
    rm -rf "$panel/dist" "$panel/node_modules"
    cp -a "$backup/dist" "$panel/dist"
    cp -a "$backup/node_modules" "$panel/node_modules"
    cp -a "$backup/package.json" "$backup/package-lock.json" "$panel/"
    cp -a "$backup/panel.env" "$panel_env"
    rm -f "$db" "$db-wal" "$db-shm"
    for suffix in '' -wal -shm; do
      if [ -f "$backup/panel.db$suffix" ]; then cp -a "$backup/panel.db$suffix" "$db$suffix"; fi
    done
    if [ -f "$backup/no-public-tcp-override" ]; then rm -f "$override"; else install -o root -g root -m 0644 "$backup/public-tcp.conf" "$override"; fi
    systemctl daemon-reload
  fi
  systemctl start hooshix-panel.service hooshix-gateway.service hooshix-gateway-b.service
}
trap 'code=$?; trap - EXIT; if [ "$code" -ne 0 ]; then rollback; fi; exit "$code"' EXIT
trap 'exit 1' HUP INT TERM
systemctl stop hooshix-gateway.service hooshix-gateway-b.service hooshix-panel.service
cp -a "$gateway" "$backup/hooshix-gateway"
cp -a "$panel/dist" "$backup/dist"
cp -a "$panel/node_modules" "$backup/node_modules"
cp -a "$panel/package.json" "$panel/package-lock.json" "$backup/"
cp -a "$panel_env" "$backup/panel.env"
for suffix in '' -wal -shm; do
  if [ -f "$db$suffix" ]; then cp -a "$db$suffix" "$backup/panel.db$suffix"; fi
done
if [ -f "$override" ]; then cp -a "$override" "$backup/public-tcp.conf"; else : >"$backup/no-public-tcp-override"; fi

install_started=1

install -o root -g root -m 0755 "$release/hooshix-gateway" "$gateway"
rm -rf "$panel/dist" "$panel/node_modules"
cp -a "$release/panel/dist" "$panel/dist"
cp -a "$release/panel/node_modules" "$panel/node_modules"
cp -a "$release/panel/package.json" "$release/panel/package-lock.json" "$panel/"
chown -R hooshixadmin:hooshixadmin "$panel/dist" "$panel/node_modules" "$panel/package.json" "$panel/package-lock.json"
grep -q '^HOOSHIX_PUBLIC_TCP_PORT_MIN=' "$panel_env" || echo 'HOOSHIX_PUBLIC_TCP_PORT_MIN=20000' >>"$panel_env"
grep -q '^HOOSHIX_PUBLIC_TCP_PORT_MAX=' "$panel_env" || echo 'HOOSHIX_PUBLIC_TCP_PORT_MAX=29999' >>"$panel_env"
install -d -o root -g root -m 0755 "$override_dir"
install -o root -g root -m 0644 "$release/public-tcp.conf" "$override"
systemctl daemon-reload

systemctl start hooshix-panel.service
sleep 2
systemctl is-active --quiet hooshix-panel.service
systemctl start hooshix-gateway.service hooshix-gateway-b.service
sleep 3
if ! curl -fsS http://127.0.0.1:9090/readyz >/dev/null ||
   ! curl -fsS http://127.0.0.1:9091/readyz >/dev/null; then
  exit 1
fi

trap - EXIT HUP INT TERM
echo "phase 5 active; rollback backup: $backup"
