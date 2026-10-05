#!/bin/sh
set -eu

release=${1:-/home/hooshixadmin/releases/phase4-20260927}
panel=/home/hooshixadmin/hooshix-panel
gateway=/opt/hooshix/hooshix-gateway
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/hooshix/phase4-$stamp

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
for path in "$release/hooshix-gateway" "$release/panel/dist" "$release/panel/node_modules"; do
  if [ ! -e "$path" ]; then
    echo "missing staged release path: $path" >&2
    exit 1
  fi
done

. /etc/hooshix/panel.env
db=${HOOSHIX_PANEL_DB:-/var/lib/hooshix/panel.db}
mkdir -p "$backup"
cp -a "$gateway" "$backup/hooshix-gateway"
cp -a "$panel/dist" "$backup/dist"
cp -a "$panel/node_modules" "$backup/node_modules"
cp -a "$panel/package.json" "$panel/package-lock.json" "$backup/"
if [ -f "$db" ]; then
  cp -a "$db" "$backup/panel.db"
fi

rollback() {
  echo "activation failed; restoring $backup" >&2
  systemctl stop hooshix-gateway.service hooshix-gateway-b.service hooshix-panel.service || true
  install -o root -g root -m 0755 "$backup/hooshix-gateway" "$gateway"
  rm -rf "$panel/dist" "$panel/node_modules"
  cp -a "$backup/dist" "$panel/dist"
  cp -a "$backup/node_modules" "$panel/node_modules"
  cp -a "$backup/package.json" "$backup/package-lock.json" "$panel/"
  if [ -f "$backup/panel.db" ]; then
    cp -a "$backup/panel.db" "$db"
  fi
  systemctl start hooshix-panel.service hooshix-gateway.service hooshix-gateway-b.service
}

systemctl stop hooshix-gateway.service hooshix-gateway-b.service hooshix-panel.service
install -o root -g root -m 0755 "$release/hooshix-gateway" "$gateway"
rm -rf "$panel/dist" "$panel/node_modules"
cp -a "$release/panel/dist" "$panel/dist"
cp -a "$release/panel/node_modules" "$panel/node_modules"
cp -a "$release/panel/package.json" "$release/panel/package-lock.json" "$panel/"
chown -R hooshixadmin:hooshixadmin "$panel/dist" "$panel/node_modules" "$panel/package.json" "$panel/package-lock.json"

if ! systemctl start hooshix-panel.service; then rollback; exit 1; fi
sleep 2
if ! systemctl is-active --quiet hooshix-panel.service; then rollback; exit 1; fi
if ! systemctl start hooshix-gateway.service hooshix-gateway-b.service; then rollback; exit 1; fi
sleep 3
if ! curl -fsS http://127.0.0.1:9090/readyz >/dev/null ||
   ! curl -fsS http://127.0.0.1:9091/readyz >/dev/null; then
  rollback
  exit 1
fi

echo "phase 4 active; rollback backup: $backup"
