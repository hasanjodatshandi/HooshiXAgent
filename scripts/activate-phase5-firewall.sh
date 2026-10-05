#!/bin/sh
set -eu

config=/etc/nftables.conf
rule='        iifname "eth0" ip daddr 188.240.196.151 tcp dport 20000-29999 accept'
marker='        tcp dport 443 accept'
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/hooshix/phase5-firewall-$stamp.conf

[ "$(id -u)" -eq 0 ] || { echo 'run as root' >&2; exit 1; }
[ "$(grep -Fxc "$marker" "$config")" -eq 1 ] || { echo 'unexpected nftables config' >&2; exit 1; }
if grep -Fqx "$rule" "$config"; then
  echo 'phase 5 firewall rule already installed'
  exit 0
fi
mkdir -p /var/backups/hooshix
cp -p "$config" "$backup"
temporary=$(mktemp /etc/.nftables.phase5.XXXXXX)
applied=0
restore() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$code" -ne 0 ] && [ "$applied" -eq 1 ]; then
    cp -p "$backup" "$config"
    nft -f "$config"
  fi
  rm -f "$temporary"
  exit "$code"
}
trap restore EXIT
trap 'exit 1' HUP INT TERM
awk -v marker="$marker" -v rule="$rule" '{ print; if ($0 == marker) { print ""; print "        # HooshiX public TCP; Gateway enforces leases and source CIDRs"; print rule } }' "$config" >"$temporary"
nft -c -f "$temporary"
applied=1
install -o root -g root -m 0755 "$temporary" "$config"
nft -f "$config"
nft list chain inet filter input | grep -Fq 'tcp dport 20000-29999 accept'
echo "phase 5 firewall active; rollback backup: $backup"
