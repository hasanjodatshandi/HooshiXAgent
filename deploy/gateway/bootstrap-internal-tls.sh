#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tls_dir="${HOOSHIX_TLS_DIR:-$script_dir/runtime/tls}"
metadata_dir="${HOOSHIX_METADATA_DIR:-$script_dir/runtime/metadata}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to bootstrap Gateway internal TLS" >&2
  exit 1
fi

mkdir -p "$tls_dir" "$metadata_dir/authorizations" "$metadata_dir/routes" "$metadata_dir/revocations"
chmod 700 "$tls_dir"
chmod 755 "$metadata_dir" "$metadata_dir/authorizations" "$metadata_dir/routes" "$metadata_dir/revocations"

ca_key="$tls_dir/ca.key"
ca_cert="$tls_dir/ca.crt"
gateway_key="$tls_dir/gateway.key"
gateway_csr="$tls_dir/gateway.csr"
gateway_cert="$tls_dir/gateway.crt"
ext_file="$tls_dir/gateway.ext"

if [[ ! -f "$ca_key" || ! -f "$ca_cert" ]]; then
  openssl genrsa -out "$ca_key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 \
    -key "$ca_key" \
    -subj "/CN=HooshiX Gateway Deployment CA" \
    -out "$ca_cert" >/dev/null 2>&1
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$gateway_key"
openssl req -new -key "$gateway_key" -subj "/CN=gateway" -out "$gateway_csr" >/dev/null 2>&1
cat >"$ext_file" <<'EOF'
subjectAltName=DNS:gateway
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
EOF
openssl x509 -req -sha256 -days 397 \
  -in "$gateway_csr" \
  -CA "$ca_cert" \
  -CAkey "$ca_key" \
  -CAcreateserial \
  -extfile "$ext_file" \
  -out "$gateway_cert" >/dev/null 2>&1

rm -f "$gateway_csr" "$ext_file" "$tls_dir/ca.srl"
chmod 600 "$ca_key"
# Parent directory is 0700; runtime containers receive only explicitly mounted files.
chmod 644 "$ca_cert" "$gateway_cert" "$gateway_key"

echo "Gateway internal TLS initialized at $tls_dir"
echo "Keep $ca_key private; it is not mounted into runtime containers."
echo "External metadata snapshot directories initialized at $metadata_dir"
