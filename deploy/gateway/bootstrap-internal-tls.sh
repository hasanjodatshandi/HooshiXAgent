#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tls_dir="${HOOSHIX_TLS_DIR:-$script_dir/runtime/tls}"
metadata_dir="${HOOSHIX_METADATA_DIR:-$script_dir/runtime/metadata}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to bootstrap Gateway internal TLS" >&2
  exit 1
fi

mkdir -p "$tls_dir" "$metadata_dir/authorizations" "$metadata_dir/routes" "$metadata_dir/revocations" "$metadata_dir/generations"
chmod 700 "$tls_dir"
chmod 755 "$metadata_dir" "$metadata_dir/authorizations" "$metadata_dir/routes" "$metadata_dir/revocations" "$metadata_dir/generations"

ca_key="$tls_dir/ca.key"
ca_cert="$tls_dir/ca.crt"
gateway_key="$tls_dir/gateway.key"
gateway_csr="$tls_dir/gateway.csr"
gateway_cert="$tls_dir/gateway.crt"
ext_file="$tls_dir/gateway.ext"

if [[ -f "$ca_key" && ! -f "$ca_cert" ]] || [[ ! -f "$ca_key" && -f "$ca_cert" ]]; then
  echo "partial Gateway CA state detected: ca.key and ca.crt must either both exist or both be absent" >&2
  exit 1
fi

if [[ ! -f "$ca_key" && ! -f "$ca_cert" ]]; then
  ca_tmp_dir="$(mktemp -d "$tls_dir/.ca-bootstrap.XXXXXX")"
  cleanup_ca_tmp() { rm -rf "$ca_tmp_dir"; }
  trap cleanup_ca_tmp EXIT
  openssl genrsa -out "$ca_tmp_dir/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 \
    -key "$ca_tmp_dir/ca.key" \
    -subj "/CN=HooshiX Gateway Deployment CA" \
    -out "$ca_tmp_dir/ca.crt" >/dev/null 2>&1
  chmod 600 "$ca_tmp_dir/ca.key"
  chmod 644 "$ca_tmp_dir/ca.crt"
  mv "$ca_tmp_dir/ca.key" "$ca_key"
  mv "$ca_tmp_dir/ca.crt" "$ca_cert"
  cleanup_ca_tmp
  trap - EXIT
fi

if ! openssl pkey -in "$ca_key" -noout >/dev/null 2>&1 || ! openssl x509 -in "$ca_cert" -noout >/dev/null 2>&1; then
  echo "Gateway CA state is unreadable or malformed" >&2
  exit 1
fi
ca_key_pub="$(openssl pkey -in "$ca_key" -pubout 2>/dev/null)"
ca_cert_pub="$(openssl x509 -in "$ca_cert" -pubkey -noout 2>/dev/null)"
if [[ -z "$ca_key_pub" || "$ca_key_pub" != "$ca_cert_pub" ]]; then
  echo "Gateway CA key/certificate do not match" >&2
  exit 1
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
echo "External metadata projection directories initialized at $metadata_dir"
