#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tls_dir="${HOOSHIX_TLS_DIR:-$script_dir/runtime/tls}"
metadata_dir="${HOOSHIX_METADATA_DIR:-$script_dir/runtime/metadata}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to bootstrap Gateway internal TLS" >&2
  exit 1
fi

# Every private key created below must be owner-only from the moment it exists,
# not from a chmod that runs later. Under the default umask a freshly generated
# gateway.key is created 0644 and is world-readable for the whole window before
# it is tightened.
umask 077

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
  # The deployment CA must be a well-formed trust anchor, not just a signing
  # key: an extension-less CA is accepted by Go, Caddy and Schannel, but strict
  # OpenSSL 3.x verification rejects it outright with "CA cert does not include
  # key usage extension". basicConstraints and keyUsage are therefore marked
  # critical, so no consumer can treat the CA as a leaf or drop the extension.
  # The extension set is supplied through a config file instead of -addext so
  # the bootstrap keeps working with the LibreSSL req on macOS.
  cat >"$ca_tmp_dir/ca.cnf" <<'EOF'
[req]
distinguished_name=ca_dn
prompt=no
x509_extensions=ca_ext

[ca_dn]
CN=HooshiX Gateway Deployment CA

[ca_ext]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
  openssl genrsa -out "$ca_tmp_dir/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 \
    -config "$ca_tmp_dir/ca.cnf" \
    -key "$ca_tmp_dir/ca.key" \
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
chmod 640 "$gateway_key"
# The gateway TLS key must be readable by the runtime container's fixed
# uid/gid (10001, per the Dockerfile) over its read-only bind mount, while
# world access stays denied. chgrp needs root or group membership; CI gates
# run unprivileged but hold passwordless sudo, so retry through sudo -n.
if ! chgrp 10001 "$gateway_key" 2>/dev/null; then
  sudo -n chgrp 10001 "$gateway_key" 2>/dev/null || true
fi
# Fail loudly instead of leaving a key the runtime cannot read. The previous
# `|| true` swallowed the chgrp failure, so the only symptom was a Gateway
# container that exited at startup with an unrelated permission error. The
# check is Linux-only: Docker Desktop on macOS/Windows maps bind-mount
# ownership itself, so gid 10001 is neither required nor observable there.
if [[ "$(uname -s)" == "Linux" ]]; then
  key_group="$(stat -c '%g' "$gateway_key")"
  if [[ "$key_group" != "10001" ]]; then
    echo "gateway.key is still group $key_group, not 10001: the Gateway container (user 10001:10001)" >&2
    echo "cannot read its TLS key over the read-only bind mount and will exit at startup." >&2
    echo "Re-run as root, or with an account permitted to chgrp the key to 10001." >&2
    exit 1
  fi
else
  echo "note: skipped the gateway.key gid 10001 check on $(uname -s) (Docker Desktop maps ownership itself)" >&2
fi
# The CA key stays owner-only and is never mounted. Certificates are public.
chmod 644 "$ca_cert" "$gateway_cert"

echo "Gateway internal TLS initialized at $tls_dir"
echo "Keep $ca_key private; it is not mounted into runtime containers."
echo "External metadata projection directories initialized at $metadata_dir"
