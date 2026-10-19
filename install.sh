#!/bin/bash
# Open Cloud installer. Safe to re-run: it never overwrites existing secrets or .env.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
command -v docker >/dev/null || { echo "Docker is required: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required."; exit 1; }
[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example. Edit it, then re-run ./install.sh"; [ "${OC_ACCEPT_DEFAULTS:-}" = 1 ] || exit 0; }
set -a; . ./.env; set +a
: "${OC_ROOT:?set OC_ROOT in .env}"
. ./compose-env.sh
if [ "${OC_EDGE_MODE:-internal}" = external ]; then
  [[ "${OC_PROXY_NETWORK:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "OC_PROXY_NETWORK is required in external mode (the network your proxy is on)"; exit 1; }
  docker network inspect "$OC_PROXY_NETWORK" >/dev/null 2>&1 || { echo "network $OC_PROXY_NETWORK not found; create it or fix OC_PROXY_NETWORK"; exit 1; }
fi
for v in OC_CONSOLE_HOST OC_APPS_DOMAIN OC_S3_HOST; do [[ "${!v}" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "$v is invalid"; exit 1; }; done
S="$OC_ROOT/secrets/platform"
mkdir -p "$OC_ROOT"/{apps,data,pgdata,releases,backups,caddy/sites,sites,storage,jobs,audit,watch} "$OC_ROOT/secrets/storage" "$S" "$OC_ROOT/secrets/gateway-clients"
chmod 700 "$OC_ROOT/secrets" "$OC_ROOT/backups"
# Read by the edge (no DAC override) and the gateway (unprivileged user) through direct mounts.
chmod 755 "$OC_ROOT" "$OC_ROOT/caddy" "$OC_ROOT/caddy/sites" "$OC_ROOT/sites"
gen() { [ -s "$1" ] || { head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > "$1"; echo "generated $(basename "$1")"; }; }
gen "$S/agent-token"
gen "$S/restic-password"
gen "$S/watch-token"
cp "$S/watch-token" "$S/watch-token.console"  # same token, separate file per reader (watch and console)
[ -e "$S/llm-upstream-key" ] || : > "$S/llm-upstream-key"
# Open Bedrock (model gateway): endpoint config + usage live in $OC_ROOT/gateway (owned by the gateway user).
mkdir -p "$OC_ROOT/gateway"
if [ ! -s "$OC_ROOT/gateway/config.json" ]; then
  OC_URL="${OC_LLM_UPSTREAM_URL:-}" python3 -c 'import json,os;print(json.dumps({"upstream_url":os.environ["OC_URL"],"endpoints":{}}))' > "$OC_ROOT/gateway/config.json"
fi
if [ ! -s "$S/llm-upstream-key" ]; then
  key="${OC_LLM_PROVIDER_KEY:-}"
  if [ -z "$key" ] && [ -t 0 ]; then read -rsp "Model Gateway provider key (optional, Enter to skip): " key; echo; fi
  [ -n "$key" ] && { printf '%s' "$key" > "$S/llm-upstream-key"; echo "stored provider key as a secret"; }
  unset key
fi
# Open CloudWatch keeps its SQLite database (and the SMTP password, written by the console) here.
mkdir -p "$OC_ROOT/watch"
if [ -n "${OC_SMTP_PASSWORD:-}" ] && [ ! -s "$OC_ROOT/watch/smtp-password" ]; then
  printf '%s' "$OC_SMTP_PASSWORD" > "$OC_ROOT/watch/smtp-password"; echo "stored SMTP password as a secret (delete OC_SMTP_PASSWORD from .env)"
fi
# S3 starts with one never-shared admin identity so anonymous access stays off.
if [ ! -s "$OC_ROOT/secrets/storage/s3.json" ]; then
  python3 -c 'import json,secrets;print(json.dumps({"identities":[{"name":"opencloud-admin","credentials":[{"accessKey":"OCADMIN"+secrets.token_hex(6).upper(),"secretKey":secrets.token_urlsafe(30)}],"actions":["Admin"]}]}))' > "$OC_ROOT/secrets/storage/s3.json"
  echo "generated s3.json"
fi
# SeaweedFS runs as uid 1000 inside its image.
chmod 600 "$OC_ROOT/secrets/storage/s3.json"; chmod 700 "$OC_ROOT/secrets/storage"
chown 1000:1000 "$OC_ROOT/secrets/storage" "$OC_ROOT/secrets/storage/s3.json" 2>/dev/null || echo "warning: run install.sh with sudo so object storage can read its config"
# Containers run as unprivileged users and read these via single-file mounts;
# the parent secrets directory (700) keeps other host users out.
# Each file is 0400 and owned by the single container user that reads it:
# console (uid 10001), llm-gateway (uid 10002). The agent runs as root.
chown 10001:10001 "$S/agent-token" "$S/watch-token.console" && chown 10003:10003 "$S/watch-token" && chown 10002:10002 "$S/llm-upstream-key" "$OC_ROOT/secrets/gateway-clients" \
  || { echo "Run install.sh with sudo (secret files need per-container owners)."; exit 1; }
chmod 400 "$S/agent-token" "$S/llm-upstream-key" "$S/watch-token" "$S/watch-token.console"; chmod 500 "$OC_ROOT/secrets/gateway-clients"
chown -R 10002:10002 "$OC_ROOT/gateway"; chmod 755 "$OC_ROOT/gateway"
chown -R 10003:10003 "$OC_ROOT/watch"; chmod 700 "$OC_ROOT/watch"; [ -e "$OC_ROOT/watch/smtp-password" ] && chmod 600 "$OC_ROOT/watch/smtp-password"
# Admin login: the console (uid 10001) owns its auth directory so it can replace the hash when the
# password is changed. "must-change-password" forces a new password at the first sign-in (see docs/SECURITY.md).
# Earlier versions of this software kept the hash and the two-step secret under secrets/platform.
# Move those two files once, if they are still there. A fresh install has neither.
A="$OC_ROOT/secrets/console"; mkdir -p "$A"
if [ -s "$S/admin-password.scrypt" ] && [ ! -s "$A/admin-password.scrypt" ]; then mv "$S/admin-password.scrypt" "$A/"; echo "moved admin-password.scrypt to $A"; fi
rm -f "$S/admin-password.scrypt"
if [ -s "$S/totp-secret" ] && [ ! -e "$A/totp.json" ]; then
  python3 -c 'import json,sys;print(json.dumps({"secret":open(sys.argv[1]).read().strip(),"last":0,"recovery":[]}))' "$S/totp-secret" > "$A/totp.json"; echo "moved totp-secret to $A/totp.json"
fi
rm -f "$S/totp-secret"
if [ ! -s "$A/admin-password.scrypt" ]; then
  pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
  OC_PW="$pw" python3 -c 'import hashlib,os,secrets;s=secrets.token_bytes(16);print("scrypt$"+s.hex()+"$"+hashlib.scrypt(os.environ["OC_PW"].encode(),salt=s,n=2**14,r=8,p=1).hex())' > "$A/admin-password.scrypt"
  : > "$A/must-change-password"
  ADMIN_PW=$pw
fi
chown -R 10001:10001 "$A"; chmod 700 "$A"; chmod 600 "$A"/*
if [ "${OC_EDGE_MODE:-internal}" = internal ]; then
  if [ "$OC_TLS" = internal ]; then tls="local_certs"; else tls="email ${OC_ACME_EMAIL:?set OC_ACME_EMAIL}"; fi
  # OC_S3_PUBLIC=0: no public S3 site (no DNS for it, so no certificate retries); apps still use storage:8333 inside.
  s3cut=""; [ "${OC_S3_PUBLIC:-1}" = 0 ] && s3cut="/# s3-public-begin/,/# s3-public-end/d"
  sed -e "$s3cut" -e "s|__TLS_GLOBAL__|$tls|" -e "s|__CONSOLE_HOST__|$OC_CONSOLE_HOST|" -e "s|__S3_HOST__|$OC_S3_HOST|" edge/Caddyfile.template > "$OC_ROOT/caddy/Caddyfile"
  chmod 644 "$OC_ROOT/caddy/Caddyfile"
fi
# Observe mode: mount the given files read-only into the agent (single files, never directories).
O="$OC_ROOT/observe.compose.yaml"; rm -f "$O"
if [ "${OC_OBSERVE:-0}" = 1 ] && [ -n "${OC_OBSERVE_STATUS_JSON:-}${OC_OBSERVE_BACKUP_MARKERS:-}" ]; then
  { echo "services:"; echo "  agent:"; echo "    volumes:"
    for f in ${OC_OBSERVE_STATUS_JSON:-} ${OC_OBSERVE_BACKUP_MARKERS:-}; do
      [[ "$f" =~ ^/[A-Za-z0-9._/-]+$ ]] && [ -f "$f" ] || { echo "observe mount $f must be an existing file" >&2; exit 1; }
      [ "$f" = "${OC_OBSERVE_STATUS_JSON:-}" ] && t=status.json || t="backup-$(basename "$f")"
      echo "      - $f:/run/observe/$t:ro"
    done; } > "$O"
  chmod 644 "$O"; . ./compose-env.sh
fi
# Host sources and mounts (opt-in): the agent sees each allowlisted path read-only, at the same path, so it can
# validate it and copy a server-folder source into the build. It never reads secret files.
H="$OC_ROOT/host-mounts.compose.yaml"; rm -f "$H"
hm=$(for p in ${OC_LOCAL_SOURCES:-} ${OC_ALLOWED_DATA_ROOTS:-} ${OC_ALLOWED_SECRET_PATHS:-}; do echo "$p"; done | sort -u)
if [ -n "$hm" ]; then
  { echo "services:"; echo "  agent:"; echo "    volumes:"
    for p in $hm; do
      [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "/$p/" != *"/../"* ]] && [ -e "$p" ] || { echo "allowlisted path $p must exist (absolute, no ..)" >&2; exit 1; }
      case "$p" in /|/etc|/proc|/sys|/dev|/var/run|/run|/var/lib/docker|"$OC_ROOT"|"$OC_ROOT"/*) echo "refusing to allowlist $p" >&2; exit 1;; esac
      echo "      - $p:$p:ro"
    done; } > "$H"
  chmod 644 "$H"
fi
# Builder on a host that restricts unprivileged user namespaces (Ubuntu 23.10+/24.04): load a profile that allows
# userns for the builder container only. The sysctl itself is left on.
builder_on=0; { [ "${OC_EDGE_MODE:-internal}" = internal ] || [ "${OC_BUILDER:-0}" = 1 ]; } && builder_on=1
if [ "$builder_on" = 1 ] && [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
  command -v apparmor_parser >/dev/null || { echo "apparmor_parser is required to run the builder on this host" >&2; exit 1; }
  install -m 644 -o root -g root deploy/apparmor/opencloud-builder /etc/apparmor.d/opencloud-builder
  apparmor_parser -r /etc/apparmor.d/opencloud-builder
  echo "loaded AppArmor profile opencloud-builder (user namespaces for oc-builder only)"
fi
. ./compose-env.sh
docker compose up -d --build --wait --wait-timeout 180
echo
echo "Open Cloud is running: https://$OC_CONSOLE_HOST"
if [ "${OC_EDGE_MODE:-internal}" = external ]; then
  echo "External proxy mode: oc-edge is not running. Add a site for $OC_CONSOLE_HOST to your proxy,"
  echo "pointing at oc-console:8080 on $OC_PROXY_NETWORK (see docs/console.caddy.example)."
fi
if [ -n "${ADMIN_PW:-}" ]; then
  echo "Admin password (shown once, only its hash is stored): $ADMIN_PW"
  echo "The console asks you to choose your own password at the first sign-in."
  echo "Lost it? ./opencloud reset-password"
fi
cat <<MSG

Firewall (not changed by this script). Expose only SSH, 80 and 443, e.g. with ufw:
  ufw default deny incoming; ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw enable
Docker-published ports bypass ufw; Open Cloud publishes only 80/443 (edge). Don't add others.
DNS: point $OC_CONSOLE_HOST and *.$OC_APPS_DOMAIN at this machine (docs/DNS.md, and the DNS page).
Backups stay on this machine until you copy $OC_ROOT/backups/restic elsewhere (docs/RESTORE.md).
Next: docs/INSTALL.md and docs/LOGIN.md.
MSG
