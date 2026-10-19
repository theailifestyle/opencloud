#!/bin/bash
# End-to-end check for OC_EDGE_MODE=external: a stand-in "existing" Caddy fronts the console.
# Usage: OC_PW=<admin password> tests/e2e-external.sh   (after install with OC_EDGE_MODE=external)
# The proxy runs on 127.0.0.1:18443 with Caddy's internal CA, using docs/console.caddy.example.
set -uo pipefail
grep() { if [ "${1:-}" = -q ]; then shift; command grep "$@" >/dev/null; else command grep "$@"; fi; }
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
[ "${OC_EDGE_MODE:-}" = external ] || { echo "needs OC_EDGE_MODE=external in .env"; exit 2; }
FAILS=0; U="https://$OC_CONSOLE_HOST:18443"; J=$(mktemp)
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS+1)); fi; }
c() { curl -sk -b "$J" -c "$J" --resolve "$OC_CONSOLE_HOST:18443:127.0.0.1" "$@"; }
ports() { local p; p=$(docker inspect "$1" --format '{{json .NetworkSettings.Ports}}') || return 0; grep -q HostPort <<<"$p"; }
P=$(mktemp -d); chmod 755 $P
{ echo "{"; echo "	local_certs"; echo "}"; sed -e "s/^console.example.com {/$OC_CONSOLE_HOST:443 {/" docs/console.caddy.example; } > $P/Caddyfile; chmod 644 $P/Caddyfile
docker rm -f e2e-proxy >/dev/null 2>&1
docker run -d --name e2e-proxy --network "$OC_PROXY_NETWORK" -p 127.0.0.1:18443:443 -v $P/Caddyfile:/etc/caddy/Caddyfile:ro caddy:${OC_CADDY_TAG:-2.11.7-alpine} >/dev/null
for _ in $(seq 60); do c -o /dev/null $U/healthz && break; sleep 1; done

echo "== external proxy mode"
check "example site snippet validates in Caddy" 'docker exec e2e-proxy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1'
check "oc-edge not running" '! docker inspect oc-edge >/dev/null 2>&1'
check "no Caddyfile rendered by the installer" '[ ! -e "$OC_ROOT/caddy/Caddyfile" ]'
for x in oc-console oc-agent oc-llm-gateway oc-storage oc-watch; do check "$x publishes no ports" 'docker inspect $x >/dev/null && ! ports $x'; done
check "builder not started in external mode (OC_BUILDER unset)" '! docker inspect oc-builder >/dev/null 2>&1'
ON=$(docker network inspect "$OC_PROXY_NETWORK" --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' | sort | xargs)
check "only oc-console joins the proxy network ($ON)" '[ "$ON" = "e2e-proxy oc-console" ]'
check "console healthy through the external proxy" '[ "$(c $U/healthz)" = ok ]'
check "wrong password rejected" '[ "$(c -o /dev/null -w %{http_code} -X POST -d password=wrong $U/login)" = 401 ]'
c -o /dev/null -X POST --data-urlencode "password=$OC_PW" $U/login
check "first sign-in redirects to change password (through the proxy)" '[ "$(c -o /dev/null -w %{redirect_url} $U/)" = "$U/account/password" ]'
PT=$(c $U/account/password | grep -o 'name=csrf value="[^"]*"' | head -1 | cut -d'"' -f2); NEWPW="ext memorable $RANDOM pass"
check "password change through the proxy (Secure cookie, CSRF)" '[ "$(c -o /dev/null -w %{http_code} -X POST -d csrf=$PT --data-urlencode "current=$OC_PW" --data-urlencode "new=$NEWPW" --data-urlencode "confirm=$NEWPW" $U/account/password)" = 303 ]'
OC_PW=$NEWPW
check "login through the external proxy" 'c $U/ | grep -q "App Runner"'
check "session cookie is Secure + HttpOnly" 'grep -q "#HttpOnly_$OC_CONSOLE_HOST" $J'
check "load balancer page works without oc-edge" '[ "$(c -o /dev/null -w %{http_code} $U/loadbalancers)" = 200 ]'
check "status page works without oc-edge" 'c $U/status | grep -q oc-console'
for i in 1 2 3 4; do c -o /dev/null -H "X-Forwarded-For: 203.0.113.$i" -X POST -d password=wrong-$i $U/login; done
check "rotating spoofed X-Forwarded-For still rate limited" 'curl -sk --resolve $OC_CONSOLE_HOST:18443:127.0.0.1 -H "X-Forwarded-For: 198.51.100.7" -X POST --data-urlencode "password=$OC_PW" $U/login | grep -q "Too many attempts"'
check "audit records the proxy-seen address, not the spoofed one" '! sudo grep -q "203.0.113." $OC_ROOT/audit/audit.log && sudo grep -q "\"login\"" $OC_ROOT/audit/audit.log'
cp .env /tmp/oc-env-bak; sed -i "s/^OC_PROXY_NETWORK=.*/OC_PROXY_NETWORK=e2e-missing-net/" .env
IO=$(sudo ./install.sh 2>&1); IRC=$?
check "installer refuses a missing proxy network" '[ $IRC = 1 ] && grep -q "network e2e-missing-net not found" <<<"$IO" || { echo "  rc=$IRC: ${IO: -300}"; false; }'
cp /tmp/oc-env-bak .env; rm -f /tmp/oc-env-bak
docker rm -f e2e-proxy >/dev/null; rm -rf $P
echo "E2E external: $FAILS failure(s)"; [ $FAILS = 0 ]
