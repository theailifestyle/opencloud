#!/bin/bash
# End-to-end check against a local install (OC_TLS=internal, *.localhost).
# Usage: OC_PW=<admin password> tests/e2e.sh [repo-url] [port]
# Needs sudo (reads generated secrets) and Docker. Leaves two test apps running.
set -uo pipefail
# grep -q exits on the first match; under pipefail that SIGPIPEs curl on large pages and fails the check.
grep() { if [ "${1:-}" = -q ]; then shift; command grep "$@" >/dev/null; else command grep "$@"; fi; }
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
# Preflight: the example-app section clones from a local HTTPS git server whose test CA lives under $OC_ROOT/test-git.
[ "${OC_GIT_SSL_CAINFO:-}" = "$OC_ROOT/test-git/ca.pem" ] || { echo "e2e needs OC_GIT_SSL_CAINFO=$OC_ROOT/test-git/ca.pem in .env (set before install)"; exit 2; }
[ "${OC_WATCH_INTERVAL:-60}" -le 10 ] || echo "note: OC_WATCH_INTERVAL>10 makes the Open CloudWatch section slow; 5 is recommended for e2e"
REPO=${1:-https://github.com/traefik/whoami}; PORT=${2:-80}; APP=e2e-$RANDOM; APP2=$APP-b
J=$(mktemp); U="https://$OC_CONSOLE_HOST"; FAILS=0
c() { curl -sk -b "$J" -c "$J" --resolve "$OC_CONSOLE_HOST:443:127.0.0.1" "$@"; }
code() { c -o /dev/null -w '%{http_code}' "$@"; }
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS+1)); fi; }
ports() { local p; p=$(docker inspect "$1" --format '{{json .NetworkSettings.Ports}}') || return 0; grep -q HostPort <<<"$p"; }
gw() { docker run --rm --network oc_edge curlimages/curl -s "$@"; }
appcode() { curl -sk -o /dev/null -w '%{http_code}' --resolve "$1.$OC_APPS_DOMAIN:443:127.0.0.1" "https://$1.$OC_APPS_DOMAIN/"; }
# POST an action; if it started a job, wait for it and print its final status.
act() { local loc; loc=$(c -o /dev/null -w '%{redirect_url}' -X POST -d csrf=$T "$@"); case "$loc" in */jobs/*) wait_job "$loc";; *) echo "$loc";; esac; }
wait_job() { for _ in $(seq 1 300); do local s; s=$(c "$1" | grep -o '<b class=[a-z]*>[a-z]*</b>' | sed 's/<[^>]*>//g'); [ "$s" != running ] && [ -n "$s" ] && { echo "$s"; return; }; sleep 2; done; echo timeout; }
sec() { sudo cat "$OC_ROOT/secrets/apps/$1/$2"; }
aws() { local a=$1; shift; docker run --rm -i --network oc_edge -e AWS_ACCESS_KEY_ID="$(sec $a S3_ACCESS_KEY_ID)" -e AWS_SECRET_ACCESS_KEY="$(sec $a S3_SECRET_ACCESS_KEY)" -e AWS_DEFAULT_REGION=us-east-1 amazon/aws-cli "$@"; }
R="-e RESTIC_REPOSITORY=$OC_ROOT/backups/restic -e RESTIC_PASSWORD_FILE=$OC_ROOT/secrets/platform/restic-password"

echo "== console + auth"
check "wrong password rejected" '[ "$(code -X POST -d password=wrong $U/login)" = 401 ]'
c -o /dev/null -X POST --data-urlencode "password=$OC_PW" $U/login

echo "== first sign-in: choose your own password"
AUTH=$OC_ROOT/secrets/console
check "installer set the must-change flag" 'sudo test -e $AUTH/must-change-password'
check "hash + flag owned by the console user, 600, dir 700" '[ "$(sudo stat -c "%u %a" $AUTH $AUTH/admin-password.scrypt $AUTH/must-change-password | xargs)" = "10001 700 10001 600 10001 600" ]'
check "home redirects to the change form while flagged" '[ "$(c -o /dev/null -w "%{http_code} %{redirect_url}" $U/)" = "303 $U/account/password" ]'
check "other pages redirect too" '[ "$(c -o /dev/null -w "%{redirect_url}" $U/apps)" = "$U/account/password" ] && [ "$(c -o /dev/null -w "%{redirect_url}" $U/status)" = "$U/account/password" ]'
PT=$(c $U/account/password | grep -o 'name=csrf value="[^"]*"' | head -1 | cut -d'"' -f2)
check "change form shown with CSRF token" '[ -n "$PT" ] && c $U/account/password | grep -q "Choose your password"'
check "actions refused while flagged" '[ "$(c -o /dev/null -w "%{redirect_url}" -X POST -d csrf=$PT -d name=x -d repo=y $U/apps)" = "$U/account/password" ]'
NEWPW="e2e memorable $RANDOM pass"
pwchange() { c -o /dev/null -w '%{http_code}' -X POST "$@" $U/account/password; }
check "change without CSRF rejected" '[ "$(pwchange --data-urlencode "current=$OC_PW" --data-urlencode "new=$NEWPW" --data-urlencode "confirm=$NEWPW")" = 403 ]'
check "short new password rejected" '[ "$(pwchange -d csrf=$PT --data-urlencode "current=$OC_PW" -d new=short1 -d confirm=short1)" = 400 ]'
check "mismatched new passwords rejected" '[ "$(pwchange -d csrf=$PT --data-urlencode "current=$OC_PW" --data-urlencode "new=$NEWPW" --data-urlencode "confirm=${NEWPW}x")" = 400 ]'
check "wrong current password rejected" '[ "$(pwchange -d csrf=$PT -d current=wrong-current --data-urlencode "new=$NEWPW" --data-urlencode "confirm=$NEWPW")" = 400 ]'
check "same as current rejected" '[ "$(pwchange -d csrf=$PT --data-urlencode "current=$OC_PW" --data-urlencode "new=$OC_PW" --data-urlencode "confirm=$OC_PW")" = 400 ]'
check "flag still set after rejected attempts" 'sudo test -e $AUTH/must-change-password'
OLDJ=$(mktemp); cp "$J" "$OLDJ"
check "valid change accepted" '[ "$(pwchange -d csrf=$PT --data-urlencode "current=$OC_PW" --data-urlencode "new=$NEWPW" --data-urlencode "confirm=$NEWPW")" = 303 ]'
check "flag cleared, hash still 600 and console-owned" '! sudo test -e $AUTH/must-change-password && [ "$(sudo stat -c "%u %a" $AUTH/admin-password.scrypt)" = "10001 600" ]'
check "session rotated: old cookie signed out" 'curl -sk -b "$OLDJ" --resolve "$OC_CONSOLE_HOST:443:127.0.0.1" $U/ | grep -q "Admin password"'
check "new session reaches home" 'c $U/ | grep -q "App Runner"'
check "audit has the change, never the value" 'sudo grep -q "\"password-change\"" $OC_ROOT/audit/audit.log && ! sudo grep -qF "$NEWPW" $OC_ROOT/audit/audit.log'
check "old password no longer works" '[ "$(curl -sk -o /dev/null -w %{http_code} --resolve "$OC_CONSOLE_HOST:443:127.0.0.1" -X POST --data-urlencode "password=$OC_PW" $U/login)" = 401 ]'
: > "$J"; c -o /dev/null -X POST --data-urlencode "password=$NEWPW" $U/login
check "new password works, no redirect" '[ "$(c -o /dev/null -w %{http_code} $U/)" = 200 ]'
check "normal Change password link present" 'c $U/ | grep -q "href=\"/account/password\""'
check "later change form has no first-login notice" 'c $U/account/password | grep -q "<h1>Change password"'
OC_PW=$NEWPW; rm -f "$OLDJ"
check "login + console home" 'c $U/ | grep -q "App Runner"'
check "POST without CSRF rejected" '[ "$(code -X POST -d name=x -d repo=y $U/apps)" = 403 ]'
T=$(c $U/apps | grep -o 'name=csrf value="[^"]*"' | head -1 | cut -d'"' -f2)
check "bad repo URL refused" 'c -L -d csrf=$T -d name=badrepo --data-urlencode repo=file:///etc $U/apps | grep -q "public https Git URL"'
check "reserved app name refused" 'c -L -d csrf=$T -d name=s3 --data-urlencode repo=$REPO $U/apps | grep -q "invalid app name"'

echo "== async App Runner"
S=$(act -d visibility=external -d name=$APP --data-urlencode repo=$REPO -d port=$PORT $U/apps)
check "deploy job succeeded ($APP from $REPO)" '[ "$S" = succeeded ]'
check "job listed on Deployments page" 'c $U/jobs | grep -q "$APP"'
check "app served via Caddy TLS" '[ "$(appcode $APP)" = 200 ]'
S2=$(act -d visibility=external -d name=$APP2 --data-urlencode repo=$REPO -d port=$PORT $U/apps)
check "second app deployed" '[ "$S2" = succeeded ]'
FIRST=$(c -o /dev/null -w '%{redirect_url}' -X POST -d csrf=$T $U/apps/$APP/redeploy)
SECOND=$(c -L -d csrf=$T $U/apps/$APP/redeploy | grep -o 'class="flash[^<]*')
check "concurrent job for same app refused" 'grep -q "already running" <<<"$SECOND" || { echo "  first=$FIRST second=$SECOND"; false; }'
sleep 1; check "redeploy job finished" '[ "$(wait_job "$U/jobs/$(c $U/jobs | grep -o "/jobs/[0-9a-f]*" | head -1 | cut -d/ -f3)")" = succeeded ]'
check "rollback job succeeded" '[ "$(act $U/apps/$APP/rollback)" = succeeded ]'
check "redeploy + rollback recorded" 'c $U/apps/$APP | grep -q ">rollback<"'
check "app still serving after rollback" '[ "$(appcode $APP)" = 200 ]'

echo "== Open ELB (load balancer routes)"
L=$(c $U/loadbalancers)
check "route listed with TLS issued and healthy" 'grep -q "$APP.$OC_APPS_DOMAIN" <<<"$L" && grep -q ">issued<" <<<"$L" && grep -q "class=ok>healthy" <<<"$L"'
act -d domains=shop-$APP.localhost -d redirect=on -d health_path=/health -d health_interval=5 -d canary_weight=0 $U/apps/$APP/route >/dev/null
check "custom domain serves over TLS" '[ "$(curl -sk -o /dev/null -w %{http_code} --resolve shop-$APP.localhost:443:127.0.0.1 https://shop-$APP.localhost/)" = 200 ]'
check "HTTP redirects to HTTPS" '[ "$(curl -s -o /dev/null -w %{http_code} --resolve $APP.$OC_APPS_DOMAIN:80:127.0.0.1 http://$APP.$OC_APPS_DOMAIN/)" = 308 ]'
check "health check rendered into Caddy config" 'sudo grep -q "health_uri /health" $OC_ROOT/caddy/sites/$APP.caddy'
act -d domains=shop-$APP.localhost -d health_path=/health -d health_interval=5 -d canary_weight=0 $U/apps/$APP/route >/dev/null
check "redirect off: HTTP served directly" '[ "$(curl -s -o /dev/null -w %{http_code} --resolve $APP.$OC_APPS_DOMAIN:80:127.0.0.1 http://$APP.$OC_APPS_DOMAIN/)" = 200 ]'
check "invalid domain refused" 'c -L -d csrf=$T -d "domains=bad_domain!" $U/apps/$APP/route | grep -q "invalid or already used domain"'
check "console hostname can't be taken" 'c -L -d csrf=$T -d domains=$OC_CONSOLE_HOST $U/apps/$APP/route | grep -q "invalid or already used domain"'
sudo cp tests/forge_route.py $OC_ROOT/forge_route.py
BEFORE=$(sudo sha256sum $OC_ROOT/caddy/sites/$APP.caddy)
FORGE=$(docker exec oc-agent python3 $OC_ROOT/forge_route.py $APP)
check "config Caddy rejects is rolled back (file unchanged, app serving)" 'grep -q "rolled back" <<<"$FORGE" && [ "$(sudo sha256sum $OC_ROOT/caddy/sites/$APP.caddy)" = "$BEFORE" ] && [ "$(appcode $APP)" = 200 ]'
sudo rm -f $OC_ROOT/forge_route.py
act -d domains=shop-$APP.localhost -d redirect=on -d canary_weight=50 $U/apps/$APP/route >/dev/null
check "canary: previous release container running" '[ "$(docker inspect -f {{.State.Running}} oc-app-$APP-prev-1 2>/dev/null)" = true ]'
split() { for i in $(seq 30); do curl -sk --resolve $APP.$OC_APPS_DOMAIN:443:127.0.0.1 https://$APP.$OC_APPS_DOMAIN/ | grep ^Hostname; done | sort -u | wc -l; }
for i in $(seq 10); do [ "$(split)" = 2 ] && break; sleep 2; done
check "canary: traffic split across two versions" '[ "$(for i in $(seq 30); do curl -sk --resolve $APP.$OC_APPS_DOMAIN:443:127.0.0.1 https://$APP.$OC_APPS_DOMAIN/ | grep ^Hostname; done | sort -u | wc -l)" = 2 ]'
act -d domains=shop-$APP.localhost -d redirect=on -d canary_weight=0 $U/apps/$APP/route >/dev/null
check "canary off: previous container removed" '! docker inspect oc-app-$APP-prev-1 >/dev/null 2>&1'
check "route changes audit-logged" 'sudo grep -q "domains=shop-$APP.localhost" $OC_ROOT/audit/audit.log'
check "rate limiting documented as not in stock Caddy" 'c $U/loadbalancers | grep -q "Per-route rate limiting needs a Caddy plugin"'

echo "== secrets, Postgres"
act -d key=API_TOKEN -d value=hunter2 $U/apps/$APP/secrets >/dev/null
check "secret mounted at /run/secrets" 'docker inspect oc-app-$APP-web-1 --format "{{range .Mounts}}{{.Destination}} {{end}}" | grep -q /run/secrets/API_TOKEN'
check "secret value never shown in console" '! c $U/apps/$APP | grep -q hunter2'
act $U/apps/$APP/db >/dev/null
check "managed Postgres created and writable" 'docker exec oc-app-$APP-db-1 psql -U app -d app -qc "create table t(x int); insert into t values (42)" >/dev/null'
check "app got DATABASE_URL secret" 'c $U/apps/$APP | grep -q "<code>DATABASE_URL</code>"'
check "database publishes no ports" 'docker inspect oc-app-$APP-db-1 >/dev/null && ! ports oc-app-$APP-db-1'
check "database not on edge network" 'docker inspect oc-app-$APP-db-1 >/dev/null && ! docker inspect oc-app-$APP-db-1 --format "{{json .NetworkSettings.Networks}}" | grep -q oc_edge'

echo "== Open Bedrock (model gateway)"
act $U/apps/$APP/ai >/dev/null
K=$(sec $APP LLM_GATEWAY_KEY)
PROMPT="private-prompt-$APP"
chat() { gw -H "Authorization: Bearer $1" -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}]}" http://llm-gateway:8000/v1/chat/completions; }
chatcode() { gw -o /dev/null -w %{http_code} -H "Authorization: Bearer $1" -d "{\"model\":\"$2\",\"messages\":[]}" http://llm-gateway:8000/v1/chat/completions; }
check "unknown endpoint name returns 404" '[ "$(chatcode $K chat-fast)" = 404 ]'
act -d name=chat-fast -d model=vendor/model-x -d apps=$APP -d rpm=3 $U/gateway/endpoints >/dev/null
check "endpoint listed" 'c $U/models | grep -q "vendor/model-x"'
check "stub mode answers (no provider key)" 'chat $K chat-fast | grep -q "\[stub\] $PROMPT"'
check "gateway rejects bad app key" '[ "$(chatcode nope chat-fast)" = 401 ]'
check "invalid endpoint name refused" 'c -L -d csrf=$T -d "name=Bad Name" -d model=x $U/gateway/endpoints | grep -q "endpoint names"'
docker rm -f oc-mock-llm >/dev/null 2>&1
docker run -d --name oc-mock-llm --network oc_edge -e MOCK_KEY=mock-test-key -v "$PWD/tests/mock_openai.py:/m.py:ro" python:3.12-slim python /m.py >/dev/null
sleep 2
act --data-urlencode upstream_url=http://oc-mock-llm:9000/v1/chat/completions -d key=mock-test-key $U/gateway/provider >/dev/null
check "provider mode shown, key never displayed" 'G=$(c $U/models); grep -q "<b class=ok>provider</b>" <<<"$G" && ! grep -q mock-test-key <<<"$G"'
RESP=$(chat $K chat-fast)
check "provider path: endpoint mapped to provider model id, key sent" 'grep -q "mock reply from vendor/model-x" <<<"$RESP" || { echo "  $RESP"; false; }'
check "app sees endpoint name, not provider id" 'grep -q "\"model\": \"chat-fast\"" <<<"$RESP"'
chat $K chat-fast >/dev/null
check "per-endpoint/app rate limit (rpm=3) returns 429" '[ "$(chatcode $K chat-fast)" = 429 ]'
check "usage counters: 3 requests, 1 rejected, 14/10 tokens" 'c $U/models | grep -q "<td>$APP</td><td>3</td><td>1</td><td>14</td><td>10</td>"'
act $U/apps/$APP2/ai >/dev/null
check "endpoint not enabled for other app returns 404" '[ "$(chatcode $(sec $APP2 LLM_GATEWAY_KEY) chat-fast)" = 404 ]'
check "prompts never logged by gateway" '! docker logs oc-llm-gateway 2>&1 | grep -q "$PROMPT"'
check "provider key and prompts never in audit log" '! sudo grep -qE "mock-test-key|$PROMPT" $OC_ROOT/audit/audit.log && sudo grep -q "key=changed" $OC_ROOT/audit/audit.log'
check "provider key file is 0400 gateway-only" '[ "$(sudo stat -c "%u %a" $OC_ROOT/secrets/platform/llm-upstream-key)" = "10002 400" ]'

echo "== object storage (S3 API)"
B=$APP-files; B2=$APP2-files
act -d bucket=$B $U/apps/$APP/buckets >/dev/null
act -d bucket=$B2 $U/apps/$APP2/buckets >/dev/null
check "buckets listed" 'c $U/storage | grep -q "$B" && c $U/storage | grep -q "$B2"'
check "app has S3 key secrets" 'c $U/apps/$APP | grep -q "<code>S3_SECRET_ACCESS_KEY</code>"'
check "secret key not shown in console" '! c $U/apps/$APP | grep -qF "$(sec $APP S3_SECRET_ACCESS_KEY)"'
echo "hello-object" | aws $APP s3 cp - s3://$B/hello.txt --endpoint-url http://storage:8333 >/dev/null
check "S3 put + get (aws CLI)" '[ "$(aws $APP s3 cp s3://$B/hello.txt - --endpoint-url http://storage:8333)" = hello-object ]'
check "app key denied on another app bucket" '! echo x | aws $APP s3 cp - s3://$B2/x.txt --endpoint-url http://storage:8333 >/dev/null 2>&1'
URL=$(aws $APP s3 presign s3://$B/hello.txt --expires-in 300 --endpoint-url https://$OC_S3_HOST)
check "presigned URL works through Caddy TLS" '[ "$(curl -sk --resolve $OC_S3_HOST:443:127.0.0.1 "$URL")" = hello-object ]'
check "tampered presigned URL rejected" '[ "$(curl -sk -o /dev/null -w %{http_code} --resolve $OC_S3_HOST:443:127.0.0.1 "${URL/hello.txt/other.txt}")" = 403 ]'
check "anonymous S3 read rejected" '[ "$(curl -sk -o /dev/null -w %{http_code} --resolve $OC_S3_HOST:443:127.0.0.1 https://$OC_S3_HOST/$B/hello.txt)" = 403 ]'
check "storage filer/master not reachable from apps" '! gw -m 3 http://storage:8888/ && ! gw -m 3 http://storage:9333/'

echo "== per-app limits"
act -d memory_mb=256 -d cpus=0.5 $U/apps/$APP/limits >/dev/null
check "memory/CPU limits applied (256 MB, 0.5 CPU)" '[ "$(docker inspect oc-app-$APP-web-1 --format "{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}")" = "268435456 500000000" ]'
check "invalid limits refused" 'c -L -d csrf=$T -d memory_mb=1 -d cpus=0.5 $U/apps/$APP/limits | grep -q "memory 64-65536 MB"'
check "app still serving after limit change" '[ "$(appcode $APP)" = 200 ]'

echo "== secret file permissions"
check "app secrets are 0400" '[ "$(sudo stat -c %a $OC_ROOT/secrets/apps/$APP/API_TOKEN)" = 400 ]'
check "DB password owned by postgres uid, 0400" '[ "$(sudo stat -c "%u %a" $OC_ROOT/secrets/db/$APP)" = "70 400" ]'
check "gateway reads its client key" 'docker exec oc-llm-gateway cat /run/clients/$APP >/dev/null'
check "other uid in gateway can't read client key" '! docker exec -u 12345 oc-llm-gateway cat /run/clients/$APP >/dev/null 2>&1'
check "other uid in gateway can't read upstream key" '! docker exec -u 12345 oc-llm-gateway cat /run/secrets/upstream_key >/dev/null 2>&1'
check "console reads its agent token" 'docker exec oc-console cat /run/oc/agent-token >/dev/null'
check "other uid in console can't read agent token or hash" '! docker exec -u 12345 oc-console cat /run/oc/agent-token >/dev/null 2>&1 && ! docker exec -u 12345 oc-console cat /run/oc/auth/admin-password.scrypt >/dev/null 2>&1'
check "other uid in database can't read DB password" '! docker exec -u 12345 oc-app-$APP-db-1 cat /run/secrets/DB_PASSWORD >/dev/null 2>&1'
check "console has no app/DB/S3 secrets mounted" '! docker inspect oc-console --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -qE "secrets/(apps|db|storage|gateway-clients)"'

echo "== /data for non-root images"
check "uid and named-user images get writable /data, recursively (nested root-owned files handed over)" 'docker exec -i oc-agent sh -s <<SH
set -e
printf "FROM busybox\nUSER 1234:1234\n" | docker build -q -t oc-app-ownera:1 - >/dev/null
printf "FROM busybox\nRUN adduser -D -u 2345 appuser\nUSER appuser\n" | docker build -q -t oc-app-ownerb:1 - >/dev/null
for n in ownera ownerb; do mkdir -p $OC_ROOT/data/\$n/sub/deeper; echo old > $OC_ROOT/data/\$n/sub/deeper/old.txt; cd /opt/agent && python3 -c "import agent;print(agent.fix_data_owner({\"name\":\"\$n\",\"image_tag\":\"1\"}))"; docker run --rm --network none -v $OC_ROOT/data/\$n:/data oc-app-\$n:1 sh -c "echo ok > /data/f && echo ok >> /data/sub/deeper/old.txt && mkdir /data/sub/deeper/new"; [ -z "\$(find $OC_ROOT/data/\$n -user 0)" ]; done
rm -rf $OC_ROOT/data/ownera $OC_ROOT/data/ownerb; docker rmi -f oc-app-ownera:1 oc-app-ownerb:1 >/dev/null
SH'

echo "== backups + restore"
STORAGE_STARTED=$(docker inspect -f {{.State.StartedAt}} oc-storage)
sudo sh -c "echo restore-me > $OC_ROOT/data/$APP/probe.txt"
# Best-effort S3 backup: storage keeps running and keeps taking writes during the backup.
( for i in $(seq 1 40); do echo "w$i" | aws $APP s3 cp - s3://$B/during/$i.txt --endpoint-url http://storage:8333 >/dev/null 2>&1; done ) &
WRITER=$!
sleep 2
act $U/backups >/dev/null
check "storage stayed running during backup" '[ "$(docker inspect -f {{.State.Running}} oc-storage)" = true ] && [ "$(docker inspect -f {{.State.StartedAt}} oc-storage)" = "$STORAGE_STARTED" ]'
wait $WRITER
check "restic snapshot listed" 'c $U/backups | grep -q "<td>[0-9a-f]\{8\}</td>"'
docker exec oc-app-$APP-db-1 psql -U app -d app -qc "drop table t"; sudo rm $OC_ROOT/data/$APP/probe.txt
aws $APP s3 rm s3://$B/hello.txt --endpoint-url http://storage:8333 >/dev/null
check "object deleted before restore" '! aws $APP s3 cp s3://$B/hello.txt - --endpoint-url http://storage:8333 >/dev/null 2>&1'
docker exec $R oc-agent sh -c "rm -rf /tmp/rs && restic restore latest --target /tmp/rs >/dev/null"
check "app /data file restored" '[ "$(docker exec oc-agent cat /tmp/rs$OC_ROOT/data/$APP/probe.txt)" = restore-me ]'
docker rm -f oc-restore-pg >/dev/null 2>&1; docker run -d --name oc-restore-pg --network none -e POSTGRES_PASSWORD=restore postgres:17-alpine >/dev/null
for _ in $(seq 60); do docker exec oc-restore-pg pg_isready -U postgres -q 2>/dev/null && break; sleep 1; done; sleep 2
docker exec oc-agent cat /tmp/rs$OC_ROOT/backups/postgres/oc-app-$APP-db-1.sql | docker exec -i oc-restore-pg psql -q -U postgres >/dev/null 2>&1
check "database dump restored into fresh Postgres (row 42)" '[ "$(docker exec oc-restore-pg psql -U postgres -d app -tAc "select x from t")" = 42 ]'
docker stop oc-storage >/dev/null
docker exec oc-agent sh -c "rm -rf $OC_ROOT/storage/* && cp -a /tmp/rs$OC_ROOT/storage/. $OC_ROOT/storage/"
docker start oc-storage >/dev/null
for _ in $(seq 60); do [ "$(docker inspect -f {{.State.Health.Status}} oc-storage)" = healthy ] && break; sleep 2; done
check "S3 object restored from backup (storage stopped, files restored, restarted)" '[ "$(aws $APP s3 cp s3://$B/hello.txt - --endpoint-url http://storage:8333)" = hello-object ]'
check "storage healthy after restoring a backup taken while running" '[ "$(docker inspect -f {{.State.Health.Status}} oc-storage)" = healthy ]'
check "objects written during the backup are readable or cleanly absent (no corruption)" 'ok=1; for i in $(seq 1 40); do v=$(aws $APP s3 cp s3://$B/during/$i.txt - --endpoint-url http://storage:8333 2>/dev/null) || continue; [ "$v" = "w$i" ] || ok=0; done; [ $ok = 1 ]'
check "presigned URL works again after restore" '[ "$(curl -sk --resolve $OC_S3_HOST:443:127.0.0.1 "$(aws $APP s3 presign s3://$B/hello.txt --endpoint-url https://$OC_S3_HOST)")" = hello-object ]'
docker rm -f oc-restore-pg >/dev/null; docker exec oc-agent rm -rf /tmp/rs

echo "== example apps (FastAPI, Express) + App Map"
GR=$OC_ROOT/test-git; sudo mkdir -p $GR; sudo chmod 755 $GR
if [ ! -f $GR/ca.pem ]; then
  sudo openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=oc-test-ca" -keyout $GR/ca.key -out $GR/ca.pem 2>/dev/null
  sudo openssl req -newkey rsa:2048 -nodes -subj "/CN=oc-test-git" -keyout $GR/srv.key -out $GR/srv.csr 2>/dev/null
  printf "subjectAltName=DNS:oc-test-git\n" | sudo tee $GR/ext.cnf >/dev/null
  sudo openssl x509 -req -in $GR/srv.csr -CA $GR/ca.pem -CAkey $GR/ca.key -CAcreateserial -days 2 -extfile $GR/ext.cnf -out $GR/srv.pem 2>/dev/null
fi
for ex in fastapi-app express-app cloudwatch-consumer; do
  W=$(mktemp -d); cp -r examples/$ex/. $W/; (cd $W && git init -q && git add -A && git -c user.name=test -c user.email=test@example.com commit -qm example)
  sudo rm -rf $GR/$ex.git; sudo git clone -q --bare $W $GR/$ex.git; sudo git -C $GR/$ex.git update-server-info; rm -rf $W
done
sudo chmod -R a+rX $GR
docker rm -f oc-test-git >/dev/null 2>&1
docker run -d --name oc-test-git --network oc_agent_egress -v $GR:/git:ro -v "$PWD/tests/git_server.py:/s.py:ro" python:3.12-slim sh -c "apt-get update -qq >/dev/null && apt-get install -yqq git >/dev/null 2>&1 && git config --global --add safe.directory \\* && python /s.py /git /git/srv.pem /git/srv.key" >/dev/null
for i in $(seq 60); do docker logs oc-test-git 2>&1 | grep -q . ; docker exec oc-test-git sh -c "command -v git && python -c \"import socket;socket.create_connection(('127.0.0.1',443))\"" >/dev/null 2>&1 && break; sleep 2; done
PY=py-$RANDOM; JS=js-$RANDOM
for pair in "$PY fastapi-app 8000" "$JS express-app 3000"; do
  read -r EN EX EP <<<"$pair"
  check "example $EX deployed" '[ "$(act -d visibility=external -d name=$EN --data-urlencode repo=https://oc-test-git/$EX.git -d port=$EP $U/apps)" = succeeded ]'
  act $U/apps/$EN/db >/dev/null; act -d bucket=$EN-files $U/apps/$EN/buckets >/dev/null
  act -d key=S3_BUCKET -d value=$EN-files $U/apps/$EN/secrets >/dev/null; act $U/apps/$EN/ai >/dev/null
done
act -d name=chat-fast -d model=vendor/model-x -d "apps=$APP $PY $JS" -d rpm=30 $U/gateway/endpoints >/dev/null
for X in $PY $JS; do
  D=$(curl -sk --resolve $X.$OC_APPS_DOMAIN:443:127.0.0.1 https://$X.$OC_APPS_DOMAIN/demo)
  check "$X /demo: Postgres, bucket, Open Bedrock and /data all work" 'grep -q "\"db\": *true" <<<"$D" && grep -q "\"bucket\": *true" <<<"$D" && grep -q "mock reply from vendor/model-x" <<<"$D" && grep -q "\"data_visits\": *1" <<<"$D" || { echo "  $D"; false; }'
  check "$X /health 200" '[ "$(curl -sk -o /dev/null -w %{http_code} --resolve $X.$OC_APPS_DOMAIN:443:127.0.0.1 https://$X.$OC_APPS_DOMAIN/health)" = 200 ]'
done
M=$(c $U/apps/$PY)
check "App Map shows route, service, Postgres, bucket, endpoint" 'for w in "App Map" "Open ELB route" "Service (web)" Postgres "$PY-files" chat-fast; do grep -q "$w" <<<"$M" || exit 1; done'
act -d spec_path=/openapi.json $U/apps/$PY/api-discover >/dev/null
M=$(c $U/apps/$PY)
check "endpoints discovered from FastAPI OpenAPI" 'grep -q "<code>/items</code>" <<<"$M" && grep -q "<code>POST</code>" <<<"$M" && grep -q "<code>/demo</code>" <<<"$M"'
act -d path=/health -d enabled=1 $U/apps/$PY/api-check >/dev/null
check "health check probed: 200 with latency and time" 'c $U/apps/$PY | grep -q "<span class=ok>200</span> · [0-9]* ms · 20"'
act -d method=POST -d path=/danger -d summary=x $U/apps/$PY/api-endpoint >/dev/null
check "non-GET endpoint can't be a health check" 'c -L -d csrf=$T -d path=/danger -d enabled=1 $U/apps/$PY/api-check | grep -q "only listed GET endpoints"'
act -d method=GET -d path=/x --data-urlencode "summary=<script>alert(1)</script><img src=x onerror=alert(2)>" $U/apps/$PY/api-endpoint >/dev/null
M=$(c $U/apps/$PY)
check "hostile endpoint text is escaped (no raw script/img)" 'grep -q "&lt;script&gt;alert(1)&lt;/script&gt;" <<<"$M" && ! grep -q "<script>alert" <<<"$M" && ! grep -q "<img src=x" <<<"$M"'
check "spec discovery fails cleanly for app without spec" 'c -L -d csrf=$T -d spec_path=/openapi.json $U/apps/$JS/api-discover | grep -q "could not fetch the spec"'
check "guide page linked and lists the real secret names" 'c $U/apps | grep -q "href=\"/guide\"" && G=$(c $U/guide) && for w in DATABASE_URL S3_ENDPOINT S3_PUBLIC_ENDPOINT S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY LLM_GATEWAY_URL LLM_GATEWAY_KEY CLOUDWATCH_URL CLOUDWATCH_KEY; do grep -q "$w" <<<"$G" || exit 1; done'

echo "== Open CloudWatch (metrics, logs, alarms, email, event feed)"
retry() { local n=$1; shift; for _ in $(seq 1 "$n"); do "$@" && return 0; sleep 2; done; return 1; }
page_has() { c "$U$1" | grep -q -F -- "$2"; }
rule_state() { c $U/cloudwatch | grep -o "<tr><td>$1</td><td>[^<]*</td><td><b class=[a-z]*>[A-Z]*</b>" | head -1 | grep -q ">$2<"; }
mail_has() { sudo grep -lqF -- "$1" $MAILD/mail-*.eml 2>/dev/null; }
WT() { docker exec -i oc-watch python - "$@" <<'PY'
import sys, urllib.request as u, urllib.error
m, p = sys.argv[1], sys.argv[2]
r = u.Request("http://agent:7000" + p, method=m, data=b"{}" if m == "POST" else None, headers={"Authorization": "Bearer " + open("/run/oc/watch-token").read().strip()})
try:
    print(u.urlopen(r, timeout=60).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}
check "watch: non-root, read-only, no docker socket" '[ "$(docker exec oc-watch id -u)" = 10003 ] && [ "$(docker inspect oc-watch --format "{{.HostConfig.ReadonlyRootfs}}")" = true ] && ! docker inspect oc-watch --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock'
check "watch token reads stats but can't deploy, set secrets or read app logs" '[ "$(WT GET /watch-stats)" = 200 ] && [ "$(WT POST /apps)" = 401 ] && [ "$(WT POST /apps/$PY/secrets)" = 401 ] && [ "$(WT GET /apps/$PY/logs)" = 401 ]'
check "metrics collected: CPU, memory, health latency charts per app + host disk" 'retry 45 page_has /cloudwatch "Health check latency · now" && W=$(c $U/cloudwatch) && grep -q "$PY" <<<"$W" && grep -q "<polyline" <<<"$W" && grep -q "Host disk used · now" <<<"$W"'
check "metrics stored in SQLite; retention shown" 'sudo test -s $OC_ROOT/watch/watch.db && page_has /cloudwatch "metrics kept 7 d, logs 7 d"'
docker exec oc-app-$PY-web-1 sh -c 'echo "ERROR e2e-leak-test postgresql://app:e2eSuperSecret@db/app API_KEY=e2eKeyValue Authorization: Bearer e2eBearerToken123" > /proc/1/fd/1'
check "logs searchable by app + text (uvicorn access lines)" 'retry 30 page_has "/cloudwatch/logs?app=$PY&q=GET%20/health&range=60" "GET /health"'
check "level filter finds the error line; secrets redacted in console" 'retry 30 page_has "/cloudwatch/logs?app=$PY&level=error&range=60" e2e-leak-test && L=$(c "$U/cloudwatch/logs?app=$PY&level=error&range=60") && ! grep -qE "e2eSuperSecret|e2eKeyValue|e2eBearerToken123" <<<"$L" && grep -qF "app:***@db" <<<"$L"'
check "secrets never reach the log database" '! sudo sh -c "cat $OC_ROOT/watch/watch.db*" | grep -q -a -E "e2eSuperSecret|e2eKeyValue|e2eBearerToken123"'
check "time filter excludes older lines" '! page_has "/cloudwatch/logs?app=$PY&level=error&to=2000-01-01T00:00" e2e-leak-test'
check "platform container logs ingested too" 'page_has "/cloudwatch/logs?q=running%20server&range=1440" oc-builder'
# email: local mock SMTP only
MAILD=$OC_ROOT/test-mail; sudo rm -rf $MAILD; sudo mkdir -p $MAILD; sudo chmod 777 $MAILD
docker rm -f oc-mock-smtp >/dev/null 2>&1
docker run -d --name oc-mock-smtp --network oc_edge -v $MAILD:/out -v "$PWD/tests/mock_smtp.py:/s.py:ro" python:3.12-slim python /s.py /out >/dev/null
act -d host=oc-mock-smtp -d port=25 -d tls=none -d user= -d from=alerts@example.com -d to=ops@example.com -d password=e2eSmtpPw $U/cloudwatch/smtp >/dev/null
N=$(c $U/cloudwatch/notifications)
check "SMTP saved; password write-only (never shown, 0600, owned by watch)" 'grep -q "value=\"oc-mock-smtp\"" <<<"$N" && grep -q "set (leave empty to keep)" <<<"$N" && ! grep -q e2eSmtpPw <<<"$N" && [ "$(sudo stat -c "%u %a" $OC_ROOT/watch/smtp-password)" = "10003 600" ]'
sleep 2; act $U/cloudwatch/smtp-test >/dev/null
check "send test email: delivered to the mock SMTP server" 'retry 15 mail_has "Open CloudWatch test email" && mail_has "To: ops@example.com"'
# event feed: deploy the consumer example, give it a webhook URL and a subscriber key
CWA=cw-$RANDOM
check "consumer example deployed" '[ "$(act -d visibility=external -d name=$CWA --data-urlencode repo=https://oc-test-git/cloudwatch-consumer.git -d port=8080 $U/apps)" = succeeded ]'
act -d key=WEBHOOK_URL --data-urlencode value=http://app-$CWA:8080/webhook $U/apps/$CWA/secrets >/dev/null
act -d app=$CWA $U/cloudwatch/keys >/dev/null
check "subscriber key delivered to the app as secrets, never shown" 'page_has /apps/$CWA CLOUDWATCH_KEY && page_has /apps/$CWA CLOUDWATCH_URL && ! page_has /cloudwatch/events ocw_'
KEY=$(sudo cat $OC_ROOT/secrets/apps/$CWA/CLOUDWATCH_KEY)
rc() { curl -sk --resolve $CWA.$OC_APPS_DOMAIN:443:127.0.0.1 https://$CWA.$OC_APPS_DOMAIN/received; }
subscribed() { curl -sk --resolve $CWA.$OC_APPS_DOMAIN:443:127.0.0.1 https://$CWA.$OC_APPS_DOMAIN/health | grep -q -F '"subscribed": true'; }
got() { rc | python3 -c 'import json,sys;d=json.load(sys.stdin);f=sys.argv[1];t=sys.argv[2]
ok = {"sse_alarm": any(e["topic"]=="alarms" and e["data"].get("state")=="ALARM" for e in d["sse"]),
      "hook_alarm": d["rejected"]==0 and any(e["topic"]=="alarms" for e in d["webhook"]),
      "deploy_audit": any(e["topic"]=="deploys" and e["data"].get("status")=="succeeded" for e in d["sse"]) and any(e["topic"]=="audit" for e in d["sse"])}[f]
sys.exit(not ok)' "$1" x; }
own_only() { gw -H "Authorization: Bearer $KEY" "http://cloudwatch:8100/v1/events?topics=alarms,metrics,deploys,audit&after=0" | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(not d or any(e["data"].get("app")!=sys.argv[1] for e in d))' "$CWA"; }
check "consumer app healthy and subscribed" 'retry 30 subscribed'
check "webhook subscription registered (own app URL only)" 'retry 30 page_has /cloudwatch/events "http://app-$CWA:8080/webhook"'
check "unauthenticated stream refused" '[ "$(gw -o /dev/null -w %{http_code} http://cloudwatch:8100/v1/stream)" = 401 ]'
check "app key can't use the admin API" '[ "$(gw -o /dev/null -w %{http_code} -H "Authorization: Bearer $KEY" http://cloudwatch:8100/admin/overview)" = 401 ]'
check "webhook to another host refused (no SSRF)" 'gw -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d "{\"url\":\"http://169.254.169.254/latest\",\"topics\":[\"alarms\"]}" http://cloudwatch:8100/v1/subscriptions | grep -q "your own app"'
docker rm -f oc-node-consumer >/dev/null 2>&1
docker run -d --name oc-node-consumer --network oc_edge -e CLOUDWATCH_URL=http://cloudwatch:8100 -e CLOUDWATCH_KEY="$KEY" -e EXIT_ON_TOPIC=alarms -v "$PWD/examples/cloudwatch-consumer/node:/c:ro" node:22-alpine node /c/consumer.js >/dev/null
act -d name=e2e-mem-$CWA -d kind=mem -d target=$CWA -d threshold=0 -d minutes=0 -d cooldown=0 $U/cloudwatch/rules >/dev/null
check "alarm goes to ALARM (memory over 0%)" 'retry 30 rule_state e2e-mem-$CWA ALARM'
check "alarm email sent" 'retry 15 mail_has "[ALARM] e2e-mem-$CWA"'
check "Python consumer received the alarm over SSE" 'retry 20 got sse_alarm'
check "Python consumer received a signed webhook (none rejected)" 'retry 20 got hook_alarm'
check "Node consumer received the alarm and exited" '[ "$(timeout 60 docker wait oc-node-consumer)" = 0 ] && docker logs oc-node-consumer | grep -q "\"topic\":\"alarms\""'
check "deploy and audit events reach the app's feed" 'retry 10 got deploy_audit'
check "app sees only its own events" 'own_only'
# unhealthy -> ALARM, recover -> OK + resolved email (Express app)
act -d name=e2e-down-$JS -d kind=unhealthy -d target=$JS -d minutes=0 -d cooldown=0 $U/cloudwatch/rules >/dev/null
docker stop oc-app-$JS-web-1 >/dev/null
check "stopped app: unhealthy alarm fires" 'retry 30 rule_state e2e-down-$JS ALARM'
docker start oc-app-$JS-web-1 >/dev/null
check "app back: alarm OK, resolved email, history" 'retry 30 mail_has "[RESOLVED] e2e-down-$JS" && rule_state e2e-down-$JS OK && [ "$(c $U/cloudwatch | grep -o "<td>e2e-down-$JS</td>" | wc -l)" -ge 3 ]'
check "metric threshold crossings published" 'page_has /cloudwatch/events breaching'
A=$(sudo cat $OC_ROOT/audit/audit.log)
check "config changes audited (SMTP, alarms, keys, app webhook subscription)" 'grep -q "/cloudwatch/smtp host=oc-mock-smtp" <<<"$A" && grep -q "password=changed" <<<"$A" && grep -q "/cloudwatch/rules name=e2e-mem-$CWA" <<<"$A" && grep -q "/cloudwatch/keys app=$CWA" <<<"$A" && grep -q "app:$CWA" <<<"$A"'
check "audit never contains the SMTP password or subscriber keys" '! grep -qE "e2eSmtpPw|ocw_" <<<"$A"'
docker rm -f oc-node-consumer oc-mock-smtp >/dev/null 2>&1

echo "== host sources and mounts (server folder, allowlisted networks, secret files, data folders)"
# The runner sets OC_LOCAL_SOURCES=/tmp/oc-hostsrc OC_ALLOWED_DATA_ROOTS=/tmp/oc-hostdata
# OC_ALLOWED_SECRET_PATHS=/tmp/oc-hostsec/app-token OC_ALLOWED_EXTERNAL_NETWORKS=e2e_shared before install.
if [ -n "${OC_LOCAL_SOURCES:-}" ]; then
  HA=hf-$RANDOM
  check "App Runner offers the server-folder source and host options" 'P=$(c $U/apps); grep -q "Server folder" <<<"$P" && grep -q "name=secret_mounts" <<<"$P" && grep -q e2e_shared <<<"$P"'
  refuse() { c -L -d csrf=$T -d name=$HA-x -d source=folder "$@" -d port=8000 $U/apps | grep -o 'class="flash[^<]*'; }
  check "folder outside the allowlist refused" 'refuse --data-urlencode folder=/etc | grep -q "not under an allowed root"'
  check "symlink escape refused" 'refuse --data-urlencode folder=/tmp/oc-hostsrc/escape | grep -q "not under an allowed root"'
  check "network not in the allowlist refused" 'refuse --data-urlencode folder=/tmp/oc-hostsrc/app -d networks=bridge | grep -q "OC_ALLOWED_EXTERNAL_NETWORKS"'
  check "secret file not in the allowlist refused" 'refuse --data-urlencode folder=/tmp/oc-hostsrc/app --data-urlencode "secret_mounts=/tmp/oc-hostsec/other=x" | grep -q "not under an allowed root"'
  check "data mount over /run/secrets refused" 'refuse --data-urlencode folder=/tmp/oc-hostsrc/app --data-urlencode "data_mounts=/tmp/oc-hostdata:/run/secrets/x" | grep -q "invalid container path"'
  S=$(act -d visibility=external -d name=$HA -d source=folder --data-urlencode folder=/tmp/oc-hostsrc/app -d dockerfile=docker/Dockerfile -d port=8000 \
      -d networks=e2e_shared --data-urlencode "secret_mounts=/tmp/oc-hostsec/app-token=host_token" \
      --data-urlencode "data_mounts=/tmp/oc-hostdata:/data" --data-urlencode "env=E2E_MODE=folder" $U/apps)
  check "server-folder app built by the sandbox and deployed (Dockerfile in a subfolder)" '[ "$S" = succeeded ]'
  W=oc-app-$HA-web-1
  check "joined the allowlisted network with its app alias" 'docker network inspect e2e_shared --format "{{range .Containers}}{{.Name}} {{end}}" | grep -q $W && [ "$(docker run --rm --network e2e_shared curlimages/curl -s -o /dev/null -w %{http_code} http://app-$HA:8000/health)" = 200 ]'
  check "secret file mounted read-only at /run/secrets/host_token" 'docker inspect $W --format "{{range .Mounts}}{{.Source}}={{.Destination}}:{{.RW}} {{end}}" | grep -q "/tmp/oc-hostsec/app-token=/run/secrets/host_token:false"'
  check "host data folder mounted at /data (host file visible)" 'docker exec $W ls /data | grep -q host-marker'
  check "plain environment variable set" '[ "$(docker exec $W printenv E2E_MODE)" = folder ]'
  check "no published ports" '! ports $W'
  check "source snapshot is a copy (host folder untouched, read-only in the agent)" '[ -z "$(cd /tmp/oc-hostsrc/app && find . -newer /tmp/oc-hostsrc/.stamp)" ] && ! docker exec oc-agent touch /tmp/oc-hostsrc/app/x 2>/dev/null'
  check "host data folder not chowned by Open Cloud" '[ "$(stat -c %u /tmp/oc-hostdata)" = "$(stat -c %u /tmp/oc-hostsrc/.stamp)" ]'
  check "redeploy rebuilds from the folder" '[ "$(act $U/apps/$HA/redeploy)" = succeeded ]'
  docker compose -p oc-app-$HA down >/dev/null 2>&1
else
  echo "SKIP host sources section (OC_LOCAL_SOURCES not set)"
fi

echo "== status, DNS, isolation"
check "logs view" 'c $U/apps/$APP | grep -q "<pre>"'
check "status page" 'c $U/status | grep -q oc-storage'
check "DNS page lists route" 'c $U/dns | grep -q "$APP.$OC_APPS_DOMAIN"'
for x in oc-console oc-agent oc-llm-gateway oc-storage oc-watch oc-app-$APP-web-1; do check "$x publishes no ports" 'docker inspect $x >/dev/null && ! ports $x'; done
check "builder is unprivileged, has no docker socket or host mounts" '[ "$(docker inspect oc-builder --format "{{.HostConfig.Privileged}} {{range .Mounts}}{{.Type}} {{end}}")" = "false volume " ]'
check "builder runs as non-root" '[ "$(docker exec oc-builder id -u)" != 0 ]'
check "builder not reachable from app network" '! gw -m 3 http://oc-builder:1234/'
check "app image was built by the sandbox, not the host daemon" 'docker exec oc-agent sh -c "docker buildx ls | grep -q oc-sandbox && grep -q \"sending tarball\" $OC_ROOT/apps/$APP/build.log"'
check "console has no docker socket" '! docker inspect oc-console --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock'
check "storage has no docker socket" '! docker inspect oc-storage --format "{{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock'
check "agent not reachable from edge network" '! gw -m 3 http://oc-agent:7000/status'

echo "== audit log"
A=$(c $U/audit)
check "audit chain intact" 'grep -q ">intact<" <<<"$A"'
check "audit has failed + ok logins" 'grep -q "<td>failed</td>" <<<"$A" && grep -q "<td>login</td>" <<<"$A"'
check "audit records deploy, secret name, bucket" 'grep -q "name=$APP" <<<"$A" && grep -q "key=API_TOKEN" <<<"$A" && grep -q "bucket=$B" <<<"$A"'
check "audit never contains secret values" '! sudo grep -q hunter2 $OC_ROOT/audit/audit.log'

# Observe checks use this session; the TOTP block below signs in with its own cookie jar.
if [ "${OC_OBSERVE:-0}" = 1 ]; then
  echo "== observe mode (read-only view of containers Open Cloud doesn't manage)"
  # A stand-in "platform" container: not oc-*, no compose project of ours. It must come out untouched.
  docker rm -f plat-e2e-web >/dev/null 2>&1
  docker run -d --name plat-e2e-web --label com.docker.compose.project=platform-e2e busybox sh -c 'while true; do echo "plat-e2e heartbeat"; sleep 2; done' >/dev/null
  BEFORE=$(docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' plat-e2e-web)
  O=$(c $U/observed)
  check "observed page lists foreign container, not oc-*" 'grep -q "<td>plat-e2e-web</td>" <<<"$O" && grep -q "platform-e2e" <<<"$O" && ! grep -q "<td>oc-console</td>" <<<"$O"'
  check "observed page has no action forms" '! grep -q "<form" <<<"${O#*<main>}"'
  check "platform status.json and backup marker shown read-only" 'grep -q "backup_last_success" <<<"$O" && grep -q "backup-last-success" <<<"$O" && ! grep -q e2e-not-shown <<<"$O"'
  check "status.json mount is read-only in the agent" '! docker exec oc-agent sh -c "echo x >> /run/observe/status.json" 2>/dev/null'
  AG() { docker run --rm --network oc_control curlimages/curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(sudo cat $OC_ROOT/secrets/platform/agent-token)" "$@"; }
  refused() { local a; for a in redeploy limits rollback db; do [[ "$(AG -X POST -d {} http://agent:7000/apps/plat-e2e-web/$a)" =~ ^40[04]$ ]] || return 1; done; }
  check "agent refuses actions on the foreign container" refused
  check "watch token can't read /observed directly" '[ "$(docker run --rm --network oc_control curlimages/curl -s -o /dev/null -w %{http_code} -H "Authorization: Bearer $(sudo cat $OC_ROOT/secrets/platform/watch-token)" http://agent:7000/observed)" = 401 ]'
  cw_observed() { local p; p=$(c $U/cloudwatch); [[ "$p" == *"Observed containers (read-only)"* ]] && grep -q -F "<td>plat-e2e-web<br>" <<<"${p#*Observed containers (read-only)}"; }
  check "observed container in Open CloudWatch metrics" 'retry 30 cw_observed'
  check "observed container logs in Open CloudWatch" 'retry 30 page_has "/cloudwatch/logs?q=plat-e2e%20heartbeat&range=60" "plat-e2e heartbeat"'
  check "foreign container untouched (same start, no restarts)" '[ "$(docker inspect -f "{{.State.StartedAt}} {{.RestartCount}}" plat-e2e-web)" = "$BEFORE" ]'
  docker rm -f plat-e2e-web >/dev/null
fi

echo "== TOTP"
check "setup page shows a QR code" 'c $U/account/2fa | grep -q "<svg"'
# Enable with a throwaway test secret, as the setup page would store it (no restart needed).
TS=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
sudo sh -c "umask 077; echo '{\"secret\": \"$TS\", \"last\": 0, \"recovery\": []}' > $OC_ROOT/secrets/console/totp.json; chown 10001:10001 $OC_ROOT/secrets/console/totp.json"
J2=$(mktemp); t() { curl -sk -b $J2 -c $J2 --resolve "$OC_CONSOLE_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' "$@"; }
check "login page asks for code" 'curl -sk --resolve $OC_CONSOLE_HOST:443:127.0.0.1 $U/ | grep -q "6-digit code"'
check "password without code rejected" '[ "$(t -X POST --data-urlencode "password=$OC_PW" $U/login)" = 401 ]'
CODE=$(python3 -c "import sys,time;sys.path.insert(0,'console');import console;print(console.totp('$TS',int(time.time()//30)))")
check "password + code accepted" '[ "$(t -X POST --data-urlencode "password=$OC_PW" -d code=$CODE $U/login)" = 303 ]'
check "same code can't be replayed" '[ "$(t -X POST --data-urlencode "password=$OC_PW" -d code=$CODE $U/login)" = 401 ]'
sudo ./opencloud disable-totp >/dev/null 2>&1
check "after disable-totp the password alone works" '[ "$(t -X POST --data-urlencode "password=$OC_PW" $U/login)" = 303 ]'


echo "== proxy client IP (X-Forwarded-For can't be spoofed past the login rate limit)"
for i in 1 2 3 4 5; do curl -sk -o /dev/null --resolve $OC_CONSOLE_HOST:443:127.0.0.1 -H "X-Forwarded-For: 203.0.113.$i" -X POST -d password=wrong-$i $U/login; done
check "rotating spoofed X-Forwarded-For still rate limited" 'curl -sk --resolve $OC_CONSOLE_HOST:443:127.0.0.1 -H "X-Forwarded-For: 198.51.100.7" -X POST --data-urlencode "password=$OC_PW" $U/login | grep -q "Too many attempts"'
check "audit records the proxy-seen address, not the spoofed one" '! sudo grep -q "203.0.113." $OC_ROOT/audit/audit.log'

echo "E2E for $APP: $FAILS failure(s)"; [ $FAILS = 0 ]
