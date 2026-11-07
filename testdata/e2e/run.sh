#!/bin/sh
# End-to-end test. Starts the compose stack and a throwaway sshd bound to
# localhost, scans this machine directly and over ssh, and checks that the
# planted problems are found. Needs root, Docker, OpenSSH and jq.
# Usage: sudo testdata/e2e/run.sh path/to/whatsrunning
set -eu
bin=$(realpath "$1")
cd "$(dirname "$0")"
tmp=$(mktemp -d)
chmod 700 "$tmp"
cleanup() {
	[ -f "$tmp/sshd.pid" ] && kill "$(cat "$tmp/sshd.pid")" 2>/dev/null
	docker compose -p e2e down -v -t 1 >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

docker compose -p e2e up -d --quiet-pull
echo "waiting for the worker's database connection..."
for _ in $(seq 90); do
	docker exec e2e-db-1 psql -U postgres -tAc "select count(*) from pg_stat_activity where query like 'select pg_sleep%'" 2>/dev/null | grep -q '^[1-9]' && break
	sleep 1
done

# Throwaway sshd: its own host key and authorized_keys, nothing in ~/.ssh is touched.
ssh-keygen -q -t ed25519 -N "" -f "$tmp/client_key"
ssh-keygen -q -t ed25519 -N "" -f "$tmp/host_key"
cp "$tmp/client_key.pub" "$tmp/authorized_keys"
cat > "$tmp/sshd_config" <<EOF
ListenAddress 127.0.0.1
Port 2222
HostKey $tmp/host_key
AuthorizedKeysFile $tmp/authorized_keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
PidFile $tmp/sshd.pid
EOF
echo "[127.0.0.1]:2222 $(cut -d' ' -f1,2 "$tmp/host_key.pub")" > "$tmp/known_hosts"
cat > "$tmp/ssh_config" <<EOF
Host e2e-server
  HostName 127.0.0.1
  Port 2222
  User root
  IdentityFile $tmp/client_key
  IdentitiesOnly yes
  UserKnownHostsFile $tmp/known_hosts
  StrictHostKeyChecking yes
EOF
mkdir -p "$tmp/bin" /run/sshd
# The wrapper must call the real ssh by path: "ssh" would find the wrapper itself.
printf '#!/bin/sh\nexec %s -F %s/ssh_config "$@"\n' "$(command -v ssh)" "$tmp" > "$tmp/bin/ssh"
chmod 755 "$tmp/bin/ssh"
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$tmp/sshd_config"

"$bin" -o "$tmp/local.html" -json "$tmp/local.json" >/dev/null
PATH="$tmp/bin:$PATH" "$bin" -ssh e2e-server -local -o - -json "$tmp/multi.json" >/dev/null

fail=0
check() { # description, jq filter, file
	if jq -e "$2" "$3" >/dev/null; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}
finding() { echo ".findings | any(.rule == \"$1\" and (.nodeId | endswith(\"$2\")))"; }
L="$tmp/local.json" M="$tmp/multi.json"
check "exposed database"               "$(finding exposed-datastore ctr:e2e-db-1)" "$L"
check "web bypasses nginx"             "$(finding proxy-bypass domain:shop.test)" "$L"
check "shop.test on plain HTTP"        "$(finding plain-http-site domain:shop.test)" "$L"
check "dead /legacy/ route"            "$(finding dead-route domain:shop.test)" "$L"
check "redirect-only site not flagged" "$(finding plain-http-site domain:secure.test) | not" "$L"
check "nginx route shop.test -> web"   '.graph.edges | any(.kind == "routes" and .from == "domain:shop.test" and .to == "ctr:e2e-web-1")' "$L"
check "observed worker -> db link"     '.graph.edges | any(.kind == "talks-to" and .label == "observed" and .from == "ctr:e2e-worker-1" and .to == "ctr:e2e-db-1")' "$L"
check "ssh scan adds a second server"  '.graph.servers | length == 2' "$M"
check "ssh server found the database"  "$(finding exposed-datastore e2e-server::ctr:e2e-db-1)" "$M"
if ls -A "$(getent passwd root | cut -d: -f6)" | grep -q '^\.whatsrunning\.'; then echo "FAIL  temporary binary left on the server"; fail=1; else echo "ok    temporary binary removed"; fi
if grep -q e2e-secret "$L" "$M" "$tmp/local.html"; then echo "FAIL  a secret leaked into a report"; fail=1; else echo "ok    no secrets in reports"; fi
exit $fail
