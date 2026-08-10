#!/usr/bin/env bash
set -Eeuo pipefail

binary=${1:?wireguide binary required}
vpn_config=${2:?VPN config required}
test_root=${3:?isolated test directory required}
uid_num=${4:-$(id -u)}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
recover="$repo_root/scripts/network_test_recover.sh"
runtime_dir="$test_root/runtime"
config_dir="$test_root/config"
data_dir="$test_root/data"
helper_data="$test_root/helper"
backup_resolv="$test_root/resolv.conf.before"
helper_pidfile="$test_root/helper.pid"
recovery_log="$test_root/recovery.log"
test_log="$test_root/test.log"
socket="$runtime_dir/wireguide-${uid_num}.sock"
split_config="$test_root/automation-split.conf"
name=automation-audit

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
awk '
  /^[[:space:]]*DNS[[:space:]]*=/ { next }
  /^[[:space:]]*AllowedIPs[[:space:]]*=/ { print "AllowedIPs = 10.255.252.1/32"; next }
  { print }
' "$vpn_config" >"$split_config"
chmod 600 "$split_config"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 5 --max-time 12 --silent --fail https://www.google.com/generate_204 >/dev/null; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  [[ -n "${keepalive_pid:-}" ]] && kill "$keepalive_pid" 2>/dev/null || true
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: live automation SSID/subnet/MAC/else matrix completed"
  else
    log "FAIL: automation matrix exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

default_if=$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
gateway=$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')
ssid=$(nmcli -t -f ACTIVE,SSID dev wifi | sed -n 's/^yes://p' | head -1)
subnet=$(ip -4 route show dev "$default_if" proto kernel scope link | awk '$1 ~ /\// {print $1; exit}')
gateway_mac=$(ip neigh show "$gateway" dev "$default_if" | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="lladdr") {print $(i+1); exit}}')
[[ -n "$ssid" && -n "$subnet" && -n "$gateway_mac" ]]

sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=4m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 4-minute emergency recovery armed"

cli import "$split_config" "$name" >>"$test_log" 2>&1
cli automation add "$name" connect "ssid:$ssid" >>"$test_log" 2>&1

sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

# The helper ties its lifetime to the GUI: with no GUI it self-exits after
# the 60s startup grace, and ctl invocations are Transient so they neither
# cancel nor re-arm it. This test has long windows where automation rules
# have disconnected every tunnel, so hold ONE non-transient control
# connection (a GUI stand-in) for the duration — otherwise the helper
# vanishes mid-matrix exactly as the lifetime design intends.
python3 - "$socket" <<'PYKEEPALIVE' &
import json, socket, struct, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "Helper.Ping"}).encode()
s.sendall(struct.pack(">I", len(body)) + body)
hdr = s.recv(4)
if len(hdr) == 4:
    n = struct.unpack(">I", hdr)[0]
    while n > 0:
        chunk = s.recv(min(n, 65536))
        if not chunk:
            break
        n -= len(chunk)
while True:
    time.sleep(30)
PYKEEPALIVE
keepalive_pid=$!

is_active() {
  cli status --json 2>>"$test_log" | python3 -c 'import json,sys; x=json.load(sys.stdin); raise SystemExit(0 if any(v["tunnel_name"]=="automation-audit" for v in x) else 1)'
}
wait_active() {
  local want=$1 timeout_secs=$2
  for ((i=0; i<timeout_secs*2; i++)); do
    if [[ "$want" == yes ]] && is_active; then return 0; fi
    if [[ "$want" == no ]] && ! is_active; then return 0; fi
    sleep 0.5
  done
  return 1
}

# Startup re-evaluation should apply the current SSID rule headlessly.
wait_active yes 15
cli automation | tee -a "$test_log" | grep -q 'decision=connect'
ip -4 route show | grep -Eq '^10\.255\.252\.1(/32)? dev wg-'
http_ok
log "SSID startup auto-connect passed"

# Rule edits are picked up by the Linux 30-second physical-network poll.
cli automation rm "$name" 1 >>"$test_log" 2>&1
cli automation add "$name" disconnect "subnet:$subnet" >>"$test_log" 2>&1
cli automation | tee -a "$test_log" | grep -q 'decision=disconnect'
wait_active no 40
! ip -4 route show | grep -q '^10.255.252.1'
http_ok
log "subnet rule live auto-disconnect passed"

cli automation rm "$name" 1 >>"$test_log" 2>&1
cli automation add "$name" connect "mac:$gateway_mac" >>"$test_log" 2>&1
cli automation | tee -a "$test_log" | grep -q 'decision=connect'
wait_active yes 40
ip -4 route show | grep -Eq '^10\.255\.252\.1(/32)? dev wg-'
http_ok
log "gateway-MAC rule live auto-connect passed"

cli automation rm "$name" 1 >>"$test_log" 2>&1
cli automation add "$name" disconnect else >>"$test_log" 2>&1
cli automation | tee -a "$test_log" | grep -q 'decision=disconnect'
wait_active no 40
! ip -4 route show | grep -q '^10.255.252.1'
http_ok
log "else rule live auto-disconnect passed"

cli automation rm "$name" 1 >>"$test_log" 2>&1
cli delete "$name" >>"$test_log" 2>&1
cmp -s "$backup_resolv" /etc/resolv.conf
