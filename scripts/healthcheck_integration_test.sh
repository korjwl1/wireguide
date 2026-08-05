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
split_config="$test_root/health-split.conf"
name=health-audit
nft_table=wireguide_health_test

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
awk '
  /^[[:space:]]*DNS[[:space:]]*=/ { next }
  /^[[:space:]]*AllowedIPs[[:space:]]*=/ { print "AllowedIPs = 10.255.251.1/32"; next }
  { print }
' "$vpn_config" >"$split_config"
chmod 600 "$split_config"
endpoint=$(awk -F= '/^[[:space:]]*Endpoint[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$vpn_config")
endpoint_ip=${endpoint%:*}
endpoint_port=${endpoint##*:}
[[ "$endpoint_ip" =~ ^[0-9.]+$ && "$endpoint_port" =~ ^[0-9]+$ ]]
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 5 --max-time 12 --silent --fail https://www.google.com/generate_204 >/dev/null; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  sudo -n nft delete table inet "$nft_table" 2>/dev/null || true
  cli set healthcheck off >>"$test_log" 2>&1 || true
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: stale-handshake healthcheck reconnect completed"
  else
    log "FAIL: healthcheck test exited rc=$rc; endpoint block removed and emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=6m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 6-minute emergency recovery armed"

cli import "$split_config" "$name" >>"$test_log" 2>&1
start_marker=$(date '+%Y-%m-%d %H:%M:%S')
sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

cli connect "$name" >>"$test_log" 2>&1
for _ in {1..40}; do
  status_json=$(cli status --json 2>>"$test_log")
  if python3 -c 'import json,sys; x=json.load(sys.stdin); raise SystemExit(0 if x and x[0].get("last_handshake") else 1)' <<<"$status_json"; then break; fi
  sleep 0.5
done
python3 -c 'import json,sys; x=json.load(sys.stdin); assert x and x[0].get("last_handshake")' <<<"$status_json"
ip -4 route show | grep -Eq '^10\.255\.251\.1(/32)? dev wg-'
http_ok
cli set healthcheck on >>"$test_log" 2>&1

# Block only the WireGuard peer UDP flow. This makes the split tunnel's
# handshake stale while leaving the host's ordinary DNS/HTTPS untouched.
sudo -n nft -f - <<EOF
table inet $nft_table {
  chain output {
    type filter hook output priority -10; policy accept;
    ip daddr $endpoint_ip udp dport $endpoint_port drop
  }
}
EOF
log "peer UDP blocked locally; waiting for the 180-second stale threshold"

reconnected=no
for _ in {1..52}; do
  journal_output=$(sudo -n journalctl -u wireguide-fulltest-helper.service --since "$start_marker" --no-pager)
  if grep -q 'reconnected successfully.*tunnel=health-audit' <<<"$journal_output"; then
    reconnected=yes
    break
  fi
  http_ok
  sleep 5
done
if [[ "$reconnected" != yes ]]; then
  log "FAIL: health monitor did not reconnect within 260 seconds"
  exit 1
fi
journal_output=$(sudo -n journalctl -u wireguide-fulltest-helper.service --since "$start_marker" --no-pager)
grep -q 'handshake stale.*tunnel=health-audit' <<<"$journal_output"
log "stale handshake was detected and reconnect transaction completed"

sudo -n nft delete table inet "$nft_table"
for _ in {1..100}; do
  status_json=$(cli status --json 2>>"$test_log")
  if python3 -c 'import json,sys; x=json.load(sys.stdin); raise SystemExit(0 if x and x[0].get("last_handshake") else 1)' <<<"$status_json"; then break; fi
  sleep 0.5
done
python3 -c 'import json,sys; x=json.load(sys.stdin); assert x and x[0]["state"]=="connected" and x[0].get("last_handshake")' <<<"$status_json"
ip -4 route show | grep -Eq '^10\.255\.251\.1(/32)? dev wg-'
http_ok
log "endpoint unblocked; fresh handshake and normal internet verified"

cli set healthcheck off >>"$test_log" 2>&1
cli disconnect "$name" >>"$test_log" 2>&1
! ip -4 route show | grep -q '^10.255.251.1'
http_ok
cli delete "$name" >>"$test_log" 2>&1
cmp -s "$backup_resolv" /etc/resolv.conf
