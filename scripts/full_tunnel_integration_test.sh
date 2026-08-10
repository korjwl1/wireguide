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
name=full-tunnel-audit

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 8 --max-time 20 --silent --fail "$1" >/dev/null; }
public_ip() { curl --connect-timeout 8 --max-time 20 --silent --fail https://api.ipify.org; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: full-tunnel integration and recovery completed"
  else
    log "FAIL: test exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

bash -n "$recover"
sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=3m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 3-minute recovery timer armed"

baseline_ip=$(public_ip)
http_ok https://www.google.com/generate_204
http_ok https://www.cloudflare.com/cdn-cgi/trace
getent ahosts www.google.com >/dev/null
log "baseline HTTPS and DNS passed"

cli import "$vpn_config" "$name" >>"$test_log" 2>&1
sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"

for _ in {1..100}; do
  [[ -S "$socket" ]] && break
  sleep 0.1
done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

cli connect "$name" >>"$test_log" 2>&1
status_json=$(cli status --json 2>>"$test_log")
grep -q '"state": "connected"' <<<"$status_json"
grep -q '"interface_name": "wg-' <<<"$status_json"
grep -Eq '"tx_bytes": [1-9][0-9]*' <<<"$status_json"
grep -q '^29040:' < <(ip -4 rule show)
grep -q '^29050:' < <(ip -4 rule show)
ip -4 route show table 51820 | grep -q '^default dev wg-'
if cmp -s "$backup_resolv" /etc/resolv.conf; then
  log "FAIL: DNS file did not change while configured tunnel DNS was active"
  exit 1
fi
log "full-tunnel policy route, TX, and DNS mutation verified"

getent ahosts www.google.com >/dev/null
http_ok https://www.google.com/generate_204
http_ok https://www.cloudflare.com/cdn-cgi/trace
vpn_ip=$(public_ip)
if [[ "$vpn_ip" == "$baseline_ip" ]]; then
  log "FAIL: public IP did not change through full tunnel"
  exit 1
fi
log "VPN DNS, HTTPS, and public-IP change verified"

cli disconnect "$name" >>"$test_log" 2>&1
[[ $(cli status --json 2>>"$test_log" | tr -d '[:space:]') == '[]' ]]
! ip -brief link show | grep -q '^wg-'
! ip -4 rule show | grep -q '^29040:'
! ip -4 rule show | grep -q '^29050:'
cmp -s "$backup_resolv" /etc/resolv.conf
getent ahosts www.google.com >/dev/null
http_ok https://www.google.com/generate_204
[[ $(public_ip) == "$baseline_ip" ]]
log "disconnect route, DNS, HTTPS, and public-IP restoration verified"

cli delete "$name" >>"$test_log" 2>&1
