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
unit_suffix="${BASHPID:-$$}"
source_unit="wireguide-crash-source-$unit_suffix"
recovered_unit="wireguide-crash-recovered-$unit_suffix"
recovery_unit="wireguide-network-recovery-$unit_suffix"
name=crash-recovery-audit

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 5 --max-time 12 --silent --fail https://www.google.com/generate_204 >/dev/null; }

throw_route_present() {
  local route=$1
  local family=-4
  [[ "$route" == *:* ]] && family=-6
  ip "$family" route show table all | awk -v target="${route%/*}" '
    $1 == "throw" {
      destination = $2
      sub(/\/.*/, "", destination)
      if (destination == target) found = 1
    }
    END { exit !found }
  '
}

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop "$source_unit.service" "$recovered_unit.service" \
    "$recovery_unit.timer" "$recovery_unit.service" 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: product crash recovery restored network and removed stale UAPI"
  else
    log "FAIL: crash recovery test exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

sudo -n systemd-run --quiet --unit="$recovery_unit" --on-active=3m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 3-minute emergency recovery armed"

http_ok
cli import "$vpn_config" "$name" >>"$test_log" 2>&1
sudo -n systemd-run --quiet --unit="$source_unit" --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
source_pid=$(sudo -n systemctl show -p MainPID --value "$source_unit.service")
[[ "$source_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$source_pid" >"$helper_pidfile"

cli connect "$name" >>"$test_log" 2>&1
status_json=$(cli status --json 2>>"$test_log")
iface=$(python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["interface_name"])' <<<"$status_json")
[[ "$iface" == wg-* ]]
[[ -f "$helper_data/tunnel-states/$name.json" ]]
[[ -S "/var/run/wireguard/$iface.sock" ]]
! cmp -s "$backup_resolv" /etc/resolv.conf
http_ok
mapfile -t endpoint_routes < <(sudo -n python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as state_file:
    print("\n".join(json.load(state_file).get("endpoint_routes", [])))
' "$helper_data/tunnel-states/$name.json")
(( ${#endpoint_routes[@]} > 0 ))
for endpoint_route in "${endpoint_routes[@]}"; do
  throw_route_present "$endpoint_route"
done

# Deliberately bypass graceful cleanup. The independent timer is the final
# safety net if the replacement helper cannot recover the host on its own.
sudo -n kill -KILL "$source_pid"
for _ in {1..100}; do kill -0 "$source_pid" 2>/dev/null || break; sleep 0.1; done
! kill -0 "$source_pid" 2>/dev/null
[[ -f "$helper_data/tunnel-states/$name.json" ]]
[[ -S "/var/run/wireguard/$iface.sock" ]]
log "SIGKILL left recovery journal and stale UAPI as expected"

# A fresh helper must consume the journal before accepting normal CLI work.
sudo -n systemd-run --quiet --unit="$recovered_unit" --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..150}; do
  if [[ -S "$socket" ]] && cli status --json >/dev/null 2>>"$test_log"; then break; fi
  sleep 0.1
done
recovered_pid=$(sudo -n systemctl show -p MainPID --value "$recovered_unit.service")
[[ "$recovered_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$recovered_pid" >"$helper_pidfile"

[[ $(cli status --json 2>>"$test_log" | tr -d '[:space:]') == '[]' ]]
[[ ! -e "$helper_data/tunnel-states/$name.json" ]]
[[ ! -S "/var/run/wireguard/$iface.sock" ]]
! ip -brief link show | grep -q '^wg-'
! ip -4 rule show | grep -q '^29040:'
! ip -4 rule show | grep -q '^29050:'
for endpoint_route in "${endpoint_routes[@]}"; do
  if throw_route_present "$endpoint_route"; then
    log "FAIL: crash recovery left endpoint throw route: $endpoint_route"
    exit 1
  fi
done
cmp -s "$backup_resolv" /etc/resolv.conf
getent ahosts www.google.com >/dev/null
http_ok
log "replacement helper consumed journal and restored DNS/routes/UAPI/internet"

cli delete "$name" >>"$test_log" 2>&1
