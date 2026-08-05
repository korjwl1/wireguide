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
split_config="$test_root/resource-split.conf"
name=resource-audit
cycle_count=${WIREGUIDE_RESOURCE_CYCLES:-30}
status_count=${WIREGUIDE_RESOURCE_STATUS_CALLS:-100}
test_gogc=${WIREGUIDE_RESOURCE_GOGC:-}
test_godebug=${WIREGUIDE_RESOURCE_GODEBUG:-}

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
awk '
  /^[[:space:]]*DNS[[:space:]]*=/ { next }
  /^[[:space:]]*AllowedIPs[[:space:]]*=/ { print "AllowedIPs = 10.255.250.1/32"; next }
  { print }
' "$vpn_config" >"$split_config"
chmod 600 "$split_config"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: helper resource stability completed"
  else
    log "FAIL: resource stability exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=5m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"

cli import "$split_config" "$name" >>"$test_log" 2>&1
service_env=(--setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir")
[[ -n "$test_gogc" ]] && service_env+=(--setenv="GOGC=$test_gogc")
[[ -n "$test_godebug" ]] && service_env+=(--setenv="GODEBUG=$test_godebug")
sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  "${service_env[@]}" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

rss_kib() { awk '/^VmRSS:/ {print $2}' "/proc/$main_pid/status"; }
threads() { awk '/^Threads:/ {print $2}' "/proc/$main_pid/status"; }
fd_count() { sudo -n find "/proc/$main_pid/fd" -mindepth 1 -maxdepth 1 -printf . | wc -c; }
cpu_ticks() { awk '{print $14+$15}' "/proc/$main_pid/stat"; }
sample() {
  local label=$1
  log "resource $label rss_kib=$(rss_kib) fds=$(fd_count) threads=$(threads) cpu_ticks=$(cpu_ticks)"
}

# Warm runtime caches before choosing the leak baseline.
for _ in {1..5}; do
  cli connect "$name" >>"$test_log" 2>&1
  cli status --json >/dev/null 2>>"$test_log"
  cli disconnect "$name" >>"$test_log" 2>&1
done
baseline_rss=$(rss_kib)
baseline_fds=$(fd_count)
baseline_threads=$(threads)
baseline_ticks=$(cpu_ticks)
start_seconds=$(date +%s)
sample warm-baseline

for cycle in $(seq 1 "$cycle_count"); do
  cli connect "$name" >>"$test_log" 2>&1
  cli status --json >/dev/null 2>>"$test_log"
  cli disconnect "$name" >>"$test_log" 2>&1
  [[ $(cli status --json 2>>"$test_log" | tr -d '[:space:]') == '[]' ]]
  if (( cycle % 10 == 0 )); then sample "cycle-$cycle"; fi
done

# Exercise short-lived IPC clients and wgctrl status acquisition repeatedly
# while one engine is live, then verify all descriptors close again.
cli connect "$name" >>"$test_log" 2>&1
for _ in $(seq 1 "$status_count"); do cli status --json >/dev/null 2>>"$test_log"; done
cli disconnect "$name" >>"$test_log" 2>&1
sleep 1
sample after-status-storm

end_rss=$(rss_kib)
end_fds=$(fd_count)
end_threads=$(threads)
end_ticks=$(cpu_ticks)
elapsed=$(( $(date +%s) - start_seconds ))
tick_hz=$(getconf CLK_TCK)
cpu_millis=$(( (end_ticks - baseline_ticks) * 1000 / tick_hz ))

(( end_rss <= baseline_rss + 32768 ))
(( end_fds <= baseline_fds + 4 ))
(( end_threads <= baseline_threads + 4 ))
! ip -brief link show | grep -q '^wg-'
! ip -4 route show | grep -q '^10.255.250.1'
[[ -z $(sudo -n find /var/run/wireguard -maxdepth 1 -type s -name 'wg-*.sock' -printf x) ]]
cmp -s "$backup_resolv" /etc/resolv.conf
gogc_label=${test_gogc:-helper-default}
log "$cycle_count lifecycle cycles + $status_count status calls (GOGC=$gogc_label): wall=${elapsed}s helper_cpu=${cpu_millis}ms rss_delta=$((end_rss-baseline_rss))KiB fd_delta=$((end_fds-baseline_fds)) thread_delta=$((end_threads-baseline_threads))"

cli delete "$name" >>"$test_log" 2>&1
