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
generated_dir="$test_root/generated"
backup_resolv="$test_root/resolv.conf.before"
helper_pidfile="$test_root/helper.pid"
recovery_log="$test_root/recovery.log"
test_log="$test_root/test.log"
socket="$runtime_dir/wireguide-${uid_num}.sock"

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data" "$generated_dir"
chmod 700 "$test_root" "$generated_dir"
install -m 0644 /etc/resolv.conf "$backup_resolv"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 6 --max-time 15 --silent --fail "$1" >/dev/null; }
public_ip() { curl --connect-timeout 6 --max-time 15 --silent --fail https://api.ipify.org; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  cli set dns-protection off >>"$test_log" 2>&1 || true
  cli set killswitch off >>"$test_log" 2>&1 || true
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: CLI feature matrix and recovery completed"
  else
    log "FAIL: CLI feature matrix exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# Produce private, short-lived variants without ever printing key material.
derive_config() {
  local destination=$1 allowed=$2 table_cfg=$3 fwmark_cfg=$4 keep_dns=$5
  awk -v allowed="$allowed" -v table_cfg="$table_cfg" -v fwmark_cfg="$fwmark_cfg" -v keep_dns="$keep_dns" '
    /^\[Interface\][[:space:]]*$/ {
      print
      if (table_cfg != "") print "Table = " table_cfg
      if (fwmark_cfg != "") print "FwMark = " fwmark_cfg
      next
    }
    /^[[:space:]]*DNS[[:space:]]*=/ && keep_dns != "yes" { next }
    /^[[:space:]]*AllowedIPs[[:space:]]*=/ { print "AllowedIPs = " allowed; next }
    { print }
  ' "$vpn_config" >"$destination"
  chmod 600 "$destination"
}

install -m 0600 "$vpn_config" "$generated_dir/full.conf"
derive_config "$generated_dir/full-custom.conf" "0.0.0.0/0" "51888" "0xca70" yes
derive_config "$generated_dir/split-v4.conf" "10.255.254.1/32" "" "" no
derive_config "$generated_dir/split-v6.conf" "fd42:4242::1/128" "" "" no
derive_config "$generated_dir/split-custom.conf" "10.255.254.88/32" "51888" "0xca70" no
derive_config "$generated_dir/table-off.conf" "10.255.254.99/32" "off" "" no

sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=5m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 5-minute emergency recovery armed"

baseline_ip=$(public_ip)
http_ok https://www.google.com/generate_204
getent ahosts www.google.com >/dev/null

# Offline config-store and automation mutations.
cli import "$generated_dir/full.conf" full-a >>"$test_log" 2>&1
cli import "$generated_dir/full.conf" full-b >>"$test_log" 2>&1
cli import "$generated_dir/full-custom.conf" full-custom >>"$test_log" 2>&1
cli import "$generated_dir/split-v4.conf" rename-source >>"$test_log" 2>&1
cli import "$generated_dir/split-v6.conf" split-v6 >>"$test_log" 2>&1
cli import "$generated_dir/split-custom.conf" split-custom >>"$test_log" 2>&1
cli import "$generated_dir/table-off.conf" table-off >>"$test_log" 2>&1
if cli import "$generated_dir/full.conf" full-a >>"$test_log" 2>&1; then
  log "FAIL: duplicate import unexpectedly overwrote full-a"
  exit 1
fi
cli automation add rename-source connect else >>"$test_log" 2>&1
cli rename rename-source split-v4 >>"$test_log" 2>&1
cli automation rules split-v4 | grep -Eq 'connect[[:space:]]+when otherwise'
if ! cli automation rules rename-source | grep -q 'has no automation rules'; then
  log "FAIL: rename left rules under the old name"
  exit 1
fi
if cli automation add split-v4 connect nonsense:value >>"$test_log" 2>&1; then
  log "FAIL: invalid automation condition was accepted"
  exit 1
fi
cli automation rm split-v4 1 >>"$test_log" 2>&1
log "import/duplicate rejection/rename/rule migration/validation passed"

sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

# Every live setting accepted by the helper, plus invalid-value rejection.
for level in debug info warn error info; do cli set loglevel "$level" >>"$test_log" 2>&1; done
if cli set loglevel verbose >>"$test_log" 2>&1; then
  log "FAIL: invalid log level was accepted"
  exit 1
fi
cli set healthcheck on >>"$test_log" 2>&1
cli set healthcheck off >>"$test_log" 2>&1
cli set pin-interface on >>"$test_log" 2>&1
cli set pin-interface off >>"$test_log" 2>&1
log "live loglevel/healthcheck/pin-interface toggles passed"

# Two full tunnels must conflict without disturbing the first one.
cli connect full-a >>"$test_log" 2>&1
http_ok https://www.google.com/generate_204
if cli connect full-b >>"$test_log" 2>&1; then
  log "FAIL: a second simultaneous full tunnel was accepted"
  exit 1
fi
status_json=$(cli status --json 2>>"$test_log")
python3 -c 'import json,sys; x=json.load(sys.stdin); assert [v["tunnel_name"] for v in x] == ["full-a"]' <<<"$status_json"
if cli rename full-a forbidden-active-name >>"$test_log" 2>&1; then
  log "FAIL: connected tunnel rename was accepted"
  exit 1
fi

# Active delete must first disconnect, restore the host, then delete config.
cli delete full-a >>"$test_log" 2>&1
[[ $(cli status --json 2>>"$test_log" | tr -d '[:space:]') == '[]' ]]
cmp -s "$backup_resolv" /etc/resolv.conf
http_ok https://www.google.com/generate_204
[[ $(public_ip) == "$baseline_ip" ]]
if cli connect full-a >>"$test_log" 2>&1; then
  log "FAIL: active delete left full-a loadable"
  exit 1
fi
cli import "$generated_dir/full.conf" full-a >>"$test_log" 2>&1
log "full-tunnel conflict/active-rename rejection/active-delete restoration passed"

# Four concurrent split tunnels exercise unique interfaces, IPv4 + IPv6,
# explicit-table routing, and Table=off.
cli connect split-v4 >>"$test_log" 2>&1
cli connect split-v6 >>"$test_log" 2>&1
cli connect split-custom >>"$test_log" 2>&1
cli connect table-off >>"$test_log" 2>&1
status_json=$(cli status --json 2>>"$test_log")
python3 -c '
import json,sys
x=json.load(sys.stdin)
assert sorted(v["tunnel_name"] for v in x) == ["split-custom","split-v4","split-v6","table-off"]
ifaces=[v["interface_name"] for v in x]
assert all(v.startswith("wg-") for v in ifaces) and len(set(ifaces)) == 4
' <<<"$status_json"
ip -4 route show | grep -Eq '^10\.255\.254\.1(/32)? dev wg-'
ip -6 route show | grep -Eq '^fd42:4242::1(/128)? dev wg-'
ip -4 route show table 51888 | grep -Eq '^10\.255\.254\.88(/32)? dev wg-'
if ip -4 route show table all | grep -Eq '^10\.255\.254\.99(/32)? ' ; then
  log "FAIL: Table=off installed its forbidden route"
  exit 1
fi
cli routes >>"$test_log" 2>&1

# Remove a middle tunnel: the other three must remain and only its route goes.
split_v6_iface=$(python3 -c 'import json,sys; print(next(v["interface_name"] for v in json.load(sys.stdin) if v["tunnel_name"]=="split-v6"))' <<<"$status_json")
cli disconnect split-v6 >>"$test_log" 2>&1
! ip link show "$split_v6_iface" >/dev/null 2>&1
! ip -6 route show | grep -q '^fd42:4242::1'
status_json=$(cli status --json 2>>"$test_log")
python3 -c 'import json,sys; assert sorted(v["tunnel_name"] for v in json.load(sys.stdin)) == ["split-custom","split-v4","table-off"]' <<<"$status_json"
cli disconnect >>"$test_log" 2>&1
[[ $(cli status --json 2>>"$test_log" | tr -d '[:space:]') == '[]' ]]
! ip -brief link show | grep -q '^wg-'
! ip -4 route show | grep -q '^10.255.254.1'
! ip -4 route show table 51888 | grep -q '^10.255.254.88'
log "four-way split/unique TUN/IPv4/IPv6/custom-table/Table=off/middle+all disconnect passed"

# Custom full-tunnel Table/FwMark, live diagnostics, DNS, and exact teardown.
cli connect full-custom >>"$test_log" 2>&1
ip -4 route show table 51888 | grep -Eq '^default dev wg-'
ip -4 rule show | grep -Eq '^29040:.*not.*fwmark 0xca70.*lookup 51888'
sudo -n wg show all fwmark | grep -Eq '^wg-.*0xca70$'
http_ok https://www.google.com/generate_204
[[ $(public_ip) != "$baseline_ip" ]]
cli dnsleak >>"$test_log" 2>&1
cli routes >>"$test_log" 2>&1
cli disconnect full-custom >>"$test_log" 2>&1
if ip -4 rule show | grep -q '^29040:'; then
  log "FAIL: custom full disconnect left priority 29040 rule"
  ip -4 rule show >>"$test_log"
  exit 1
fi
if ip -4 rule show | grep -q '^29050:'; then
  log "FAIL: custom full disconnect left priority 29050 rule"
  ip -4 rule show >>"$test_log"
  exit 1
fi
if [[ -n $(ip -4 route show table 51888) ]]; then
  log "FAIL: custom full disconnect left table 51888 routes"
  ip -4 route show table 51888 >>"$test_log"
  exit 1
fi
if ! cmp -s "$backup_resolv" /etc/resolv.conf; then
  log "FAIL: custom full disconnect did not restore exact resolv.conf"
  exit 1
fi
if ! http_ok https://www.google.com/generate_204; then
  log "FAIL: custom full disconnect did not restore HTTPS"
  exit 1
fi
restored_ip=$(public_ip)
if [[ "$restored_ip" != "$baseline_ip" ]]; then
  log "FAIL: custom full disconnect public IP mismatch baseline=$baseline_ip restored=$restored_ip"
  exit 1
fi
log "custom full Table/FwMark/DNS-leak/routes/disconnect restoration passed"

# Delete also removes associated automation state.
cli automation add table-off disconnect else >>"$test_log" 2>&1
cli delete table-off >>"$test_log" 2>&1
if ! cli automation rules table-off | grep -q 'has no automation rules'; then
  log "FAIL: delete left automation rules addressable"
  exit 1
fi
log "delete rule cleanup passed"
