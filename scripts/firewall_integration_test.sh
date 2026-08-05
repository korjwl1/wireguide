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
name=firewall-audit
split_name=firewall-split-audit
split_config="$test_root/split.conf"

mkdir -p "$runtime_dir" "$config_dir" "$data_dir" "$helper_data"
install -m 0644 /etc/resolv.conf "$backup_resolv"
split_private=$(wg genkey)
awk -v split_private="$split_private" '
  /^[[:space:]]*PrivateKey[[:space:]]*=/ { print "PrivateKey = " split_private; next }
  /^[[:space:]]*Address[[:space:]]*=/ { print "Address = 10.255.253.2/32"; next }
  /^[[:space:]]*DNS[[:space:]]*=/ { next }
  /^[[:space:]]*AllowedIPs[[:space:]]*=/ { print "AllowedIPs = 10.255.253.1/32"; next }
  { print }
' "$vpn_config" >"$split_config"
chmod 600 "$split_config"
export XDG_RUNTIME_DIR="$runtime_dir" XDG_CONFIG_HOME="$config_dir" XDG_DATA_HOME="$data_dir"

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$test_log"; }
cli() { timeout 45 "$binary" ctl "$@"; }
http_ok() { curl --connect-timeout 5 --max-time 12 --silent --fail "$1" >/dev/null; }

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  # Product OFF is the primary recovery path. These are best-effort here
  # because the helper may already have been killed by a failure.
  cli set dns-protection off >>"$test_log" 2>&1 || true
  cli set killswitch off >>"$test_log" 2>&1 || true
  sudo -n "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log" || true
  sudo -n systemctl stop wireguide-network-recovery.timer wireguide-network-recovery.service 2>/dev/null || true
  if (( rc == 0 )); then
    log "PASS: firewall integration and product-OFF recovery completed"
  else
    log "FAIL: test exited rc=$rc; emergency recovery executed"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

sudo -n systemd-run --quiet --unit=wireguide-network-recovery --on-active=2m \
  "$recover" "$backup_resolv" "$helper_pidfile" "$recovery_log"
log "independent 2-minute emergency recovery armed"

http_ok https://www.google.com/generate_204
getent ahosts www.google.com >/dev/null
cli import "$vpn_config" "$name" >>"$test_log" 2>&1
cli import "$split_config" "$split_name" >>"$test_log" 2>&1

sudo -n systemd-run --quiet --unit=wireguide-fulltest-helper --service-type=exec \
  --setenv="XDG_CONFIG_HOME=$config_dir" --setenv="XDG_DATA_HOME=$data_dir" \
  "$binary" --helper --socket "$socket" --uid "$uid_num" --data-dir "$helper_data"
for _ in {1..100}; do [[ -S "$socket" ]] && break; sleep 0.1; done
[[ -S "$socket" ]]
main_pid=$(sudo -n systemctl show -p MainPID --value wireguide-fulltest-helper.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
printf '%s\n' "$main_pid" >"$helper_pidfile"

cli connect "$name" >>"$test_log" 2>&1
http_ok https://www.google.com/generate_204
getent ahosts www.google.com >/dev/null

# Pre-enabled kill switch: no tunnel means intentional blockade. Connecting
# must temporarily make just enough room for the first WireGuard handshake,
# then rebuild the blockade around the live interface. This caught a real
# ordering bug where the endpoint permit was added only after Connect, so the
# handshake could never leave the host.
cli disconnect "$name" >>"$test_log" 2>&1
cli set killswitch on >>"$test_log" 2>&1
sudo -n nft list table inet wireguide >>"$test_log"
if http_ok https://www.google.com/generate_204; then
  log "FAIL: pre-enabled kill switch did not block with no VPN"
  exit 1
fi
cli connect "$name" >>"$test_log" 2>&1
status_json=$(cli status --json 2>>"$test_log")
grep -q '"state": "connected"' <<<"$status_json"
grep -q '"interface_name": "wg-' <<<"$status_json"
http_ok https://www.google.com/generate_204
getent ahosts www.google.com >/dev/null
cli set killswitch off >>"$test_log" 2>&1
if sudo -n nft list table inet wireguide >/dev/null 2>&1; then
  log "FAIL: pre-enable sequence left kill-switch table after OFF"
  exit 1
fi
http_ok https://www.google.com/generate_204
log "pre-enabled kill switch blockade/connect/normal-OFF passed"

# DNS protection: prove the table is installed, DNS still resolves through
# the configured VPN resolver, and the normal OFF path removes the table.
cli set dns-protection on >>"$test_log" 2>&1
sudo -n nft list table inet wireguide_dns >>"$test_log"
getent ahosts www.google.com >/dev/null
cli set dns-protection off >>"$test_log" 2>&1
if sudo -n nft list table inet wireguide_dns >/dev/null 2>&1; then
  log "FAIL: DNS-protection table survived product OFF"
  exit 1
fi
getent ahosts www.google.com >/dev/null
log "DNS protection ON/allowed-resolution/OFF passed"

# Full + split simultaneously: enabling the kill switch must permit both live
# interfaces. Removing the split must remove only its permit and leave the
# full tunnel usable.
cli connect "$split_name" >>"$test_log" 2>&1
http_ok https://www.google.com/generate_204
status_json=$(cli status --json 2>>"$test_log")
full_iface=$(python3 -c 'import json,sys; print(next(v["interface_name"] for v in json.load(sys.stdin) if v["tunnel_name"]=="firewall-audit"))' <<<"$status_json")
split_iface=$(python3 -c 'import json,sys; print(next(v["interface_name"] for v in json.load(sys.stdin) if v["tunnel_name"]=="firewall-split-audit"))' <<<"$status_json")
cli set killswitch on >>"$test_log" 2>&1
nft_rules=$(sudo -n nft list table inet wireguide)
grep -q "$full_iface" <<<"$nft_rules"
grep -q "$split_iface" <<<"$nft_rules"
http_ok https://www.google.com/generate_204
cli disconnect "$split_name" >>"$test_log" 2>&1
nft_rules=$(sudo -n nft list table inet wireguide)
grep -q "$full_iface" <<<"$nft_rules"
if grep -q "$split_iface" <<<"$nft_rules"; then
  log "FAIL: disconnected split tunnel remained permitted by kill switch"
  exit 1
fi
http_ok https://www.google.com/generate_204
cli set killswitch off >>"$test_log" 2>&1
log "multi-tunnel kill-switch add/selective-remove passed"

# Kill switch while connected must preserve VPN traffic.
cli set killswitch on >>"$test_log" 2>&1
sudo -n nft list table inet wireguide >>"$test_log"
http_ok https://www.google.com/generate_204
log "kill switch ON preserved VPN HTTPS"

# With the VPN removed but kill switch still ON, a fresh outbound connection
# must fail. This is the intentional offline phase. IPC remains reachable over
# loopback so the product's OFF command can restore connectivity.
cli disconnect "$name" >>"$test_log" 2>&1
if http_ok https://www.google.com/generate_204; then
  log "FAIL: internet remained reachable with kill switch ON and VPN down"
  exit 1
fi
log "kill switch intentionally blocked internet with VPN down"

# This is the primary assertion requested by the test: normal feature OFF,
# not the emergency script, must restore internet and remove nftables state.
cli set killswitch off >>"$test_log" 2>&1
if sudo -n nft list table inet wireguide >/dev/null 2>&1; then
  log "FAIL: kill-switch table survived product OFF"
  exit 1
fi
getent ahosts www.google.com >/dev/null
http_ok https://www.google.com/generate_204
cmp -s "$backup_resolv" /etc/resolv.conf
log "kill switch product OFF restored DNS and internet"

cli delete "$name" >>"$test_log" 2>&1
cli delete "$split_name" >>"$test_log" 2>&1
