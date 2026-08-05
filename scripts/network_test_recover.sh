#!/usr/bin/env bash
set -u

# Emergency recovery for the destructive Linux full-tunnel integration test.
# Designed to be run by an independent systemd transient unit, so it still
# executes if the test shell, Codex connection, or VPN route is wedged.
backup_resolv=${1:?backup resolv.conf path required}
helper_pidfile=${2:?helper pidfile required}
recovery_log=${3:?recovery log path required}

exec >>"$recovery_log" 2>&1
echo "$(date -Is) recovery starting"

systemctl stop wireguide-fulltest-helper.service 2>/dev/null || true

if [[ -s "$helper_pidfile" ]]; then
  helper_pid=$(<"$helper_pidfile")
  if [[ "$helper_pid" =~ ^[0-9]+$ ]]; then
    kill -TERM "$helper_pid" 2>/dev/null || true
    for _ in {1..20}; do
      kill -0 "$helper_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$helper_pid" 2>/dev/null || true
  fi
fi

# Removing the userspace-owned TUN also removes its device routes. Handle any
# leftovers explicitly because a crash between route phases can leave rules.
while IFS= read -r iface; do
  [[ "$iface" == wg-* ]] && ip link delete dev "$iface" 2>/dev/null || true
done < <(ip -o link show | awk -F': ' '{print $2}')

# A killed wireguard-go process can leave its Unix UAPI socket behind even
# after the TUN is gone. Restrict deletion to WireGuide's hashed wg-* names.
find /var/run/wireguard -maxdepth 1 -type s -name 'wg-*.sock' -delete 2>/dev/null || true

for family in -4 -6; do
  for priority in 29040 29050; do
    for _ in {1..50}; do
      ip "$family" rule show | grep -q "^${priority}:" || break
      ip "$family" rule delete priority "$priority" 2>/dev/null || break
    done
  done
  for table in $(seq 51820 51919); do
    ip "$family" route flush table "$table" 2>/dev/null || true
  done
done

nft delete table inet wireguide 2>/dev/null || true
nft delete table inet wireguide_dns 2>/dev/null || true

if [[ -f "$backup_resolv" ]]; then
  install -m 0644 "$backup_resolv" /etc/resolv.conf
fi

# Give the normal cleanup a chance first. If connectivity is still unavailable,
# restart NetworkManager as a final self-healing fallback; the saved Wi-Fi
# profile reconnects wlan0 without requiring this test session to be alive.
if ! curl --connect-timeout 5 --max-time 10 --silent --fail https://www.google.com/generate_204 >/dev/null; then
  echo "$(date -Is) primary recovery did not restore connectivity; restarting NetworkManager"
  systemctl restart NetworkManager 2>/dev/null || true
  sleep 10
  if [[ -f "$backup_resolv" ]]; then
    install -m 0644 "$backup_resolv" /etc/resolv.conf
  fi
fi

if curl --connect-timeout 5 --max-time 15 --silent --fail https://www.google.com/generate_204 >/dev/null; then
  echo "$(date -Is) recovery connectivity check passed"
else
  echo "$(date -Is) recovery connectivity check FAILED"
fi
echo "$(date -Is) recovery complete"
