#!/usr/bin/env python3
"""Run the opt-in native macOS helper test with bounded recovery.

Build first: go test -c -o /tmp/wireguide-macos-live.test ./internal/helper
Run: python3 scripts/macos_native_live_test.py BINARY PRIVATE_EVIDENCE_DIR
Uses native administrator authentication; never accepts a password argument.
No sleep, physical interface changes, existing profiles or installed helper changes.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile


def call(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, timeout=25, **kwargs)


def root_run(binary, evidence):
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="wg-native-live-", dir="/private/tmp"))
    os.chmod(work, 0o700)
    exe = work / "helper.test"
    shutil.copy2(binary, exe)
    os.chmod(exe, 0o700)
    (evidence / "work-path").write_text(str(work))
    env = dict(os.environ, WIREGUIDE_TEST_MACOS_LIVE="1", WIREGUIDE_MACOS_LIVE_DIR=str(work), TMPDIR="/tmp")
    pf_state = Path("/Library/Application Support/wireguide/pf-was-enabled")
    original_lease = pf_state.read_bytes() if pf_state.exists() else None
    if original_lease is not None:
        (evidence / "original-pf-journal.private").write_bytes(original_lease)
    installed = call(["/bin/launchctl", "print", "system/com.wireguide.helper"])
    if installed.returncode == 0 and "state = running" in installed.stdout:
        raise RuntimeError("installed WireGuide helper is running; close WireGuide before testing")
    before = {}
    for name, argv in {
        "dns": ["/usr/sbin/scutil", "--dns"],
        "route": ["/sbin/route", "-n", "get", "default"],
        "pf": ["/sbin/pfctl", "-si"],
        "pf-rules": ["/sbin/pfctl", "-sr"],
        "pf-references": ["/sbin/pfctl", "-s", "References"],
        "interfaces": ["/sbin/ifconfig", "-l"],
    }.items():
        r = call(argv)
        if r.returncode and name != "pf-references":
            raise RuntimeError(f"preflight {name}: {r.stderr}")
        before[name] = r.stdout
        (evidence / (name + ".before")).write_text(r.stdout + r.stderr)
    for anchor in ("com.apple/wireguide", "com.apple/wireguide/dns"):
        r = call(["/sbin/pfctl", "-a", anchor, "-sr"])
        if r.returncode or r.stdout.strip():
            raise RuntimeError("existing WireGuide firewall state; close the running VPN first")
    rules = before["pf-rules"]
    if rules.strip() and 'anchor "com.apple/*"' not in rules:
        raise RuntimeError("custom PF master rules lack the Apple anchor; refusing replacement")
    if "Status: Disabled" in before["pf"] and "No pf starter references held" in before["pf-references"]:
        env["WIREGUIDE_LIVE_PF_DISABLE"] = "1"
    services = {}
    listing = call(["/usr/sbin/networksetup", "-listallnetworkservices"])
    if listing.returncode:
        raise RuntimeError(listing.stderr)
    for row in listing.stdout.splitlines()[1:]:
        name = row.removeprefix("*")
        if not name:
            continue
        services[name] = {}
        for field, option in (("dns", "-getdnsservers"), ("search", "-getsearchdomains")):
            r = call(["/usr/sbin/networksetup", option, name])
            if r.returncode:
                raise RuntimeError(f"cannot snapshot {name}: {r.stderr}")
            services[name][field] = r.stdout
    (evidence / "services.before.private.json").write_text(json.dumps(services, indent=2))
    (evidence / "binary.sha256").write_text(hashlib.sha256(exe.read_bytes()).hexdigest() + "\n")
    rc = 1
    try:
        # Test subprocess has its own test timeout; this independent parent
        # also recovers when the test panics, crashes or loses its caller.
        with (evidence / "native-test.log").open("w") as log:
            try:
                r = subprocess.run([str(exe), "-test.run=^TestMacOSLiveProductionNetworking$", "-test.v", "-test.timeout=180s"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=210)
                rc = r.returncode
            except subprocess.TimeoutExpired:
                log.write("\nFAIL: independent 210-second deadline; emergency cleanup follows\n")
    finally:
        label = work / "label"
        if label.exists():
            call(["/bin/launchctl", "bootout", "system/" + label.read_text().strip()])
        with (evidence / "recovery.log").open("w") as log:
            try:
                r = subprocess.run([str(exe), "-test.run=^TestMacOSLiveEmergencyCleanup$", "-test.v", "-test.timeout=40s"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=45)
                if r.returncode:
                    rc = rc or 1
            except subprocess.TimeoutExpired:
                rc = rc or 1
                log.write("\nEmergency recovery timed out; restoring exact service preferences\n")
        # Restore only preferences that differ from the recorded original.
        for name, values in services.items():
            for field, get_op, set_op in (("dns", "-getdnsservers", "-setdnsservers"), ("search", "-getsearchdomains", "-setsearchdomains")):
                current = call(["/usr/sbin/networksetup", get_op, name])
                if current.stdout != values[field]:
                    lines = values[field].strip().splitlines()
                    args = ["Empty"] if not lines or lines[0].startswith("There aren't any") else lines
                    r = call(["/usr/sbin/networksetup", set_op, name, *args])
                    if r.returncode:
                        rc = rc or 1
        for anchor in ("com.apple/wireguide/dns", "com.apple/wireguide"):
            r = call(["/sbin/pfctl", "-a", anchor, "-F", "rules"])
            if r.returncode:
                rc = rc or 1
        # Release only our still-journaled token; never use a global PF stop.
        if pf_state.exists():
            try:
                state = json.loads(pf_state.read_text())
                token = state.get("token", "")
                if token and str(token).isdigit():
                    call(["/sbin/pfctl", "-X", str(token)])
            except (ValueError, OSError):
                pass
        other_token = work / "other-pf-token"
        if other_token.exists() and other_token.read_text().strip().isdigit():
            call(["/sbin/pfctl", "-X", other_token.read_text().strip()])
        if original_lease is not None:
            pf_state.write_bytes(original_lease)
        elif pf_state.exists():
            pf_state.unlink()
        for name, argv in {"dns": ["/usr/sbin/scutil", "--dns"], "route": ["/sbin/route", "-n", "get", "default"], "pf": ["/sbin/pfctl", "-si"], "interfaces": ["/sbin/ifconfig", "-l"]}.items():
            r = call(argv)
            (evidence / (name + ".after")).write_text(r.stdout + r.stderr)
            if name == "dns" and r.stdout != before[name]:
                rc = rc or 1
            if name == "interfaces" and set(r.stdout.split()) != set(before[name].split()):
                rc = rc or 1
            if name == "pf" and ("Status: Enabled" in r.stdout) != ("Status: Enabled" in before[name]):
                rc = rc or 1
        for src in work.rglob("*.log"):
            shutil.copy2(src, evidence / src.name)
        (evidence / "result.json").write_text(json.dumps({"exit_code": rc, "work_dir": str(work), "sleep_test": "deferred by user", "installed_helper_modified": False}, indent=2))
        uid = int(os.environ.get("SUDO_UID", str(binary.stat().st_uid)))
        for root, dirs, files in os.walk(evidence):
            os.chown(root, uid, -1)
            for name in files:
                os.chown(Path(root) / name, uid, -1)
    print(f"Native test exit={rc}; evidence={evidence}")
    return rc


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    binary, evidence = map(lambda s: Path(s).resolve(), sys.argv[1:])
    if sys.platform != "darwin":
        raise SystemExit("macOS only")
    if os.geteuid() == 0:
        return root_run(binary, evidence)
    # Authorization processes may not access removable volumes under TCC.
    # Stage all inputs/output on the internal disk before elevating.
    stage = Path(tempfile.mkdtemp(prefix="wg-live-stage-", dir="/private/tmp"))
    os.chmod(stage, 0o700)
    staged_script, staged_binary = stage / "runner.py", stage / "helper.test"
    shutil.copy2(Path(__file__).resolve(), staged_script)
    shutil.copy2(binary, staged_binary)
    local_evidence = stage / "evidence"
    command = " ".join(shlex.quote(s) for s in [sys.executable, str(staged_script), str(staged_binary), str(local_evidence)])
    literal = command.replace("\\", "\\\\").replace('"', '\\"')
    result = subprocess.run(["/usr/bin/osascript", "-e", f'do shell script "{literal}" with administrator privileges'])
    if local_evidence.exists():
        shutil.copytree(local_evidence, evidence, dirs_exist_ok=True)
    print(f"Internal evidence: {local_evidence}; copied evidence: {evidence}")
    return result.returncode



if __name__ == "__main__":
    raise SystemExit(main())
