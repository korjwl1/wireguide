> Historical review of **68fdca0**, before the follow-up fixes. See [disposition](claude-review-disposition.md) for implemented corrections and remaining runtime verification.

# WireGuide PR #50–#53 통합 독립 리뷰

- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5). 코드 소유권은 Codex에 있음
- 범위: `origin/main` 8ecdfd4 → `fix/windows-single-instance` HEAD **68fdca07407b886664315618c759a295e69416f9** (커밋 37개, 파일 200개, +16,651/−2,425)

## 0. 기준 상태

| 항목 | 값 | 확인 방법 |
|---|---|---|
| HEAD | 68fdca0, 작업 트리 깨끗함 | `git rev-parse HEAD`, `git status --short` |
| origin/main | 8ecdfd4 (PR #50의 merge-base와 같음) | `git merge-base` |
| PR #50 | c06c0fe, OPEN | `gh pr view`. 원격 head와 ref 일치 |
| PR #51 | 37e63bb, OPEN | 일치 |
| PR #52 | 0bb2fb7, OPEN | 일치 |
| PR #53 | f1de66f, OPEN | 일치 |
| PR 댓글, 리뷰, inline 댓글 | 네 PR 모두 0건 | `gh pr view --json comments,reviews`, `gh api .../pulls/N/comments` |
| issue #48/#49/#41/#12 | 본문과 댓글 모두 읽음 | `gh issue view` |
| CI run 38672451963 | headSha=68fdca0, Linux/Windows/macOS 모두 success | `gh run view` |

리뷰를 시작할 때 원격 PR head와 지정된 ref 사이에 차이는 없었습니다.

**작업 경계 준수.** 실제 checkout, 브랜치, 문서는 수정하지 않았습니다. 재현 테스트는 `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-claude-review-20261015/` 아래 HEAD 복사본(루트와 `agents/a50..a53`)에만 추가했습니다. 호스트의 PF/DNS/route/launchd system 도메인은 건드리지 않았습니다.

**검토 방식.** PR별 대조는 독립 하위 에이전트 네 개가 원본 diff(`pr-50..pr-N`)와 HEAD를 비교했습니다. 아래 "재현" 표시는 그중 핵심 항목을 제가 직접 다시 실행해 확인한 결과입니다. 최근 수정 커밋(513e161, faef4c8, adb9f5c)은 제가 직접 읽었습니다.

---

## 1. 결론

**지금 상태로는 main 병합을 권하지 않습니다.**

PR 네 개의 기능 자체는 대부분 HEAD에 들어와 있습니다. 문제는 세 가지입니다.

1. 원본 #50이 막아 둔 장애 경로 몇 개가 조용히 빠졌습니다. PF 토큰 무효화 처리, KS 모드의 unpinned DNS permit 제거, signal fallback cleanup, 시작 시 DNS 설정 복원이 여기에 해당합니다.
2. 통합 과정에서 새로 생긴 상호작용 결함이 있습니다. pendingDesired와 CLI 판정, 재연결 중 helper 종료, faef4c8이 추가한 주기적 KS 재조정이 해당합니다.
3. 체크리스트 문서의 몇몇 주장이 사실과 다릅니다(5절).

결함 하나하나는 고칠 범위가 작습니다. 다만 "실패를 숨기지 않는다", "사용자 Off/KS 의도를 존중한다"는 프로젝트 핵심 약속을 직접 깨는 항목이 여러 개라서 병합 차단 사유로 봅니다.

---

## 2. 기능별 판정 요약

판정 기호: ✅ 수용 · 🔁 변경(adapted) · ⛔ 의도적 제외 · ❌ 누락

### #50 DNS/KS reconciliation (issue #48)

| 기능 | 판정 | 근거 |
|---|---|---|
| helper가 DNS wanted 상태 보유, 클라이언트 DNS 목록 무시 | ✅ | `helper/handlers.go:692-711` |
| **helper 일반 시작 시 config.json의 `dns_protection` 복원** | ❌ | PR `helper.go:374 setDNSWanted(settings.DNSProtection)`. HEAD `helper.go:534-548`은 HealthCheck/Pin/LogLevel만 복원함 → 결함 H-3 |
| 모든 connected 터널 기준 per-resolver permit, loopback 예외, search domain 무시, split 터널 제외 | ✅ (개선: 터널 간 longest-prefix, Table=off) | `dns_policy.go:18-77`, `dns_rules.go:80,124`, `dns_protection.go:58` |
| **KS가 켜져 있을 때 unpinned permit 제거 (`dropUnpinned`)** | ❌ | PR `darwin.go:207-235`. HEAD `dns_rules.go:82-88` → 결함 M-4 |
| connect, 모든 disconnect, automation, watchdog, partial 실패 시 reconcile | ✅ | `handlers.go:538`, `wifi_rules.go:287-313`, `forced_disconnect.go:63` |
| safety net 재시도/backoff | 🔁 (5초 tick, 1s→30s) | `dns_protection.go:128-149`. faef4c8이 KS 재조정도 추가 → 결함 M-1 |
| suspend/resume 중첩, deferred resume | 🔁 (depth 카운트) | `helper.go:1009-1081`, `monitor.go:572-586` |
| **panic 안전: 모든 connect 경로에서 connectMu를 defer로 해제** | ❌ (부분) | PR `connectLocked`. HEAD legacy 루프 `helper.go:724-747`은 수동 Unlock → 결함 M-2 |
| PF `-E`/`-X` 토큰, bootsessionuuid | ✅ | `firewall/pf_lease_darwin.go` |
| **외부 `pfctl -d` 뒤 pf 재활성화, 죽은 토큰 처리** | ❌ | PR `pfRunning`/`pfTokenGone` → 결함 H-1 |
| pf.conf reload는 `com.apple/*` anchor가 없을 때만 | 🔁 (퇴행) | `darwin.go:649`가 부분 문자열 매칭 → 결함 L-1 |
| 시작 시 두 anchor flush | ✅ | `darwin.go:702` |
| Linux nft DNS 테이블 원자 교체, pinned만 oifname, stale 정리, delete 실패 재시도 | ✅ (재시도는 PR보다 나음) | `linux.go:287-296`. 렌더 결과 검사함 |
| **SIGTERM/SIGINT 3초 상한 graceful + fallback cleanup** | ❌ (상한만 있고 fallback 없음) | `helper/signals.go:42-45`가 시간 초과 시 바로 `exit(0)` → 결함 M-3 |
| `/1` 쌍을 `/0` 자동 정책에 반영하지 않음 | ⛔ 정당. 다만 문서 설명이 틀림 | 원본 PR도 `IsFullTunnel`(/0)만 사용(PR `firewall_reconcile.go:73`). "원본이 /1을 /0처럼 취급"이라는 체크리스트 서술은 사실이 아님 |

### #51 split DNS

| 기능 | 판정 | 근거 |
|---|---|---|
| validator (`~`, 형식 오류, split이면 서버 1개 이상, `~` 32개 상한) | ✅ | `config/validator.go:14,139,141`. 길이 예산은 없음 → L-3 |
| macOS dynamic store 키, injection 검증, 2000바이트 줄 제한, read-back | ✅ | `network/splitdns_darwin.go:90-221` |
| disconnect/rollback/shutdown 제거, 시작·recovery sweep | ✅/🔁 (실패 시 retry 큐, journal 유지) | `connect_phases.go:75,395,453`, `recovery.go:189,216` |
| journal `dns_mode`, global일 때만 시스템 DNS reset | ✅ | `recovery.go:32,69-77,253` |
| Linux resolvectl과 부분 적용 rollback | 🔁 (default-route 실패도 치명 처리) | `linux.go:641-665` |
| Windows split | 🔁 (경고 대신 Connect 실패) | `windows.go:437`. 타당하나 사전 점검 없음 |
| utun 재사용 보호 | 🔁 (추가) | `tunnel/dns_cleanup.go`. connectMu 직렬화 때문에 실제 경합 경로는 거의 없음 |
| split-aware/혼합 진단, 상세 패널, 에디터, i18n, CLI | ✅/🔁 | `diag/dnsleak_split.go`, `TunnelDetail.svelte`, `wireguard-lang.js`. 혼합 모드 판정 오류 → M-6 |

누락 항목은 없습니다.

### #52 automation/reconnect

| 기능 | 판정 | 근거 |
|---|---|---|
| 부정 조건(SSID/subnet/MAC), HOLD 규칙, 유선 빈 SSID | ✅ | `wifi/automation.go:153-231` |
| 부정 규칙 저장 | 🔁 (같은 config.json 안의 `per_tunnel_rules_v2`) | `wifi/automation_json.go`. 다운그레이드 후 재업그레이드 시 유실 → L-4 |
| 에디터, CLI `not-*:`, en/ko/ja | ✅ | `AutomationEditor.svelte`, `cli.go:618-660` |
| 기본 인터페이스 settle, 15초 타이머 재평가, preview Peek | ✅ (preview가 drift 시 실제 재평가를 띄울 수 있음) | `automation_state.go:35-68,215-242`, `wifi_rules.go:348-376` |
| 수동 latch (GUI/트레이/CLI 모두 RPC 하나로 모임) | ✅ | `handlers.go:425/473/488` |
| latch 식별자 (SSID + iface + MAC + subnet) | 🔁 → 결함 | `automation_state.go:126,206,285` → M-7, M-8 |
| 규칙 저장 시 재평가 | ✅ | `wifi_rules.go:387-469` |
| ErrAlreadyConnected/ErrNotConnected 처리, 첫 시도에만 teardown, 할 일 없으면 종료 | ✅ | `helper.go:711,758`, `monitor.go:690-744` |
| 기본 경로 대기 (513e161) | 🔁 (원본은 teardown 후, HEAD는 teardown 전) | `monitor.go:640-655`, `automation_state.go:350-409`. 시간 초과 시 계속 진행(원본과 같음). 취소 지연 약 14µs. **513e161 수정은 맞음** |
| 규칙 소유 터널을 legacy teardown에서 제외 | ⛔ (수동 On repair 허용) | 타당. wake 때마다 규칙 터널이 한 번씩 끊김 |
| LAN overlap: 경로 생략, 재연결 skip | ⛔ / automation 연결만 skip | `wifi_rules.go:230`. 자동 연결 터널의 wake 복구에 적용되지 않음 → L-2 |

### #53 launchd socket activation (issue #41)

| 기능 | 판정 | 근거 |
|---|---|---|
| Sockets.Listeners 0600, SockPathOwner=설치 uid, RunAtLoad false | ✅ | `elevate/spawn_darwin.go:95-135` |
| `launch_activate_socket` FD 사용, legacy 대체 경로 | ✅ | `launchd/activate_darwin.go`, `helper.go:147-189` |
| GUI 전 휴면, 15초 유예, 활성 터널이면 유지 | 🔁 (휴면은 activated일 때만, pendingDesired도 유지 조건) | `wifi_rules.go:82`, `helper.go:898-960` → H-2, M-5 |
| 최신 설치는 osascript 없음, 업그레이드는 요청 1회, 이전 helper 정상 종료 | ✅ | `gui/helper_lifecycle.go:98-153` |
| 종료 시 health 감시 먼저 중단 | ✅ | `gui/gui.go:260-262,388-390` |
| IPC 1.2 `gui_attached`, CLI start/stop/status | ✅ | `ipc/types.go:13-17`, `cli/lifecycle.go:50-170`. pending 상태가 보이지 않음 → M-5 |
| orphan 자체 삭제와 `--app-bundle` | ⛔ | 이유(일시적 앱 부재로 복구 바이너리 삭제)는 정당. 그러나 "기존 명시 uninstall 경로 유지"는 사실이 아님 → M-9 |

### Windows 단일 인스턴스 (issue #30)

- 두 번째 인스턴스는 `guiinstance.Acquire`에서 끝납니다. helper spawn, 종료, UAC 요청을 하지 않는 것을 코드로 확인했습니다.
- 문서의 "helper teardown이 끝날 때까지 예약 유지"는 과장입니다. `handleShutdown`은 즉시 반환합니다(`handlers.go:63-68`). 그래서 재실행하면 이전 helper가 정리하는 도중에 새 helper가 뜰 수 있습니다. main에도 있던 문제라 회귀는 아닙니다.

---

## 3. 확정 결함 (심각도순)

"재현"은 격리 테스트로 동작을 보인 것이고, "추론"은 코드 읽기에 근거한 것입니다. 실제 OS에서 일어나는지는 별도로 표시했습니다.

### High

**H-1. 외부 `pfctl -d` 또는 죽은 토큰 → KS/DNS 보호가 fail-open인데 UI는 켜짐**
- 위치:
  - `firewall/pf_lease_darwin.go:41-43`: 같은 boot의 토큰이 있으면 pf 실행 여부를 확인하지 않음
  - `pf_lease_darwin.go:96-99`: `-X` 실패 시 토큰 유지
  - `darwin.go:418-420,541-543,581-583`: release 실패 시 모델 갱신 안 함
  - `darwin.go:708-712`: recovery에서 죽은 토큰 유지
- 발생 조건: 다른 VPN이나 사용자가 `pfctl -d`를 실행함. 또는 helper crash 뒤 pf가 꺼진 상태에서 재시작함.
- 영향:
  - DisableKillSwitch가 계속 실패하고 `IsKillSwitchEnabled=true`가 유지됩니다.
  - 다시 켜는 경로에서 `-E`를 호출하지 않아 pf가 계속 꺼져 있습니다.
  - kill switch와 DNS 보호가 실제로는 동작하지 않는데 UI에는 켜짐으로 보입니다.
  - 원본 #50에 있던 방어 코드가 빠진 것입니다.
- 증거 (재현, fake pfctl exec seam): `agents/a50/internal/firewall/review_a50_darwin_test.go`
  ```
  TestReviewA50_ExternalPfDisableWedgesKillSwitch:
    DisableKillSwitch after external pfctl -d: err=pfctl -X: exit status 1 (pfctl: DIOCSTOPREF: Invalid argument), IsKillSwitchEnabled=true
    calls on re-enable: []; pf kernel enabled=false
  TestReviewA50_RecoveryWithDeadTokenNeverEnablesPf:
    enable calls=[-si -sr] IsKillSwitchEnabled=true pfEnabled=false
  ```
- 실제 pfctl의 오류 문자열과 동작은 fake로 흉내 낸 것이라 실기기 확인이 필요합니다.
- 수정 방향:
  - 토큰이 있어도 `pfctl -si`로 Enabled 여부를 확인하고, 꺼져 있으면 토큰을 버리고 `-E`를 다시 실행합니다.
  - `-X`가 "토큰 무효"로 실패하면 토큰을 버리고 성공으로 처리합니다.
  - flush가 성공했다면 release 실패가 모델 갱신을 막지 않게 합니다.

**H-2. 재연결 backoff 중 helper가 유휴 종료 → wanted 터널과 KS가 조용히 사라짐**
- 위치: `helper/helper.go:898-960`. 유지 여부를 `manager.ActiveTunnel()`과 `pendingDesired`로만 판단합니다.
- 재연결 monitor는 `DisconnectTunnel`을 먼저 호출한 뒤 backoff합니다. 이 구간에서 터널은 `activeCfgs`에만 남습니다.
- 발생 조건:
  - socket-activated 또는 crash 후 재시작된 helper(15초 유예)가 복원 직후 wake로 재연결에 들어간 경우
  - GUI가 재연결 backoff 중에 종료된 경우(10초 유예)
- 영향: `cleanup()`이 desired-state를 비우고(`helper.go:1100`) firewall도 정리합니다. 사용자가 켠 VPN과 KS가 아무 알림 없이 사라지며, #44가 막으려던 결과와 같습니다.
- main에도 같은 유지 판단이 있었습니다(`origin/main helper.go:530-`). #53의 15초 활성화 유예가 노출 경로를 더했습니다.
- 증거 (재현): `agents/a53/internal/helper/zz_review53_test.go`
  ```
  TestReview53_WantedTunnelMidReconnectDoesNotKeepHelperAlive:
    REPRODUCED: helper shut down although tunnel "work" is still wanted (activeCfgs=map[work:...])
  ```
  desired 파일 삭제는 코드를 보고 추론했습니다.
- 수정 방향: 유지 조건과 타이머 발화 시 재검사에 `len(activeCfgs) > 0`과 `monitor.GetState().Reconnecting`을 추가합니다.

**H-3. 일반 시작에서 DNS 보호 설정이 복원되지 않음**
- 위치: `helper.go:534-548`. 원본 #50에는 `setDNSWanted(settings.DNSProtection)`가 있었습니다.
- 영향:
  - GUI가 연결 후 `SetDNSProtection(true)`를 다시 보내기 전까지 보호가 적용되지 않습니다.
  - CLI(`ctl connect`)나 GUI 없이 동작하는 경로(crash restore가 아닌 경우)에서는 설정이 켜져 있어도 보호가 아예 적용되지 않습니다.
  - "helper가 wanted 상태를 소유"한다는 #50의 목적이 반쯤 빠졌습니다.
- 증거: 코드로 확인했습니다. PR과 HEAD를 직접 대조했습니다.
- 수정 방향: settings를 복원할 때 dnsWanted를 설정하고, 이 동작을 고정하는 테스트를 추가합니다.

### Medium

**M-1. 상태 조회가 한 번 실패하면 살아 있는 터널의 KS 및 DNS permit이 제거됨 (faef4c8로 KS에 새로 생김)**
- 위치:
  - `helper/kill_switch.go:48-55`, `handlers.go:321-355`, `dns_protection.go:34-60`
  - 상태 원천은 `tunnel/manager_status.go:174-180`입니다. `getStatusForEngine`(wgctrl `Device()`)이 오류를 내면 `StateError`가 됩니다.
- 발생 조건: 5초 safety net tick에서 wgctrl/UAPI 질의가 한 번 실패함(예: 소켓 일시 오류).
- 영향:
  - kill switch: `RemoveKillSwitchTunnel(live utun)`이 실행되어 살아 있는 터널 트래픽이 최소 다음 tick까지 막힙니다.
  - DNS: 그 터널의 resolver permit이 빠집니다. 보호 대상 터널이 그것 하나뿐이면 규칙 전체가 제거되어 fail-open이 됩니다.
- 증거 (재현): `internal/helper/claude_review_transient_test.go` (리뷰 루트 복사본)
  ```
  TestClaudeReviewTransientStatusErrorDropsLiveKillSwitchPermit:
    live tunnel utun5 lost its kill-switch permit after one transient status error: removed=[utun5]
  TestClaudeReviewTransientStatusErrorDropsDNSProtection:
    live tunnel's resolver permit removed after transient status error: before=2 after=1
  ```
  실제 wgctrl 실패 빈도는 확인하지 못했습니다(추론).
- 수정 방향: 방화벽 permit 계산에는 wgctrl 질의 대신 manager 내부의 `state==Connected`와 `engine.InterfaceName()`을 쓰는 전용 API를 둡니다. `reconcileDisconnectFirewall`(State != Disconnected)과 판정 기준도 하나로 맞춥니다.

**M-2. legacy 재연결 루프에서 panic이 나면 connectMu가 영구히 잠김**
- 위치: `helper.go:724-747`. Lock과 수동 Unlock 사이에서 connect를 호출합니다.
- 영향: monitor가 panic을 recover한 뒤 deferred `resumeFirewall`이 connectMu를 기다리다 같은 goroutine 안에서 멈춥니다. 이후 모든 handler와 safety net이 멈춥니다. 체크리스트의 "every exit including panic" 주장과 어긋납니다.
- 증거 (재현): `agents/a50/internal/helper/review_a50_test.go`
  ```
  TestReviewA50_LegacyReconnectPanicLeaksConnectMu:
    recovered panic: boom in Connect
    resumeFirewall blocked on leaked connectMu (helper wedged)
  ```
- 수정 방향: 반복 본문을 `func(){ Lock; defer Unlock; ... }()`로 감쌉니다.

**M-3. signal 3초 상한이 cleanup을 잘라내고 fallback이 없음**
- 위치: `helper/signals.go:42-45`
- cleanup은 `monitor.Stop()`, `DisconnectAll`, `firewall.Cleanup()` 순서입니다. 앞의 두 단계만으로 3초를 넘기기 쉽습니다.
- 영향:
  - PF anchor(KS block-all)와 networksetup DNS override가 프로세스 종료 뒤에도 남습니다.
  - #53 이후 helper는 요청이 있을 때만 다시 뜨므로, 다음 앱 실행 전까지 네트워크나 DNS가 막힌 채 남을 수 있습니다.
  - launchd 기본값 20초보다 짧게 끊습니다.
- 증거: 코드 읽기로 확인했습니다. 원본 PR에는 상한이 걸린 `firewall.Cleanup()`과 `RestoreDNSBestEffort()` fallback이 있었습니다.
- 수정 방향: 시간 초과 시 상한이 걸린 firewall/DNS 정리를 실행한 뒤 종료합니다.

**M-4. macOS에서 KS와 DNS 보호를 함께 켜면 off-tunnel resolver로 가는 평문 DNS가 kill switch를 우회함**
- 위치: `firewall/dns_rules.go:82-88`, `darwin.go:445-451`
- 발생 조건: split 터널의 DNS가 AllowedIPs 밖(예: 1.1.1.1)이거나 Table=off인 상태에서 KS와 DNS 보호를 둘 다 켬.
- 영향: dns sub-anchor의 `pass out quick ... to 1.1.1.1 port 53`이 KS의 `block drop out all`보다 먼저 평가되어 물리 NIC로 나갑니다. Linux는 KS가 drop하므로 플랫폼 간 동작도 다릅니다.
- 증거:
  - 렌더 결과는 `TestReviewA50_KillSwitchPlusUnpinnedDNSPunchesHole`로 확인했습니다.
  - pf 평가 순서는 pf.conf(5)에 근거한 추론입니다.
- 수정 방향: 원본처럼 KS가 켜져 있으면 unpinned permit을 렌더링에서 뺍니다.

**M-5. pendingDesired만 남은 helper가 CLI에서 보이지 않음 (통합 과정에서 생긴 상호작용)**
- 위치:
  - `handlers.go:668` (`ActiveTunnels`가 manager만 봄)
  - `cli/lifecycle.go:111`과 `appRunning`/`activeTunnelCount`
- 영향:
  - `ctl stop`은 "not running"을 출력하고 RequestQuit 없이 exit 0으로 끝납니다.
  - `ctl disconnect`와 `ctl status`는 거부됩니다.
  - 이후 다음 wake나 네트워크 변경 때 VPN과 KS가 다시 올라옵니다. 사용자는 CLI로 이를 취소할 수 없습니다.
- 증거 (재현):
  ```
  TestReview53_PendingDesiredHelperInvisibleToCLI: helper alive with pending=map[work:{}] but reports GUIAttached=false active=[]
  TestReview53_StopIgnoresPendingRestoreHelper: ctl stop returned 0 ('not running') without RequestQuit
  ```
- 수정 방향: Ping이나 ActiveTunnels에 wanted/pending 정보를 넣고(IPC 1.3), CLI는 이를 실행 중으로 취급합니다.

**M-6. 혼합(global+split) DNS 진단이 실제 global 누수를 OK로 보고함**
- 위치: `diag/dnsleak_split.go:198-212`. split 터널 서버 IP를 global 검사의 기대 집합에 넣습니다.
- 발생 조건: split 서버가 LAN 공유기 IP(192.168.1.1)와 같은데 global override가 풀린 경우.
- 증거 (재현):
  ```
  TestReviewA51MixedGlobalLeakMaskedBySplitServerIP:
    leaked=false error="" servers=[{IP:192.168.1.1 IsVPN:true}]
  ```
- 같은 위치의 L-5도 함께 볼 것: 누수와 오류가 서로를 가립니다. CLI는 Error만 출력하고 GUI는 누락된 도메인을 숨깁니다(`TestReviewA51MixedLeakMaskedByErrorInCLI` 재현).
- 수정 방향: split 서버는 supplemental 블록에서만 허용하고, 기본 resolver에는 global 서버만 기대합니다. Leaked와 Error는 함께 표시합니다.

**M-7. 식별자가 "알 수 없음"인 네트워크에서 만든 수동 latch가 영구히 풀리지 않음**
- 위치: `helper/automation_state.go:206` (`identityKnown`), `:285-296`; `wifi/route_windows.go:10-16`
- 발생 조건:
  - Windows 유선: iface가 항상 ""이고 `IsWiFiInterface`가 항상 true라서 식별자가 늘 "알 수 없음"
  - macOS: Location 권한이 없어 SSID를 못 읽는 경우
- 영향: 유선 A에서 수동 Off 후 유선 B로 옮겨도 latch가 남아 "network=B → connect" 규칙이 영구히 막힙니다. 원본도 SSID만으로 식별해 같은 한계가 있었을 가능성이 높으므로, 회귀가 아니라 미해결 결함으로 분류합니다.
- 증거 (재현): `TestReview52_WindowsWiredLatchNeverClears` FAIL
- 수정 방향: SSID와 망 정보(MAC, 서브넷)를 나눠 비교합니다. 게이트웨이 MAC이나 서브넷이 알려져 있고 달라졌다면 SSID가 비어 있어도 "변경"으로 판정합니다.

**M-8. 같은 네트워크에 그대로 있는데 수동 Off가 풀림**
- 위치: `automation_state.go:126-128` (식별자에 subnet과 MAC 포함)
- 발생 조건: IPv6 SLAAC 프리픽스가 생기거나 사라짐. 또는 ARP가 비어 게이트웨이 MAC이 ""로 읽혀 15초 넘게 유지됨.
- 영향: latch가 해제되고 SSID 규칙이 사용자가 끈 터널을 다시 켭니다. "수동 Off 존중"을 직접 깹니다.
- 증거 (재현): `TestReview52_LatchClearedBySubnetChurnOnSameNetwork` FAIL
- 수정 방향: M-7과 같은 비교 함수로 고칩니다. IPv4 서브넷만 쓰거나 "겹치는 프리픽스가 하나도 없을 때만 변경"으로 봅니다. MAC이 ""이면 "알 수 없음"으로 처리합니다.

**M-9. 앱을 삭제해도 root 데몬과 socket listener가 남고, 명시 uninstall 경로가 없음**
- 근거: `git grep -i uninstall` 결과, macOS helper 제거 수단은 Homebrew cask `zap`뿐입니다. 앱과 CLI에는 uninstall이 없고 README에도 안내가 없습니다.
- 영향:
  - #53 이후에는 같은 uid의 어떤 프로세스든 비밀번호 없이 root helper를 띄웁니다. 앱이 실행 중일 때와 같은 RPC 표면이 열립니다.
  - Pre/PostUp은 무시되므로 root 코드 실행으로 이어지지는 않습니다.
  - 다만 업데이트되지 않는 옛 root 바이너리가 무기한 노출됩니다.
- 판단: orphan 자동 삭제를 제외한 것은 정당합니다. 그러나 체크리스트의 "Existing explicit uninstall remains"는 사실이 아닙니다.
- 수정 방향:
  - 명시적인 "Uninstall helper"(관리자 요청)를 제공합니다.
  - README에 제거 방법을 적습니다.
  - 파일은 지우지 않는 orphan 처리(여러 번의 활성화에 걸쳐 앱 부재가 확인되면 `bootout`만)를 검토합니다.

**M-10. Windows에서 DNS 필터 제거가 실패하면 재시도되지 않음 (#48 증상)**
- 위치:
  - `firewall/windows.go:1100`: 트랜잭션 전에 enabled=false로 바꿈
  - `windows.go:911`: commit 전에 ID를 nil로 바꿈
  - `helper/dns_protection.go:108-110`: backend 플래그만 보고 Disable을 생략
- 영향: 터널이 없는데도 53번 포트 block 필터가 남을 수 있습니다.
- 증거: helper 쪽 동작은 Windows 의미론을 흉내 낸 fake로 재현했습니다(`TestReviewA50_FailedDisableWithEagerFlagIsNeverRetried`: 5 tick 동안 disables=1). WFP backend 자체의 동작은 추론입니다.
- 수정 방향: 플래그와 ID는 commit이 성공한 뒤에만 갱신합니다. helper는 자기 journal로 "규칙이 남아 있을 수 있음"을 판단합니다.

### Low

| ID | 내용 | 근거 |
|---|---|---|
| L-1 | pf.conf marker 검사가 부분 문자열이라 `scrub-anchor "com.apple/*"`만으로 통과. `-sr` 실패 시 enable 실패 | `darwin.go:649`. `TestReviewA50_ScrubAnchorSatisfiesMarker` 재현 (`calls=[-si -sr -E]`, `-f` 없음) |
| L-2 | 자동 연결 터널의 wake 복구는 LAN overlap 검사를 하지 않음. skip 사유는 Info 로그로만 남음 | `helper.go:718-760`. `TestReview52_LegacyReconnectIgnoresLANOverlapForAutoTunnel` |
| L-3 | validator는 통과하지만 macOS scutil 길이 제한(2000B)으로 설치가 항상 실패하는 설정. 검색 도메인 상한 없음 | `TestReviewA51ValidatorAcceptsUninstallableSplitConfig` 재현 |
| L-4 | 다운그레이드한 바이너리가 config.json을 다시 쓰면 `per_tunnel_rules_v2`가 소리 없이 사라짐. 문서화 안 됨 | `TestReview52_DowngradeRoundTripDropsNegatedRules` |
| L-5 | 혼합 진단에서 Leaked와 Error가 서로를 가림 | M-6 참조, 재현 |
| L-6 | legacy 재시도 2회차부터는 teardown이 없는데도 매 시도마다 KS/DNS를 suspend/resume함 | `TestReview52_LaterLegacyAttemptsStillSuspendFirewall` 재현 (suspend 4회, teardown 1회) |
| L-7 | Windows에서 search domain을 아무 기록 없이 버림 | `network/windows.go:437-442` 코드로 확인 |
| L-8 | Windows의 `~` 설정이 연결 7단계에서야 실패(사전 점검 없음). 상세 패널은 "system DNS stays in place"라고 안내 | 코드 추론 |
| L-9 | socket-activated helper가 GUI 없이 desired 터널을 복원함. DESIGN.md:15의 "GUI까지 automation 휴면" 설명과 다름 | `TestReview53_ActivatedHelperRestoresTunnelsWithoutGUI` 재현. 정책 판단이 필요 |
| L-10 | split 정리 실패는 Warn 로그로만 남고, 5초마다 backoff 없이 재시도하며 경고를 반복 | `dns_cleanup.go:35`, 기존 테스트 `split_dns_test.go:191`이 nil 반환을 고정 |

---

## 4. 설계상 이견 (결함은 아니지만 판단 필요)

1. **suspend 실패 시 transport 유지(faef4c8).** KS disable이 계속 실패하면 재연결이 MaxAttempts까지 아무 진전 없이 반복됩니다. 보호를 유지하는 쪽으로 기운 것은 타당합니다. 다만 사용자에게 "보호 해제 실패로 재연결 불가"를 이벤트로 알려야 합니다.
2. **suspend 중의 KS/DNS 토글.** On/Off 요청이 즉시 성공으로 응답되고 resume 때 적용됩니다. reconnectFn이 오래 걸리는 동안 UI와 실제 상태가 어긋납니다. "pending" 상태를 표시할 필요가 있습니다.
3. **manual On의 transport repair 허용.** 타당합니다. 대가로 wake 때마다 규칙 소유 터널이 한 번씩 끊겼다 붙습니다(원본 #52가 피하려던 동작). 문서에 적어야 합니다.
4. **Windows `~` 설정은 Connect 실패.** 원칙(지원하지 않는 명시 DNS는 실패)은 타당합니다. 오류 시점은 import/validate 단계로 당기는 것이 이 프로젝트 방향(가져온 설정의 예측 가능한 동작)에 더 맞습니다.

---

## 5. 문서 주장과 실제의 불일치 (`docs/analysis/pr-adoption-checklist.md`)

| 주장 | 실제 |
|---|---|
| "#50 treat /1 pairs like /0 for automatic firewall policy" (원본 동작으로 서술) | 원본 PR도 /0(`IsFullTunnel`)만 사용. `OwnsDefaultRoute`는 원본과 HEAD 모두 쓰이지 않음 |
| "Existing explicit uninstall remains" | macOS 앱과 CLI에 uninstall 없음. cask zap뿐 |
| "Reconnect suspension, zero-tunnel blockade and every exit including panic" | legacy 루프의 panic이 connectMu를 누수시킴 (M-2) |
| "PF reference ownership ..." | 죽은 토큰과 외부 disable 처리가 빠짐 (H-1) |
| "Bounded graceful SIGTERM / SIGINT" | 상한만 있고 fallback cleanup이 없음 (M-3) |
| "Helper owns wanted DNS / kill-switch settings" | 일반 시작 시 DNS wanted 복원이 없음 (H-3) |
| "Preview peeks without resetting" | Peek은 맞지만 drift 시 실제 재평가를 띄울 수 있음 (`wifi_rules.go:348-376`) |
| windows-single-instance.md "helper teardown이 끝날 때까지 예약" | `handleShutdown`이 즉시 반환함 |

---

## 6. 최근 수정(513e161, faef4c8, adb9f5c) 평가

- **513e161 (기본 경로 대기 연결):** 근본 해결로 봅니다.
  - 시간 초과 시 계속 진행하는 원본 의미를 유지합니다(`automation_state.go:352-366`).
  - teardown 전으로 옮겨 작동 중인 transport를 보존합니다.
  - helper 잠금을 잡지 않아 수동 Off가 즉시 취소합니다(재현 테스트 PASS, 약 14µs).
  - per-tunnel 재시도와 시작 시 복원에는 대기가 없습니다. 의도된 설계로 문서와 일치합니다.
- **faef4c8 (suspend depth, KS intent, 재시도, panic cleanup):**
  - 중첩 suspend, 실패한 suspend의 rollback, explicit Off의 지속은 의도대로 동작합니다. 기존 테스트와 제 코드 검토가 일치합니다.
  - 그러나 새로 추가한 주기적 KS 재조정이 M-1(일시적 상태 오류로 permit 제거)을 KS에 새로 만들었습니다.
  - monitor 쪽 panic 정리만 다루고 helper legacy 루프의 panic(M-2)은 다루지 않았습니다.
- **adb9f5c (진단 오류 처리):** 열거 실패, resolver 0개, 무응답을 오류로 보는 방향은 타당합니다. 혼합 모드의 기대 집합 문제(M-6)는 별개로 남아 있습니다.

---

## 7. 병합 권고

**병합 차단 (main 전에 수정과 회귀 테스트 필요)**
- H-1, H-2, H-3
- M-1, M-2, M-3, M-5
- 체크리스트 문서의 사실 오류 정정(5절)

**병합 전에 고치기를 강하게 권함**
- M-4, M-6, M-7, M-8, M-10
- M-9: 최소한 README 안내와 문서 정정

**후속 issue로 넘겨도 됨**
- L-1 ~ L-10
- 4절의 설계 판단

수정할 때 각 항목의 재현 테스트(아래 경로)를 실제 테스트 스위트로 옮기면, 같은 누락이 다시 생기는 것을 막는 데 도움이 됩니다.

---

## 8. 실행한 명령과 결과

공통 환경 변수는 `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`이고, 모두 HEAD 복사본에서 실행했습니다.

| 명령 | 결과 |
|---|---|
| `go vet ./...` (루트 복사본) | 루트 패키지만 `frontend/dist` 없음(embed 대상, archive에 빌드 산출물이 없음). 나머지 깨끗함 |
| `go test -race -count=1 ./...` | 루트 패키지는 같은 이유로 setup 실패. app, diag, domain, elevate, firewall, gui, guiinstance, healthcheck, helper, ipc, launchd, network, reconnect, storage, tunnel, update, wifi 모두 ok |
| `go test -race -run TestClaudeReview -v ./internal/helper/` | M-1 재현 2건 FAIL |
| `go test -race -run TestReviewA50 -v ./internal/firewall/ ./internal/helper/` (a50) | H-1(2건), M-4, L-1, M-2, M-10 재현 출력 확인 |
| `go test -race -run ReviewA51 -v ./internal/diag/ ./internal/network/` (a51) | M-6, L-5, L-3 FAIL로 재현 |
| `go test -race -run TestReview52 -v ./internal/helper/ ./internal/reconnect/` (a52) | M-7, M-8, L-6 FAIL로 재현. L-2, L-4 로그 확인. preflight 취소 PASS |
| `go test -race -run TestReview53 -v ./internal/helper ./internal/cli` (a53) | H-2, M-5(2건), L-9 재현 |
| `WIREGUIDE_TEST_LAUNCHD=1 go test ... TestNativeSocketActivation\|TestLaunchdDemandLifecycle` (a53 에이전트가 실행) | PASS. gui/&lt;uid&gt; 사용자 도메인과 임시 디렉터리만 사용하는 것을 사전에 확인 |
| `GOOS=linux/windows go vet` (firewall/helper/network/tunnel) | 출력 없음 |
| `gh run view 38672451963` | headSha 68fdca0, 3 job 모두 success |

재현 테스트 파일 (모두 격리 복사본에만 있음):
- `wireguide-claude-review-20261015/internal/helper/claude_review_transient_test.go`
- `.../agents/a50/internal/firewall/review_a50_darwin_test.go`, `review_a50_nft_test.go`, `internal/helper/review_a50_test.go`
- `.../agents/a51/internal/network/zz_review_a51_darwin_test.go`, `internal/diag/zz_review_a51_test.go`
- `.../agents/a52/internal/helper/zz_review52_test.go`, `internal/reconnect/zz_review52_test.go`
- `.../agents/a53/internal/helper/zz_review53_test.go`, `internal/cli/zz_review53_test.go`

---

## 9. 검증하지 못한 범위

- 실제 sleep/wake, 실제 PF(다른 pf 사용자와의 공존, 실제 pfctl 오류 문자열과 토큰 동작). H-1은 fake exec seam으로만 재현했습니다.
- 실제 wgctrl/UAPI 일시 오류의 빈도 (M-1의 실제 발생률)
- 실제 mixed DNS 패킷 라우팅, scutil supplemental resolver 동작, systemd-resolved(버전별 default-route 의미)
- Windows 실기기: WFP 트랜잭션 실패(M-10), 단일 인스턴스 재실행 타이밍, 유선 식별자(M-7)
- launchd system 도메인과 root, SockPathOwner chown, `/var/run`의 0600 권한, 업그레이드 시 관리자 요청 횟수 (fixture는 사용자 도메인만 증명함)
- 프론트엔드 `npm run build`는 제가 실행하지 않았습니다. Svelte UI는 코드만 읽었습니다.
- main 대비 변경 중 #44/#45/#46/#49와 GUI 네이티브 트레이 작업은 PR 통합과 맞물리는 부분(desired state, watchdog, forced disconnect)만 봤습니다. 네이티브 트레이와 hang 진단 코드는 따로 리뷰하지 않았습니다.
