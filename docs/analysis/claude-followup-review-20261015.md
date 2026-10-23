> Historical review of **f0ead69**, before the N-1–N-5 corrections. See
> [disposition](claude-review-disposition.md) for current resolution and limits.

# WireGuide f0ead69 재검토 (68fdca0 리뷰 후속)

- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5) + 이 대화의 맥락이 없는 독립 검토자 4명(f1~f4)
- 대상: `f0ead697751c70cd89b8a1674f5744bb78b0b7d1` (working tree clean 확인), `68fdca0..f0ead69` 커밋 6개, 53개 파일

| 커밋 | 내용 | 검토자 |
|---|---|---|
| 7c22284 | backend | f4 (Claude가 쓴 patch와 같아서 독립 검토로 분리) |
| 81f15f0 | lifecycle, snapshot, IPC | f1, f2 |
| a2064b6 | mixed DNS | f3 |
| f3e43e9 | identity, backup | f3 |
| 44f68e1 | preflight, backoff | f2 |
| f0ead69 | docs | Claude |

프로덕션 checkout, HEAD, 문서는 수정하지 않았습니다. 재현 테스트는 `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-claude-followup-20261015/{main,f1,f2,f3,f4}`(f0ead69 사본)에만 있습니다.

**독립성.** root가 작성한 영역은 이 대화의 이전 결론을 받지 않은 새 검토자에게 맡겼습니다. signal fallback, cached activeCfgs idle guard, lifecycle snapshot, default/supplemental DNS 검사, 부분 증거 기반 manual Off, downgrade backup, pending CLI stop, platform preflight가 여기에 해당합니다. 7c22284는 Claude 자신의 patch와 파일 단위로 같다는 것을 확인했고, 그래서 Claude가 아닌 새 검토자(f4)가 검토했습니다. 각 검토자에게는 계약과 대상만 주었고, 예전 증상 재현용으로 쓰인 테스트를 oracle로 쓰지 말라고 지시했습니다.

**Oracle 원칙.** 예전 결함을 보여 주려던 테스트가 지금 계약 방향으로 반전된 경우가 있습니다. 예를 들어 `TestReview52_WindowsWiredLatchNeverClears`는 이제 해제를 기대합니다. 이런 테스트의 성공이나 실패를 그대로 결함 판정에 쓰지 않았습니다. 아래 결함은 모두 "현재 의도한 계약"을 기준으로 새로 쓴 시나리오 테스트에서 나온 것입니다.

---

## 1. 결론

현재 상태로는 main 병합을 권하지 않습니다. 남은 결함은 모두 수정 범위가 작습니다.

68fdca0 리뷰의 High 3건과 Medium 10건은 핵심 경로에서 대부분 해결됐습니다. 특히 다음은 근거가 확실합니다.
- PF 토큰과 외부 disable 처리(H-1)
- 텔레메트리 실패와 무관한 방화벽 snapshot(M-1)
- panic-safe connectMu(M-2)
- Windows KS/DNS 단일 transaction(M-4, M-10)
- CLI stop의 pending 취소(M-5 핵심)

다만 프로젝트 핵심 약속인 "사용자의 수동 On/Off와 명시적 설정을 존중한다"를 깨는 경로가 테스트로 2건 재현됐습니다. 그 밖에 lifecycle과 CLI 쪽 결함이 몇 건 있습니다.

새로 찾은 결함 중 보호가 조용히 fail-open되거나 사용자가 원하는 터널이 사라지는 종류는 없습니다.

---

## 2. 68fdca0 High/Medium 재대조

| ID | 판정 | 근거 / 남은 문제 |
|---|---|---|
| H-1 PF 토큰·외부 disable | **해결** (작은 잔여 있음) | `pf_lease_darwin.go:42-58,112-149`, `darwin.go:677-716`. 가짜 커널 mutation이 테스트로 잡힘(f4). 잔여는 B-6, B-7 |
| H-2 재연결 중 helper 종료 | **해결, 단 반대 방향 결함 새로 생김** | arm 시점과 fire 시점에 activeCfgs와 pending을 함께 봄(`helper.go:910,940`). 대신 원하는 것이 없어진 뒤에도 helper가 종료되지 않는 경로가 생김(N-3) |
| H-3 시작 시 DNS intent | **부분** | 일반 시작은 해결(`helper.go:494`). crash restore가 명시적 Off를 덮어씀(N-2) |
| M-1 상태 snapshot | **해결** | `Manager.ConnectedInterfaces`(`manager_status.go:288`). 방화벽 판단 경로 8곳 모두 사용(f1이 확인). disconnecting 상태와 nil engine은 제외. 잠금 순서 이상 없음 |
| M-2 legacy panic | **해결** | `helper.go:720-747`의 closure 안에서 defer로 Unlock |
| M-3 signal fallback | **대체로 해결** | 3초 예산 안에서 종료됨. fallback은 정상 정리 경로와 같은 `opMu`를 쓰므로, 방화벽 호출이 멈춰 있으면 fallback도 효과가 없음(문서에 "best-effort, journal 필요"로 정직하게 적혀 있음). 정상 정리 예산이 2초로 줄어 fallback을 자주 탈 수 있음(아래 P-2) |
| M-4 KS에서 unpinned DNS | **해결** | macOS sub-anchor 축소, Windows는 같은 transaction에서 축소. Windows "pinned" permit도 인터페이스에 묶이지 않는 점은 기존 설계 한계(B-8) |
| M-5 pending CLI | **핵심 해결, 보고 결함 2건** | `ctl stop` → RequestQuit → cleanup이 desired 파일을 비움(f2). 남은 문제는 N-4 |
| M-6 혼합 DNS 진단 | **혼합 모드만 해결** | 전역 전용 경로는 여전히 scoped와 보조 resolver까지 검사해서, split 터널 유무에 따라 판정이 뒤집힘(N-5) |
| M-7 Windows 유선 latch | **해결** | 유선 A→B(MAC 다름, 또는 ARP 없이 GW IP 다름)에서 해제됨(f3 시나리오) |
| M-8 같은 망에서 Off 해제 | **부분** | ARP 누락, IPv6 churn, DHCP 갱신에서는 유지됨. 하지만 Wi-Fi→이더넷(같은 LAN)과, 늦게 채운 증거로 원래 망에 돌아올 때 해제됨(N-1) |
| M-9 uninstall 문서 | **해결** | README 안내가 cask `zap` 경로와 맞음. 이 절이 License 아래에 들어간 구조 문제는 Codex가 정리할 예정이라고 전달받음 |
| M-10 WFP transaction | **해결 (DNS 범위)** | `windows.go:910-942,1125-1143`. `RemoveKillSwitchTunnel`과 endpoint 필터 제거는 여전히 delete 실패를 무시함(B-9, 기존 결함) |

Low 항목 요약:
- **해결:** L-1, L-3(바이트 예산이 스크립트와 정확히 일치, 경계 테스트에서 불일치 0건), L-4(대체로), L-6(suspend 1회, teardown 1회), L-10(backoff가 있어도 utun 재사용은 즉시 정리)
- **부분:** L-2(N-6), L-7(경고가 `slog`에만 남음), L-8(아래 P-1)

---

## 3. 새로 확인된 결함

### 병합 전 수정 필요 (사용자 명시 의도 위반, 재현됨)

**N-1. [Medium] 같은 LAN에서 Wi-Fi→이더넷으로 바꾸면 수동 Off가 풀림. 늦게 채운 증거로 원래 망에 돌아올 때도 풀림**
- 위치:
  - `internal/helper/automation_state.go:344`: `a.Iface != b.Iface`만으로 changed를 반환
  - `automation_state.go:309-337`: `enrich`가 latch에 다른 망의 MAC을 채워 넣음
- 발생 조건:
  - 집에서 수동 Off를 한 뒤 노트북을 dock에 꽂아 이더넷으로 바뀜(SSID가 남아 있든 비어 있든)
  - SSID를 모르는 상태(위치 권한 거부, 유선)에서 A에서 Off를 걸고 같은 /24인 B를 다녀와 A로 복귀
- 영향: latch가 해제되어 "ssid=Home → connect" 같은 규칙이 사용자가 끈 터널을 다시 켭니다.
- 증거 (Claude 재실행): `f3/internal/helper/zz_review_latch_test.go`
  ```
  Wi-Fi -> Ethernet same LAN, SSID still assoc [expect hold] latch held=false
  Wi-Fi -> Ethernet same LAN, SSID blank [expect hold]       latch held=false
  A(no ARP) -> B -> A(ARP aa): released on A?                latch held=false  (FALSE RELEASE back on original network A)
  ```
  계약대로 동작하는 시나리오는 11개입니다. 같은 SSID 새 라우터, SSID 숨김, ARP 누락, DHCP 갱신과 IPv6, 오프라인 후 복귀, Windows 유선 4종 등이 여기에 해당합니다.
- 수정 방향:
  - iface 차이는 해제 근거에서 빼고, SSID·MAC·IPv4 서브넷 중 하나가 확실히 다를 때만 해제합니다.
  - `enrich`는 latch를 건 네트워크임이 확실할 때만 적용합니다. 예를 들어 같은 SSID이거나 같은 gateway IP이면서 같은 iface일 때입니다. 아니면 늦게 채운 MAC을 해제 근거로 쓰지 않습니다.
- 관련 (추론, OS 출력 미확인): 다른 VPN이 기본 경로를 가져가고 SSID를 모르면, utun peer gateway와 비교하다 해제됩니다. darwin과 linux에서 iface가 ""이면 "알 수 없음"으로 처리하면 막힙니다.

**N-2. [Medium] crash restore가 명시적 DNS 보호 Off를 덮어씀**
- 위치: `internal/helper/desired_state.go:483-487`. 비동기 restore가 시작 시 읽은 `intent.DNSProtection=true`로 `dnsProtectionWanted`를 무조건 덮고, 다시 영속합니다.
- 발생 조건:
  - `ctl set dns-protection off`가 config.json을 쓴 뒤 IPC가 실패(helper가 죽어 있음)하고, 이어서 restore가 실행됨
  - macOS socket activation 중 `SetDNSProtection(false)`가 restore 완료보다 먼저 처리됨
- 영향: config와 GUI는 Off인데 helper는 On을 적용하고 desired 파일에도 On으로 기록됩니다. 다음 토글 전까지 보이지 않는 불일치가 남습니다. IPC가 restore 뒤에 처리되는 경우는 문제없습니다(PASS).
- 증거 (Claude 재실행): `f1/internal/helper/review_followup_repro_test.go`
  ```
  TestRepro_RestoreOverridesConfigDNSOff: persisted={Tunnels:[alpha] ... DNSProtection:true}  FAIL
  TestRepro_RestoreOverridesLiveDNSOff:   persisted={... DNSProtection:true}                FAIL
  ```
- 수정 방향: restore가 config.json(이미 H-3으로 먼저 로드됨)이나 사용자 설정 갱신 세대를 우선하고, desired intent는 그보다 새로울 때만 적용합니다. `intent.KillSwitch`(`:491`)도 같은 패턴이라 함께 점검해야 합니다.

### 병합 전 수정 강력 권장 (작은 수정, 재현됨)

**N-3. [Medium] 원하는 것이 없어진 뒤에도 GUI 없는 helper가 종료되지 않음**
- 위치:
  - `helper.go:944-948`: fire 시점에 `pending+activeCfgs>0`이면 종료를 취소하고 타이머를 다시 걸지 않음
  - `handlers.go:259-271`: 첫 connect 실패 롤백에 `maybeArmShutdownAfterTeardown`이 없음
  - `desired_state.go:299-317`: pending을 비우는 경로(`withdrawPendingDesired`, load 실패 drop)에 arm이 없음. 이 부분은 81f15f0 이전부터 있던 결함
- 발생 조건: GUI 없이 grace 중에 connect가 진행되다 타이머가 fire하고 그 뒤 실패함. 또는 자동화가 pending restore를 회수함.
- 영향: 아무것도 원하지 않는데 root helper가 무기한 남습니다. "앱 없음 = root 프로세스 없음"이라는 설계와 어긋납니다. 연결이 끊기는 방향의 문제는 아닙니다.
- 증거: `TestRepro_FireAbortDuringConnectThenRollbackNeverShutsDown`, `TestRepro_WithdrawPendingNeverShutsDown` 모두 FAIL (Claude 재실행)
- 수정 방향: abort할 때 grace로 다시 arm합니다. 롤백과 회수 경로 끝에서 `maybeArmShutdownAfterTeardown`을 호출합니다.

**N-4. [Medium] M-5 CLI 보고 결함 2건**
- (a) pending만 남은 터널에 `ctl disconnect`를 하면 intent는 취소되는데 `tunnel "alpha" is not connected`, exit 1로 끝납니다(`handlers.go:495-552`). `withdrew`일 때 not-connected를 성공으로 처리해야 합니다. 기존 테스트가 이 에러를 `_, _ =`로 버려서 가리고 있었습니다.
- (b) 활성 터널이 하나라도 있으면 pending/backoff 터널이 `ctl status`(`--json` 포함)에서 사라집니다(`cli.go:263-273`). `WantedTunnels`에서 active를 뺀 나머지를 항상 출력해야 합니다.
- 증거: `TestReviewDisconnectPendingOnlyReportsError` FAIL, `TestReviewStatusHidesPendingWhenAnotherActive` FAIL (출력 `"● home ...\n"`만 나옴). 둘 다 Claude가 재실행했습니다.

**N-5. [Medium] 전역 DNS 터널만 있을 때 진단이 scoped와 보조 resolver까지 검사함 (M-6 수정이 혼합 분기에만 적용됨)**
- 위치: `diag/dnsleak_split.go:177-178` → `dnsleak.go:264-289`
- 증거 (Claude 재실행): 같은 resolver 상태에서
  ```
  전역만: leaked=true  probed=[10.0.0.53 100.100.100.100 192.168.1.1]
  혼합:   leaked=false probed=[10.0.0.53]
  ```
  다른 앱의 보조 resolver(예: Tailscale 100.100.100.100)나 scoped LAN resolver 때문에 LEAK로 오탐합니다.
- main에도 있던 동작이지만, 이제 split 터널 유무에 따라 판정이 뒤집히는 불일치가 생겼습니다.
- 수정 방향: darwin에서는 전역 전용일 때도 파싱한 비-scoped 기본 블록만 검사합니다.

### 후속으로 넘겨도 되는 항목

| ID | 심각도 | 내용 | 근거 |
|---|---|---|---|
| N-6 | low-med | L-2: LAN overlap으로 건너뛸 때 로그나 이벤트가 없음. desired state에 소유자 정보가 없어 helper 재시작 뒤 pending restore에는 overlap 검사가 적용되지 않음 | f3 `TestReview_L2` (logs="") |
| P-1 | low | Windows split-DNS connect에서 플랫폼 preflight보다 `doConnectHeld`의 KS 해제가 먼저 일어남. 어차피 실패할 connect인데도 KS가 잠시 내려감 | 코드 확인 (`handlers.go:244-260`) |
| P-2 | low | signal: 정상 정리 예산이 2초라 `monitor.Stop`(최대 5초)과 IPC Shutdown(3초) 때문에 fallback으로 자주 감. 강제 종료도 exit 0 | f1 추론 |
| P-3 | low | restore 진행 중 시작 grace 공백. 롤백과 pending 등록 사이에 타이머가 fire하면 intent를 잃음 | f1 추론, 좁은 창 |
| D-1 | low | `flags : Scoped`나 영역 표기 IPv6(`fe80::1%en0`)를 파서가 무시함(기존). 혼합 모드 GUI에서 "safe"인데 scoped LAN resolver에 "!" 배지가 표시됨 | f3 |
| D-2 | medium, 기존 | Linux systemd-resolved stub(127.0.0.53)이 응답해서 전역 진단이 항상 LEAK | f3 `TestReview_StubResolverIsLeak` |
| L4-x | low | 백업 쓰기가 실패하면 관계없는 설정 저장까지 실패함. 재업그레이드 뒤 새 부정 규칙을 저장하면 다운그레이드 전 백업을 경고 없이 덮어씀. 백업 경고가 GUI에 안 보임 | f3 |
| B-6 | low-med | PF가 외부에서 `-d` 된 뒤 다른 도구가 `-E`를 하면, pf가 실행 중이라 죽은 토큰을 계속 믿음. 그 도구가 `-X`를 하면 repair까지 최대 5초 동안 KS가 적용되지 않음. `pfctl -s References`로 토큰 생존을 확인하면 해결 | f4 R1 재현 |
| B-7 | low | enable마다 `-si`를 실행하므로 일시적 실패로 DNS 재적용이 실패하고 backoff함(보호 자체는 유지됨) | f4 R2·R3 |
| B-1 | low (테스트) | helper 5초 루프에서 `repairFirewallEnforcement()` 호출을 지워도 테스트가 통과함. Claude가 작성한 테스트가 함수를 직접 부르기만 함. tick 본문을 함수로 빼서 테스트해야 함 | f4 mutation |
| B-5 | low | Repair에 backoff가 없음. pf.conf가 깨져 있으면 5초마다 pfctl을 실행하고 connectMu를 점유함 | f4 추론 |
| B-8 | low, 설계 | Windows KS 모드에서도 pinned DNS permit에 LUID 조건이 없어서, 물리 NIC에 바인딩한 앱이 그 IP의 53번으로 나갈 수 있음 | f4 추론 |
| B-9 | low, 기존 | `RemoveKillSwitchTunnel`과 endpoint 필터 제거가 delete 실패를 무시하고 commit함 | f4 |
| C-1 | low | 옛 1.2 CLI와 새 helper 조합에서 headless pending 상태일 때 `ctl stop`이 "not running"으로 끝남. 동봉 배포라 영향 작음 | f2 |

---

## 4. 반대 방향 테스트와 공백

- `TestReview52_WindowsWiredLatchNeverClears`는 해제를 기대하도록 바뀌었지만, latch 해제를 직접 assert하지 않고 `t.Logf`만 남깁니다. 규칙 동작 로그 문자열에 의존합니다.
- L-2와 L-6에는 리포에 회귀 테스트가 없습니다. 원래 리뷰가 L-6 근거로 든 `TestReview52_LaterLegacyAttemptsStillSuspendFirewall`은 사본에만 있었습니다. 현재 동작이 맞다는 것은 f3가 별도 테스트로 확인했습니다(attempts=4, suspends=1).
- `TestHandleDisconnect_WithdrawsPendingTunnel`은 에러를 버려서 N-4(a)를 가립니다.
- `claude_followup_test.go`는 helper를 살려 두는 방향만 확인하고, 원하는 것이 사라진 뒤 종료하는지는 확인하지 않아 N-3을 잡지 못합니다.
- B-1의 helper 연결 테스트 공백도 같은 종류입니다.

---

## 5. 실행한 명령과 결과

공통 환경 변수는 `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`이고 모두 f0ead69 사본에서 실행했습니다.

| 명령 | 결과 |
|---|---|
| `git rev-parse HEAD`, `git status --short` | f0ead69, 변경 없음 |
| 7c22284와 Claude patch 파일 비교 | 14개 파일 모두 동일 |
| `go vet $(go list ./internal/...)` (darwin), `GOOS=windows go vet ./internal/...` | 출력 없음 / rc=0 |
| `GOOS=windows go test -c ./internal/firewall` | ok |
| `go test -race -count=1 ./internal/...` | 19개 패키지 모두 ok |
| `npm run build` (사본, node_modules 복사) | 211 modules, built ok |
| 루트 패키지 `go vet .`, `go build .` (dist 생성 뒤) | ok (테스트 파일 없음) |
| `gh run view 38682595855` | headSha f0ead69. Windows(test), macOS(test), Linux(test+package) 모두 success. Windows job은 `-v` 없이 `go test ./...`만 돌려서 개별 테스트 이름은 로그에 없지만, `internal/firewall` ok에 windows 전용 WFP 테스트가 포함됨(Skip 없음) |
| f1 `go test -race ./internal/helper ./internal/tunnel ./internal/reconnect`, `-run TestRepro_` | 기본 ok. 재현 4건 FAIL (Claude 재실행으로 확인) |
| f2 `go test -race ./internal/{cli,ipc,config,tunnel,network}`, 경계와 재현 테스트 | 기본 ok. 바이트 예산 불일치 0건. N-4 2건 FAIL (Claude 재실행) |
| f3 `go test -race ./internal/{diag,helper,wifi,storage,reconnect}`, `-run TestReview_` | 기본 ok. N-1, N-5 재현 (Claude 재실행) |
| f4 `go test -race ./internal/{firewall,helper}`, Windows/Linux vet, mutation C/D/E | ok. mutation D·E는 테스트가 잡고, C(helper 연결 삭제)는 통과함(B-1) |

재현 테스트 파일 위치:
- `f1/internal/helper/review_followup_repro_test.go`
- `f2-review-tests/*`
- `f3/internal/{diag,helper,storage,reconnect}/zz_review_*_test.go`
- `f4/internal/firewall/zz_review_repro_darwin_test.go`

---

## 6. 실기기에서 확인하지 않은 범위

- macOS PF 실제 동작: `pfctl -X`의 실제 출력과 exit code, `-d`가 토큰을 무효화하는지, 다른 도구와의 refcount 공존(B-6), 외부 `pfctl -d` 뒤 5초 안에 복구되는지
- Windows WFP 커널: transaction 실패 주입, FILTER_NOT_FOUND의 실제 동작, 물리 NIC 바인딩으로 DNS를 우회할 수 있는지(B-8). CI의 Windows 테스트는 가짜 WFP를 통한 전이 검증일 뿐, 패킷 경로 검증은 아님
- 실제 sleep/wake, launchd system 도메인의 socket activation, 업그레이드 시 관리자 요청 횟수, 실제 SIGTERM 정리 시간
- 실제 `scutil --dns` 출력 형태(scoped 블록, `flags`, 영역 표기 IPv6), systemd-resolved 버전별 동작, 혼합 DNS 패킷 경로
- macOS에서 다른 VPN이 기본 경로를 가져갔을 때 `route -n get default`의 실제 출력(N-1 관련)
- Wi-Fi/이더넷 전환이나 dock 연결 시 실제 probe 값(N-1)

## 7. 병합 권고

- **main 병합 전에 고쳐야 할 것:** N-1, N-2 (사용자 명시 의도 위반)
- **같이 고치면 좋은 것:** N-3, N-4, N-5. 모두 수정 범위가 작고 재현 테스트가 있습니다.
- 위 항목을 고친 뒤 재현 테스트를 리포 회귀 테스트로 옮기고, native 3-OS CI를 다시 돌리면 병합 판단에 충분하다고 봅니다.
- 실기기 항목(6절)은 릴리스 전 수동 검증 목록으로 남겨야 합니다.
