> Historical review of **6dcc6d5**, before F-1–F-3 were corrected.
> See [disposition](claude-review-disposition.md) for subsequent corrections.

# WireGuide 최종 재검토: 다섯 수정 (N-1~N-5)

- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5) + 이 대화의 맥락이 없는 독립 검토자 2명(g1: N-2/N-3, g2: N-4/N-1/N-5)
- 범위: N-1~N-5 다섯 수정과 그 직접 회귀. 이미 `docs/analysis/claude-review-disposition.md`에 보존된 낮은 우선순위 후속 항목은 다시 다루지 않습니다.

## 0. 검토 대상 고정

| 항목 | 값 |
|---|---|
| 최종 판정 기준 커밋 | **`6dcc6d5477017b4787b5ed44e297b4255025ac95`** (origin `fix/windows-single-instance`와 같음, working tree clean) |
| 포함 커밋 | `804b563` (N-2, N-3, N-4a), `c690492` (N-4b), `f8b4424` (N-1), `5a68ade` (N-5), `6dcc6d5` (문서) |
| 검토 시작 시점 스냅샷 | `c690492` + 미커밋 diff. 미커밋 diff의 sha256(`git diff`)은 `dc23f3a7…86d4`이고, 여기에 untracked 테스트 2개와 문서 1개가 더 있었음 |
| 동일성 확인 | 미커밋 코드 = `c690492` + `wireguide-n1-n5.patch` (파일 5개 `cmp` 동일). `git archive 6dcc6d5`와 스냅샷이 문서까지 동일 (`diff -rq` rc=0, `node_modules`, `dist`, `.claude` 제외) |

따라서 아래 결과는 모두 `6dcc6d5`에 그대로 적용됩니다. 실제 checkout, HEAD, 문서는 수정하지 않았습니다.

## 1. 결론

`6dcc6d5`는 아직 main 병합 전 수정이 필요합니다.

- 회귀 2건: 하나는 이번 수정 커밋(`804b563`)이 만든 Windows DNS 보호 회귀이고, 다른 하나는 Claude가 작성한 N-1 patch(`f8b4424`)가 만든 회귀입니다.
- 계약 누락 1건: N-2 계약의 일부입니다.

세 건 모두 수정 범위가 함수 한두 곳으로 작습니다. 이를 고치면 다섯 수정의 의도는 충족된다고 판단합니다. 원래 재현 테스트(A, B, N-2 세 경로, N-4 두 경로, N-1, N-5)는 모두 현재 계약 기준으로 해결된 것을 확인했습니다.

## 2. 병합 차단 항목 (재현됨)

### F-1 [High, Windows 전용, `804b563`이 만든 회귀] crash 복원된 full tunnel이 자동 DNS 보호를 잃음
- **위치:** `internal/helper/helper.go:1166`, `restoreUserSettings`의 `h.dnsAutoOff = !settings.DNSProtection`
- **원인:**
  - 기본 설정은 `dns_protection=false`입니다. 그래서 "한 번도 켜지 않은 사용자"가 "full tunnel에서 명시적으로 끈 사용자"로 바뀝니다.
  - 복원과 pending 재시도 경로는 `applyConnectedFirewall(cfg, false)`라서 이 값을 지우지 않습니다(`handlers.go:444-451`).
  - Windows에서는 `fullTunnelForcesDNSProtection`(`dns_protection.go:16`)이 `!autoOff`를 요구합니다.
- **영향:** Windows에서 helper crash 뒤 복원된 full tunnel이 자동 DNS 보호 없이 동작합니다(fail-open). `f0ead69`에서는 시작 시 이 값을 건드리지 않았고, 모든 full tunnel 연결이 지웠기 때문에 보호가 걸렸습니다. GUI는 config가 On일 때만 `SetDNSProtection`을 보내므로, 사용자가 다시 연결하기 전까지 복구되지 않습니다.
- **증거 (Claude 재실행):** `g1/internal/helper/zz_review_g1_test.go`
  ```
  TestReviewG1_WindowsRestoredFullTunnelLosesAutoDNS:
    restored needs DNS protection=false, fresh connect=true   FAIL
  ```
- **최소 수정:** 시작할 때 config로부터 `dnsAutoOff`를 유도하지 않습니다(`f0ead69`처럼 false로 시작). crash 전의 명시적 Off를 복원해야 한다면, journal에 그 사실(`dns_auto_off`)을 따로 저장해 복원합니다.

### F-2 [Medium, `f8b4424`(Claude 작성 N-1)이 만든 회귀] 오프라인에서 건 latch가 일부 환경에서 영원히 풀리지 않음
- **위치:** `internal/helper/automation_state.go:313` (enrich를 `l.unknown && st.identityKnown`으로 좁힘)
- **원인:** 오프라인에서 건 latch는 증거가 비어 있고 `unknown`입니다. 아래 환경에서는 `identityKnown`이 끝내 true가 되지 않아 채택이 일어나지 않습니다. `networkChanged(empty, X)`는 항상 false입니다.
  - Windows 유선: iface가 ""이고 `IsWiFiInterface`가 true이며 SSID가 ""
  - SSID를 얻을 수 없는 Wi-Fi: macOS 위치 권한 거부
- **영향:** 예를 들어 Windows 데스크톱에서 케이블이 빠진 상태로 터널을 끄면, 다른 네트워크로 옮겨도 그 터널의 자동화가 helper 재시작 전까지 동작하지 않습니다.
- **증거 (Claude 재실행):** `g2/internal/helper/zz_review_latch_test.go`의 `TestReviewLatchEdgeCases`
  - R1(Windows 유선: offline → A → B), R2(SSID 없는 Wi-Fi: offline → home → 다른 LAN)
  - HEAD에서는 `latch held = true, want false`
- **최소 수정 (g2 제안, Claude가 별도 사본 g4에서 검증):**
  ```go
  } else if l.unknown && l.evidence.empty() && !st.evidence.empty() {
      l.evidence = st.evidence
  }
  ```
  비교 기준이 완전히 빈 latch만 처음 안정된 관찰을 채택하므로, A→B→A 보호와 충돌하지 않습니다. 이 수정을 적용하면:
  - R1, R2 통과
  - `TestManualOffReleaseNeedsPositiveNetworkChange`(15개 시나리오), `TestManualOffNotReleasedOnReturnAfterIndistinguishableNetwork`, `TestUnknownLatchAdoptsFirstKnownNetwork`, `TestReview52_*`, `TestKnownGatewayDisappearanceDoesNotReleaseManualOff` 모두 통과
  - `go test -race ./internal/helper/` ok

### F-3 [Medium, N-2 계약 누락] config.json의 `kill_switch:false`가 journal의 KS On에 짐
- **위치:** `helper.go:1161-1167`. `restoreUserSettings`가 DNS만 읽고 KillSwitch는 읽지 않습니다.
- **발생 조건:** Linux/Windows에서 helper가 죽어 있는 동안 `ctl set killswitch off`를 실행합니다. config에는 저장되고 IPC는 실패합니다. 그 뒤 GUI가 `--restore-desired`로 helper를 다시 띄우면 restore가 KS를 켜고 journal에 다시 기록합니다.
- **영향:** 사용자가 명시한 Off를 무시하고 모든 트래픽을 차단합니다. 같은 커밋이 DNS에서 고친 시나리오의 KS 버전입니다. live IPC로 보낸 KS Off는 restore보다 우선합니다(정상).
- **증거 (Claude 재실행):** `TestReviewG1_ConfigKillSwitchOffVsJournal` → `wanted=true fw=true journal=true` FAIL
- **최소 수정:** `restoreUserSettings`에서 `settings.KillSwitch`로 `killSwitchWanted`와 `ksIntentKnown=true`를 설정합니다. 이렇게 하면 DNS와 KS의 On 방향 비대칭도 같이 정리됩니다.
- **같이 고칠 것 (Low-Med):** `loadUserSettings`는 config 파일이 없을 때도 기본값을 에러 없이 반환합니다. 그래서 `dnsIntentKnown=true`가 되어 journal의 DNS On이 버려집니다(`TestReviewG1_MissingConfigDropsJournalDNSOn` 재현). intent known은 config 파일이 실제로 존재하고 정상 파싱됐을 때만 설정해야 합니다.

## 3. 다섯 수정의 계약별 판정

| 수정 | 계약 | 판정 | 근거 |
|---|---|---|---|
| N-2 | live IPC로 보낸 DNS Off가 restore 전/중/후 모두 이김 | 충족 | `handlers.go:711`, `desired_state.go:494`. f1 재현 3건이 HEAD에서 PASS |
| N-2 | config DNS Off가 이김 | 충족 (config 없을 때는 F-3 부록) | 위와 같음 |
| N-2 | KS Off: live IPC | 충족 | `handleSetKillSwitch`가 connectMu를 잡음 |
| N-2 | KS Off: config | **미충족** | F-3 |
| N-2 | 복원은 dnsAutoOff를 지우지 않고, 새 연결은 지움 | 메커니즘은 맞으나 시작 시 유도 때문에 **회귀** | F-1 |
| N-3 | fire 뒤 재검사(Reset) | 충족 | `helper.go:964-968`. A 재현 PASS |
| N-3 | 실패한 connect, drop, 회수 시 idle arm | 충족 | `handlers.go:267,289`, `desired_state.go:306,321`. B는 원래 테스트가 300ms만 기다려 실패했음. 현재 계약(10초 grace) 기준 oracle `TestRepro_WithdrawPendingArmsIdleGrace` PASS (10.04초) |
| N-3 | `restoreInProgress`를 grace보다 먼저 설정하고, 모든 return에서 해제 | 충족 (panic 때 좁은 틈은 추론, low) | `helper.go:523-526`, `desired_state.go:405-412` |
| N-3 | 정상 흐름에서 helper가 남지 않음 / 필요할 때는 살아 있음 | 충족 | g1 확인. 락 순서 이상 없음 |
| N-4a | pending만 있는 터널의 disconnect가 성공 | 충족 | `handlers.go:503-511,557`. f2 재현 PASS (`err=<nil>`) |
| N-4b | status 텍스트와 JSON에 pending이 활성 터널과 함께 표시 | 충족 (표시 문구 low 회귀) | f2 재현 PASS(`○ work  waiting to reconnect`). D3 참고 |
| N-1 | iface 변경만으로 해제 안 함, A→B→A 보호, 같은 SSID 다른 공유기와 Windows 유선 이동 감지 | 충족 | 시나리오 테스트 통과 |
| N-1 | 현실적인 환경에서 영구 latch가 없음 | **미충족** | F-2 |
| N-5 | 세 진입점이 같은 기본 resolver 기준을 씀, 실제 누출 탐지, 거짓 OK 없음 | 충족 | `dnsleak.go:273`, `dnsleak_split.go:68,215`. 기본 resolver가 비면 OK가 아니라 Error(CLI exit 1, GUI ⚠). 이 Mac의 실제 `scutil --dns` 형식(`flags : Scoped`, `search domain[0]`)과 파서 가정이 일치함(g2, 읽기 전용 확인) |

## 4. 차단하지 않는 항목 (이번 수정 범위의 low, 또는 의도된 설계)

| ID | 내용 | 분류 |
|---|---|---|
| D3 | `c690492`: 연결 중이거나 해제 중인 활성 터널(manager가 `StateConnecting`으로 보고)도 "waiting to reconnect"로 표시됨. JSON에는 pending 행을 구분할 필드가 없음. 덧붙인 pending 행 이름만 따로 기억해 라벨을 붙이면 해결 | low, 표시 문제 회귀 |
| R3/R4 | ARP가 없던 상태에서 건 latch, 또는 다른 VPN이 기본 경로를 쥔 상태에서 건 latch는, 다른 SSID나 positive 증거를 볼 때까지 유지됨 | 의도된 보수적 trade-off. N-1 md에 기술. 영구적이지 않음 |
| P-1 | restore 중 panic하면 goSafe가 재시작하기 전(0.5~1.5초) `restoreInProgress=false` 구간이 생김 | low, 추론 |
| D4 | 실패한 disconnect가 이름 검증 전에 수동 Off latch를 남김(`handlers.go:479-481`) | 기존 결함, 범위 밖 |

N-5는 결함이 없었습니다. 남은 진단 한계(Linux stub resolver, 영역 표기 IPv6, 혼합 모드 GUI 배지)는 disposition 문서에 이미 보존돼 있습니다.

## 5. 검증 증거

| 항목 | 결과 |
|---|---|
| 스냅샷(= `6dcc6d5`) `go test -race -count=1 ./...` | 19개 internal 패키지 모두 ok (나머지는 테스트 파일 없음) |
| `go vet ./...` (darwin), `GOOS=windows go vet ./internal/...`, `GOOS=linux go vet` (firewall/diag/network/tunnel) | ok |
| `GOOS=windows go test -c` (firewall, helper) | ok |
| `npm run build` | ok |
| 이전 재현 테스트 재실행 (`6dcc6d5` 사본 g3, 이름 충돌만 바꿈) | A PASS. B는 현재 계약 oracle로 PASS. N-2 3건 PASS. N-4 2건 PASS |
| g1 재현 (`TestReviewG1_*`) | F-1, F-3, F-3 부록 FAIL (Claude 재실행). panic과 retry 관련 2건 PASS |
| g2 재현 (`TestReviewLatchEdgeCases`) | R1~R4 FAIL. F-2 수정 적용 후 R1, R2 PASS. R3, R4는 trade-off |
| CI `38684734157` (workflow_dispatch, headSha `6dcc6d5`) | Windows(test), macOS(test), Linux(test + package, binary/DEB) 모두 success. Claude가 `gh run view`로 확인. Codex가 내려받은 로그 기준으로 helper/cli/diag/firewall/tunnel이 3개 OS 모두 ok, FAIL과 DATA RACE 0건 |

CI 성공은 위 F-1~F-3을 잡지 못합니다. 해당 시나리오를 다루는 테스트가 없기 때문입니다. 그래서 CI 결과를 기능 완성의 근거로 쓰지 않았습니다.

재현 테스트 파일 위치(모두 격리 사본에만 있음, `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-final-review-20261015/` 아래):
- `g1/internal/helper/zz_review_g1_test.go`
- `g2/internal/helper/zz_review_latch_test.go`, `g2/internal/helper/zz_review_disconnect_test.go`, `g2/internal/cli/zz_review_status_unix_test.go`, `g2/internal/diag/zz_review_resolver_test.go`
- `g3/internal/helper/review_followup_repro_test.go` (+ 현재 계약 oracle)
- `g4/internal/helper/automation_state.go` (F-2 수정 검증본)

## 6. 실기기 미검증

- Windows: 실제 helper crash 뒤 `--restore-desired` 경로와 WFP DNS 필터(F-1의 실제 패킷 영향), 유선의 `GetBestRoute`/ARP 실제 값(F-2)
- macOS: 다른 VPN 사용 시와 0/1·128/1 full tunnel 사용 시 `route -n get default`의 실제 출력, 위치 권한 거부 상태의 SSID 동작
- 실제 sleep/wake, launchd socket activation의 15초 grace 동작, 실제 `scutil --dns` 변형(resolver #1에 `domain` 줄이 있는 형식 등)

## 7. 권고

1. F-1, F-2, F-3(부록 포함)을 고칩니다. 세 건 모두 함수 한두 곳 범위입니다. 위 재현 테스트를 리포 회귀 테스트로 옮깁니다.
2. D3(표시 문구)도 같이 고치면 좋지만 차단 사유는 아닙니다.
3. 그 뒤 3-OS CI를 다시 돌리면 다섯 수정 범위에서는 병합 가능하다고 판단합니다. 6절 항목은 릴리스 전 실기기 확인 목록으로 남겨야 합니다.
