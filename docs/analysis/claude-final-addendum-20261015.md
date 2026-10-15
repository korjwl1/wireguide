> Subsequent macOS native checks: see [execution report](macos-native-verification-20261015.md).
> The historical review below predates that run; its remaining-check list is
> narrowed by the new report, not considered fully closed.

> Codex verification after this review: CI [38686094150](https://github.com/korjwl1/wireguide/actions/runs/38686094150)
> completed successfully on **48b5c92755f451498897c0e41a3baa7075827b4b**.
> Windows, macOS and Linux jobs all passed, including Linux binary/DEB packaging.
> This satisfies the CI condition in Claude’s conclusion below. Target-machine
> checks and the explicitly deferred findings remain outstanding.

# 최종 리뷰 addendum: `48b5c92` 기준

- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5), 직접 검토 (추가 검토자 없음)
- 범위: 최종 리뷰의 F-1, F-2, F-3, config 부록, D3 수정과 그 직접 회귀. 이미 보존된 낮은 우선순위 항목은 다시 감사하지 않았습니다.

## 0. 검토 대상

| 항목 | 값 |
|---|---|
| **판정 기준 커밋** | **`48b5c92`** (root working tree clean, push 완료로 전달받음) |
| `6dcc6d5` 이후 커밋 | `5957ece` (helper: 저장된 설정과 명시적 firewall intent 구분), `3f4f5b0` (F-2), `95ecc24` (D3), `48b5c92` (문서) |
| 검토 경로 | 1) root의 미커밋 diff(`6dcc6d5` + sha256 `4e42…030d` + untracked 테스트 1개)를 스냅샷으로 떠서 전체 검토 2) 커밋된 `48b5c92`와 그 스냅샷의 차이를 직접 대조 3) `48b5c92`를 `git archive`한 사본(`/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-final-addendum-20261015/h48`)에서 재검증 |
| 스냅샷 대비 차이 (코드) | `helper.go`: `ksRestoreOn` 필드 추가. config `kill_switch:true`는 `ksRestoreOn`에만 기록하고, `false`일 때만 `killSwitchWanted=false`, `ksIntentKnown=true`로 설정 <br> `desired_state.go:505`: `(intent.KillSwitch \|\| h.ksRestoreOn) && !h.ksIntentKnown` <br> `handlers.go:451`: 새 full-tunnel connect에서 `dnsIntentExplicit=true` <br> 테스트 추가 |

root는 읽기만 했습니다.

## 1. 결론

**`48b5c92`에서 다섯 수정 범위에 남은 병합 차단 항목은 없습니다. 3-OS CI(`38686094150`)가 녹색이면 main 병합을 권합니다.**

검토 중 스냅샷에서 회귀 하나(G-1)를 찾았습니다. config `kill_switch:true`만으로 터널 없이 helper가 시작될 때 KS blockade가 설치되는 문제였습니다. 이것은 `5957ece`에서 이미 해결됐고, `48b5c92`에서 같은 재현 테스트가 PASS하는 것을 직접 확인했습니다.

## 2. G-1의 경과 (해결됨)

**재현:** 스냅샷(미커밋 diff)에서 config `{"kill_switch":true}`로 일반 시작한 뒤 safety net의 `reconcileKillSwitch(false, now)`를 실행했습니다.
```
killSwitchWanted=true ksIntentKnown=true firewall KS enabled=true   → FAIL
```
같은 테스트가 `6dcc6d5`에서는 PASS(차단 없음)였습니다. GUI는 KS를 연결이 성공한 뒤에만 적용합니다(`App.svelte:583-590`). 따라서 시작 즉시 차단은 기존 제품 동작에서 벗어나는 회귀였습니다.

**`48b5c92` 확인:**
- `restoreUserSettings`는 config On을 `ksRestoreOn`에만 기록하고, 현재 `killSwitchWanted`는 바꾸지 않습니다. config Off는 즉시 알려진 거부권으로 적용합니다.
- `ksRestoreOn`을 읽는 곳은 `restoreDesiredTunnels:505` 한 곳뿐입니다(`git grep`으로 확인). 이 지점은 다음 확인을 모두 통과한 뒤에만 도달합니다:
  - 복원할 이름이 있음(`:422`)
  - `restoreOnStart`(`:433`)
  - 같은 boot(`:444-461`)
  - tunnel store 있음(`:470`)
- connect 전에 KS를 reconcile합니다.
- 결과: 같은 재현 테스트 `TestAddendum_StartupWithSavedKillSwitchAndNoTunnel`이 PASS합니다(`killSwitchWanted=false ksIntentKnown=false firewall KS enabled=false`). root의 `TestFirewallRecovery_SavedKillSwitchDoesNotBlockIdleStartup`(restoreOnStart false/true, 터널 없음)도 PASS합니다.

## 3. 수정별 판정 (`48b5c92`)

| 항목 | 판정 | 근거 |
|---|---|---|
| F-1: 기본값 DNS false가 `dnsAutoOff`를 초기화하지 않음 | 충족 | `TestFirewallRecovery_WindowsRestoredFullTunnelLosesAutoDNS` PASS |
| F-1: 명시적 Off를 journal `dns_auto_off`로 따로 저장하고, live 갱신이나 새 full connect가 없을 때만 재생 | 충족 | `desired_state.go:499`(`!dnsIntentExplicit`), `handlers.go:451,716`. `DNSAutoOffJournalAndLiveUpdate`, `PersistsExplicitDNSOffSeparatelyFromDefault`, `NewFullConnectWinsOverSnapshottedAutoOff` PASS |
| F-2: 증거가 빈 unknown latch의 첫 관찰 채택 | 충족 | `3f4f5b0`. `TestOfflineManualOffAdoptsFirstPositiveNetworkEvidence` PASS. A→B→A와 15개 시나리오, `TestReview52_*`, `TestKnownGatewayDisappearance…` PASS |
| F-3: config KS Off가 journal KS On을 이김 | 충족 | `ConfigKillSwitchOffVsJournal` PASS |
| F-3: config KS On은 복원 시 connect 전에 적용하되, 유휴 시작은 차단하지 않음 | 충족 | `ConfigKillSwitchOnProtectsBeforeRestoreConnect`, `SavedKillSwitchDoesNotBlockIdleStartup`, G-1 재현 테스트 PASS |
| config 부록: 파일, 키, 파싱이 없거나 실패하면 journal 유지 | 충족 | `MissingConfigDropsJournalDNSOn`, `MissingFieldsDoNotOverrideJournal` PASS. 읽는 경로가 `loadUserSettings`와 같은 `userAppSupport/config.json`임을 확인 |
| D3: 덧붙인 pending 행만 "waiting to reconnect", 활성 전환 중인 행은 "connecting" | 충족 | `95ecc24`. `TestStatusShowsPendingAlongsideActive`(텍스트/JSON × connecting 여부, 4가지 조합) PASS. JSON 스키마는 변경 없음 |

**설계 메모 (차단 아님):** config KS On + 같은 boot crash 복원이면, crash 전 세션에서 KS가 실제로 적용되지 않았더라도(예: CLI로만 연결한 경우 GUI의 연결 후 적용이 없었음) 복원 시 KS를 켭니다. 저장된 사용자 설정을 우선하는 의도된 정책이고 보호를 늘리는 방향이라 수용 가능합니다.

## 4. 실행한 명령과 결과 (`48b5c92` 사본)

공통 환경 변수는 `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`입니다.

| 명령 | 결과 |
|---|---|
| `go test -race -count=1 -run 'TestAddendum\|TestFirewallRecovery\|TestOfflineManualOff\|TestStatusShowsPending\|TestManualOff\|TestUnknownLatch\|TestKnownGateway\|TestReview52' ./internal/helper ./internal/cli` | 18개 모두 PASS (G-1 재현 테스트 포함) |
| `go test -race -count=1 ./internal/...` | 19개 패키지 모두 ok |
| `go vet $(go list ./internal/...)` (darwin), `GOOS=windows go vet ./internal/helper ./internal/cli` | ok |
| 이전 스냅샷 `go test -race ./internal/...` (G-1 재현 테스트 제외) | 19개 모두 ok (참고) |
| `gh run list` | `38686094150` (headSha `48b5c92`) in_progress. 결과는 아직 미확인. 직전 `38684734157` (`6dcc6d5`)은 success |

## 5. 남은 사항

- **CI:** `38686094150`의 3-OS 결과를 아직 확인하지 못했습니다. 녹색이면 위 결론이 성립합니다.
- **실기기 미검증 (이전 최종 보고서 6절 그대로):**
  - Windows crash 복원 경로와 WFP DNS 필터
  - macOS에서 다른 VPN이나 full tunnel을 쓸 때 기본 경로 출력, 위치 권한 거부 상태의 SSID
  - sleep/wake, launchd socket activation grace
- **보존된 low 항목:** `docs/analysis/claude-review-disposition.md`에 기록된 후속 항목은 이번 범위 밖이며 차단 사유가 아닙니다.
