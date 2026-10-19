# core 수정 재검토: `632d7c4`

> 이 문서는 해당 스냅샷의 당시 리뷰 기록입니다. 후속 수정 판정은 [최종 재검토](claude-quality-final-followup-20261015.md)와 [작업 결과](code-quality-review-20261015.md#독립-리뷰-반영과-최종-검증)를 기준으로 확인하세요.
- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5) 직접 검토. 추가 에이전트는 쓰지 않았습니다.
- 대상: `632d7c47a85d2ca5922028d44897c68b94ada7e5`. 직전 검토 기준 `576ae84` 이후 커밋 5개(`dd05810`, `bcbab6b`, `7910800`, `470c900`, `632d7c4`), 49개 파일 +1099/−361.
- 실행 위치: `git archive` 사본 `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-core-632d7c4/{base,rep}`. root 작업 트리는 읽기만 했습니다.
- 제약 준수: 실제 VPN, 설치된 앱, OS 설정은 바꾸지 않았습니다. HOME도 바꾸지 않았습니다. q1 재현 테스트의 `t.Setenv("HOME")`는 사본에서 `userPaths` seam으로 바꾼 뒤 실행했습니다. Go 임시 파일과 캐시는 모두 SSD에 썼습니다.

**이전 보고서 표현 정정:** 원 보고서의 "사용자가 공간을 확보했다"는 표현은 정확하지 않습니다. 정확히는 Codex가 이 작업에서 남은 비활성 검증 바이너리 11개를 외장 SSD로 보존 이동한 것입니다. 사용자 파일, 다른 프로젝트, 실제 앱 백업은 건드리지 않았습니다.

## 1. 결론

- **이번 수정의 대상 결함은 모두 원래 반례 기준으로 해결됐습니다:** H-S1, H-G1, H-N1, M-H1, M-H2, M-H4, M-H5, M-F1, M-I1~M-I4, L-H1, L-G5. 재현 테스트가 지금 계약 방향을 따르지 않는 경우에는 현재 계약에 맞는 oracle을 새로 써서 확인했습니다(2절).
- **새 병합 차단 항목은 없습니다.**
- **남은 사항:** 이번 수정 범위 안에서 새로 찾은 낮음~중간 반례가 3건 있습니다(3절). 이 외에 아직 수정 중이라고 하신 항목은 실패로 단정하지 않고 5절에 따로 적었습니다.

## 2. 수정별 검증

| ID | 판정 | 근거 |
|---|---|---|
| **H-S1** root 경로 보안 | 해결 | 아래 2.1 |
| **H-G1** macOS 종료 정리 | 해결 | 아래 2.2 |
| **H-N1** DNS 복원 오류 은닉 | 해결 (잔여 1건은 3절 C-1) | q3 재현 2건 PASS. `restoreServiceDNS`가 모든 서비스를 끝까지 시도하고 `errors.Join`으로 실패를 반환함. 호출부(`connect_phases.go:426`, `recovery.go:238-252`, `manager_dns.go:131`)는 오류를 받아도 teardown을 중단하지 않으므로, 오류 전파로 인한 새 회귀는 없음 |
| **M-H1** 연결 중인 터널 종료 | 해결 | q3 재현: 취소된 연결이 `connect cancelled mid-phase`로 끝나고 `IsTunnelConnected=false`. entry의 cancel과 done 채널, Phase 3의 `ctx.Err()` 재확인(`manager.go:368,403`), `DisconnectAll`의 선취소, `cleanup()`이 `h.done`을 닫은 뒤 `connectMu` 아래에서 `DisconnectAll` 무조건 호출. `handleConnect`, restore, automation 모두 `operationContext()`라 종료 시 취소되므로, 종료가 연결 완료를 오래 기다리지 않음. 테스트의 가짜 단계는 ctx를 무시해서 DisconnectAll이 10초 대기하지만, 커밋은 거절됨 |
| **M-H2** ForceShutdown과 reconcile 경쟁 | 해결 | q3 원래 테스트는 이전 핸들러(직접 `firewall.Cleanup()`)를 흉내 내므로 oracle로 맞지 않음. 새 oracle `TestCoreFollowupCleanupThenTickDoesNotReinstall`: `h.cleanup()`과 `reconcileFirewallTick`을 200회 동시 실행 → kill switch 재설치 0회, `-race` 통과. tick이 `connectMu` 아래에서 `h.done`을 재확인함(`dns_protection.go:142-148`) |
| **M-H4** desired-state 덮어쓰기 | 해결 | q3 재현 PASS(`in-memory wanted=0, on-disk wanted=[]`) |
| **M-H5** 규칙 해제 뒤 캐시 | 해결 | q3 재현이 "fixed" 사유로 SKIP(테스트가 수정을 감지) |
| **M-F1** PF 참조 journal | 해결 (잔여 low는 3절 C-3) | q3 재현 PASS. `enablePf`와 `persistPfEnabledState`가 메모리 토큰이 비어 있으면 디스크 lease를 먼저 읽음. 살아 있는 이전 참조는 새 helper가 넘겨받아 해제하고, 죽은 참조는 기존 검증으로 버림 |
| **M-I1/M-I2** CLI rename, set | 해결 | q1 재현(HOME 대신 `userPaths` seam): incompatible → `exit=1 alphaExists=true betaExists=false`, hung → 15초 뒤 exit=1·파일 그대로, `set killswitch` → exit=1 |
| **M-I3** 느린 RPC를 장애로 오인 | 해결 | q1 원래 테스트는 이전 방식(제어 연결 ping)을 흉내 내므로 oracle로 맞지 않음. 새 oracle `TestCoreFollowupProbeSucceedsDuringSlowControlRPC`: 3초 걸리는 제어 RPC 중에도 `ProbeHelper`(transient 연결) 성공, 제어 연결 유지, 사용자 RPC 성공. 헬퍼 쪽 `HasControlConn` 유지 |
| **M-I4** 백그라운드 복구의 권한 상승 | 해결 | `recoveryDial`이 모든 OS에서 `reconnectHelper`만 사용(`helper_lifecycle.go:350-351`). q1 원래 테스트는 설치 경로 `ensureHelperWith`를 직접 부르므로(설치 경로의 업그레이드는 정상) oracle로 맞지 않음 |
| **L-H1** watchdog 차단 영속 | 해결 | q3 재현 PASS |
| **L-S5** rename 고아 메타 | 해결 (부수 효과) | q2 재현: 고아 메타가 붙지 않고 rename 성공 |

### 2.1 H-S1 상세

**확인한 설계**
- `NewUserTunnelStore`는 "/"부터 구성요소마다 `os.Root` 핸들로 내려갑니다.
  - Unix 중간 구성요소는 소유자가 uid 또는 root여야 하고, root 소유가 아닌 symlink는 거부합니다.
  - 최종 디렉터리는 소유자가 uid여야 합니다.
- 파일은 `Root.OpenFile(O_NOFOLLOW|O_NONBLOCK)`로 열고, 일반 파일인지와 소유자를 확인합니다.
- 쓰기는 같은 Root 안에서 temp → rename으로 게시합니다(`atomicfile.WriteInRoot`).
- `Lstat`과 `OpenRoot` 사이에 항목이 바뀌어도(TOCTOU) `os.Root`가 현재 root 밖으로 나가지 못하게 하므로, 사용자 자신의 영역 안에 갇힙니다.
- Windows: Go 1.26 `os.Root`는 junction을 포함한 name-surrogate reparse point를 root 안에서만 해석합니다(`root_windows.go:231`, `isLink:424-427`).
- helper가 사용자 저장소에 하는 작업은 Rename과 Delete뿐이라, 파일 소유자가 root로 바뀌지 않습니다.
- 현재 설치본 `930dc4a`의 helper는 `.imports.lock`을 만들지 않았으므로(import 경로는 GUI 전용), 업그레이드 후 root 소유 lock 때문에 GUI가 막히는 경로가 없습니다.

**새 oracle** (`rep/internal/storage/zz_core_userstore_test.go`, 모두 PASS)
- `tunnels`가 사용자 소유 symlink이면 Delete와 Rename이 거부되고, 외부 파일과 lock이 생성되지 않습니다.
- 사용자 소유 중간 경로 symlink를 거부합니다.
- 파일 symlink를 Load하면 내용이 노출되지 않습니다. symlink와 하드링크를 Delete하면 항목만 지워지고 대상 파일은 남습니다.

**참고: q2 원래 테스트**
- 원래 테스트 `TestReviewSymlinkedTunnelsDirEscapes`는 일반 `NewTunnelStore`(GUI/CLI, 사용자 권한)를 씁니다. 그래서 여전히 사용자 자신의 symlink를 따라가지만, 같은 권한 안의 동작이라 권한 상승이 아닙니다.
- `TestReviewLoadSymlinkLeaksLine`은 일반 저장소에서도 `path escapes from parent`로 막혀 내용이 나오지 않습니다.
- 잠금 대기 테스트는 이제 2초 뒤 `ErrStoreBusy`를 반환합니다. 이전 oracle로는 FAIL이지만 수정된 것입니다.
- 파서 오류에서 원문(`%q line`, key)이 제거됐습니다.
- 운영 경로에서는 helper의 `config.json`도 항상 `ReadUserFile`로 읽습니다. 직접 `os.ReadFile`하는 fallback은 `userFileUID == nil`인 테스트 fixture 전용입니다.

### 2.2 H-G1 상세

- `ShouldQuit`이 `doShutdown()`을 동기로 실행합니다.
- 교착 상태가 없습니다.
  - Wails `dispatchOnMainThread`는 main thread에 있으면 함수를 바로 실행하므로(`application.go:839-844`), 연결 아이콘 초기화가 즉시 끝납니다.
  - tray Quit은 다른 goroutine에서 `doShutdown`을 먼저 실행합니다. 이때 main thread 작업은 `InvokeAsync`뿐이라, `ShouldQuit`이 `sync.Once` 완료를 기다리는 동안에도 막히지 않습니다.
- Windows는 `App.Quit` 경로에서만 `shouldQuit`을 호출합니다. Linux는 마지막 창이 닫힐 때도 호출하지만, 이전에도 그 경우 앱은 종료됐으므로 이제 종료 전에 정리가 실행될 뿐입니다.
- 대가: 종료 시 main thread가 최대 약 5초(history 1초 + Disconnect 2초 + Shutdown 2초) 막힙니다. 로그아웃이나 시스템 종료 중에는 이 시간이 허용되는지 실기기 확인이 필요합니다.

## 3. 새로 찾은 반례 (이번 수정 범위, 차단 아님)

| ID | 심각도 / 유형 | 위치 | 내용 | 권장 |
|---|---|---|---|---|
| C-1 | low-medium / 실제 오류(코드로 확정) | `network/dns_darwin.go:392-396`, `dns_restore_darwin.go:14-21` | `networksetup -listallnetworkservices`가 실패하면 `getAllNetworkServices()`가 nil을 반환합니다. 그러면 `ResetDNSToSystemDefault()`가 아무것도 쓰지 않고 nil(성공)을 반환해, crash 복구가 journal을 지웁니다. H-N1과 같은 유형인데 이 경로에 남아 있습니다. `runOut`이 테스트에서 바꿀 수 있는 변수가 아니라 테스트로 재현하지는 않았지만, 실패 → nil 목록 → nil 반환은 결정적입니다. | 목록 조회 오류를 반환합니다. 목록이 비면 오류로 처리합니다. |
| C-2 | low / 동작 변화(추론) | `dns_restore_darwin.go:24-51` | 이전 코드는 서비스마다 `-setdnsservers` 다음 `-setsearchdomains`를 순서대로 실행했습니다. 이제 같은 서비스에 두 명령을 동시에 실행합니다. networksetup이 SCPreferences 잠금 경합에서 실패하면 새로 일시적인 복원 실패가 생길 수 있습니다. 실기기로는 확인하지 않았습니다. | 서비스 단위로는 순서대로, 서비스끼리는 병렬로 실행합니다. |
| C-3 | low / 복구 경로 없음 | `firewall/pf_lease_darwin.go:40-46, 121-137` | lease 파일이 손상되면(JSON 파싱 실패) 이제 `enablePf`가 계속 오류를 반환해서, 파일을 직접 고치기 전까지 kill switch와 DNS 보호를 켤 수 없습니다. 오류는 드러나므로 숨김은 아닙니다. | 손상된 lease를 `.corrupt`로 옮기고 "소유권 불명"으로 진행합니다. 기존 원칙대로 해제하지 않는 쪽입니다. |

## 4. 참고 (low, 설계 확인 필요)

- **Windows에서 SID가 비면 소유자 검사가 모두 생략됩니다.** 이전 GUI가 `--owner-sid` 없이 띄운 helper가 해당합니다(`transport_windows.go:43` 호환 경로). `os.Root`가 상위 root 밖으로 나가는 것은 막으므로 탈출 위험은 낮습니다. 사용자 저장소 기능은 SID가 있을 때만 켜는 방안을 권합니다.
- **Unix 중간 디렉터리 검사가 root 소유이기만 하면 통과합니다.** root 소유이면서 sticky bit 없이 group/world 쓰기가 가능한 디렉터리는 드물지만 이론상 교체 지점이 됩니다. OpenSSH StrictModes처럼 이런 디렉터리를 거부하는 방안을 권합니다.
- **중간 디렉터리 소유자 제약으로 인한 호환성:** 비표준 위치(다른 비-root 계정이 소유한 상위 디렉터리)에 홈이 있는 Linux 사용자는 helper가 프로필을 읽지 못하게 됩니다. 안전한 쪽의 실패이고 오류가 드러납니다.
- **macOS health probe의 helper 재기동:** 이제 health tick마다 새 연결로 probe합니다. helper가 없으면 socket activation이 helper를 다시 띄웁니다. GUI가 열려 있을 때의 복구 의도와 맞고, Quit 시에는 health를 먼저 멈추므로 문제는 없어 보입니다.

## 5. 아직 수정 중인 항목 (이번 결과에 포함하지 않음)

`632d7c4`에서 재현 결과만 기록합니다. 수정 실패로 판정하지 않습니다.
- **M-H3 / L-H3:** wifi 콜백 Stop(`onChanged invoked 2 time(s) after Stop`), Monitor retry wait와 handover slot(재현 2건 FAIL)
- **N-2:** `disconnectPhases`가 DNS 복원이 실패해도 `ClearPreModDNS()`와 `ClearActiveState`를 실행합니다. H-N1은 복원 함수 자체의 오류 보고를 고친 것이고, 이 정리 순서는 N-2 범위입니다.
- **M-S3:** 설정 스냅샷 저장이 삭제된 규칙을 되살림(재현 그대로 `true`)
- **L-S6/L-S7:** inline 주석, ExtraKeys 순서(재현 그대로)
- **GUI 항목과 나머지 low**

## 6. 실행한 명령과 결과

공통 환경 변수는 `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`이고, GOCACHE는 SSD입니다. 부트 볼륨 여유는 2.1Gi로 안정적이었습니다.

| 명령 | 결과 |
|---|---|
| `go vet ./internal/...` (darwin) | 통과 |
| `GOOS=windows go vet` storage/atomicfile/helper/cli/gui | 통과 |
| `GOOS=linux go vet` storage/atomicfile/tunnel/firewall | 통과 |
| `go test -race -count=1 ./internal/...` (`base`) | 20개 패키지 모두 ok |
| `GOOS=windows go test -c` storage/atomicfile/helper/cli/gui/firewall/network/tunnel, `GOOS=linux go test -c ./internal/storage` | 컴파일 성공 |
| 이전 재현 테스트 재실행(`rep`: q1/q2/q3 파일 복사, q1은 HOME 대신 seam) | 2절 표와 5절대로 |
| 새 oracle | `TestCoreUserStore*` 3건, `TestCoreFollowupCleanupThenTickDoesNotReinstall`(200회, `-race`), `TestCoreFollowupProbeSucceedsDuringSlowControlRPC` 모두 PASS |

새 oracle 테스트 파일(사본에만 있음):
- `rep/internal/storage/zz_core_userstore_test.go`
- `rep/internal/helper/zz_core_followup_test.go`
- `rep/internal/gui/review_q1_test.go`(맨 끝 테스트)

## 7. 미검증 범위

- Windows: 실제 실행(SID ACL, junction 처리). 교차 컴파일만 했습니다.
- macOS: 실기기 Cmd+Q, 로그아웃, 시스템 종료 시 5초 동기 정리의 허용 여부. networksetup 동시 실행 경합(C-2).
- Linux: 실제 실행.
- 설치 앱 교체, 실제 VPN, 잠자기 시험은 하지 않았습니다.
