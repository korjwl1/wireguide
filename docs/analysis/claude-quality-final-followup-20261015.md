# WireGuide 후속 수정 재검토 (final2)

- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5), 직접 검토(worker 없음). 이전 전체 스캔은 반복하지 않았고, 후속 수정과 그 직접 회귀만 봤습니다.
- 대상: 고정 스냅샷 `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-quality-final2-20261015`. 스냅샷은 읽기만 했습니다.
- 실행 사본: `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-final2-claude-run/{s,rep}`
  - 스냅샷의 `frontend/node_modules`는 실제 작업 디렉터리를 가리키는 symlink라 복사하지 않았습니다.
  - 빌드는 이전에 만든 별도 실제 복사본을 썼습니다. 그래서 공유 `node_modules`에는 쓰지 않았습니다.
- 환경 변수: 이전과 같음(`GOTMPDIR=TMPDIR=` SSD, `CGO_*FLAGS=-mmacosx-version-min=12.0`, `MACOSX_DEPLOYMENT_TARGET=12.0`, Go 1.26.9)
- 하지 않은 것: 실제 앱, VPN, OS 설정, 수면, 관리자 시험. 실제 작업 디렉터리와 Git도 수정하지 않았습니다.
- 정정 유지: 테스트 바이너리 11개를 보존 이동한 것은 Codex 자신의 작업입니다. 사용자 파일 이동이 아닙니다.

## 1. 결론

**이번 수정으로 생긴 blocker는 없습니다.** 이전 최종 리뷰의 B-3(High)와 M-1, M-2(Medium), L-1~L-10은 모두 해결된 것으로 판정합니다.

D-1과 `testing.Testing` gate는 기존 정책대로 유지했으므로 평가 대상에서 뺐습니다.

## 2. 검증 결과 (`s` 사본)

| 명령 | 결과 |
|---|---|
| 프론트엔드 `node --test` | **14/14 통과** |
| `vite build` (별도 실제 node_modules 복사본) | 성공, 경고 0 |
| `gofmt -l` (frontend 제외 전체 .go) | **0건** |
| `go vet ./...` (darwin) | 통과 |
| `GOOS=windows go vet ./internal/...` | 통과 |
| `GOOS=linux go vet` firewall/network/tunnel/storage/reconnect | 통과 |
| `GOOS=windows/linux go test -c` firewall/network/tunnel/storage/helper/reconnect/wifi/elevate/atomicfile/cli, `GOOS=windows ... gui` | 통과 |
| `GOOS=linux go test -c ./internal/gui` | 실패. Wails linux 코드가 cgo를 요구하는 교차 컴파일 환경 한계(`menu_linux.go: undefined: pointer`)이고, 이번 변경과 무관. 이번에 처음 목록에 넣은 것 |
| `go test -race -count=1 ./...` | **FAIL 0, DATA RACE 0** |

## 3. 항목별 판정

| ID | 판정 | 근거 |
|---|---|---|
| **B-3** 정리 대기가 모든 연결을 차단 | **해결** | 이전 재현 `TestFinalPermanentCleanupFailureBlocksAllConnects`를 이 스냅샷에서 다시 실행. 정리가 영구히 실패하는 상태에서도 Connect가 정리 대기 검사를 통과해 엔진 생성 단계까지 진행함(남은 오류는 테스트용 가짜 키의 `invalid base64`로, 차단과 무관). 이 테스트의 원래 oracle(`err == nil`)은 지금 계약에 비해 너무 엄격함 |
| M-1 Linux nft 교체 | 해결 | `firewall/linux.go:178`이 `add table` → `delete table` → 재정의를 한 batch로 실행. 실제 nft를 격리 namespace에서 돌리는 CI 테스트는 macOS에서 실행할 수 없어 확인하지 않음 |
| M-2 Windows `ACCESS_DENIED` | 해결 | `replace_windows.go:36`에 `ERROR_ACCESS_DENIED` 추가(1초 상한). Windows CI 재현 결과는 사용자 보고 기준 |
| L-1 이전 예약 경로 선점 | 해결 | `instance_darwin.go:52-55`가 신뢰할 수 없는 디렉터리를 오류가 아니라 "이전 GUI 아님"으로 무시 |
| L-2 저장 로직 중복 | 해결 | `field-writer.js` 공유. Node 테스트 통과 |
| L-3 ExtraKeys 이중 표현 | 해결 | map 제거, `ExtraEntries` 하나로 통일 |
| L-4 ZIP `List()` 오류 | 해결 | 오류 전파 |
| L-5 update State rollback | 해결 | `State.clone` |
| L-6 `disconnecting` 상태 | 해결 | `domain.StateDisconnecting` 추가. `manager_status.go`가 실제 상태를 그대로 전달. CLI `tunnels.go:91-94`와 프론트 `tunnel-state.js`가 처리. tray는 connected만 집계. reconnect 패키지에 `StateConnecting`만 보는 비교가 남아 있지 않음 → 회귀 없음 |
| L-7 CLI 접속 정책 | 해결 (사용자 설명, 코드 일부 확인) | `contactHelper` 하나의 정책과 handshake 재사용 |
| L-8 긴 함수 | 부분 (요청 범위 반영) | GUI 초기 helper 설정과 종료를 `shutdown.go` 등으로 분리. `connect_rollback.go`로 실패 경로 분리. retry slot 삭제와 backoff 중복 통합 |
| L-9 gofmt | 해결 | 0건과 CI gate |
| L-10 지연 변화 로그 | 해결 (사용자 설명) | `deliveredIface` 유지 |
| tray 메뉴 언어 (이전 L-G13) | 해결 (사용자 설명, 파일 추가 확인) | `gui/language*.go`, 설정 patch 시 메뉴 재구성 |

## 4. 새 owner / lifetime / retired journal 검토

**확인한 내용 (오류 없음)**
1. **키의 왕복 일관성**
   - 실패한 정리는 `.cleanup-<rand.Text()>` 키로 원자적으로 이름을 바꿉니다(`dns_cleanup.go:116-143`, `os.Rename`).
   - `stateFileName`은 `/`, `\`, `..`만 바꾸고, `rand.Text()`(base32) 키에는 이런 문자가 없습니다.
   - `LoadActiveState`는 파일명이 `stateFileName(TunnelName)`과 다를 때만 `journalKey`를 기록합니다. 그래서 `..`가 들어간 터널 이름도 이중 변환이 생기지 않습니다.
   - `SaveActiveState`와 `ClearActiveState`, crash recovery의 삭제가 모두 `activeStateKey`를 거치므로 같은 파일을 가리킵니다.
2. **같은 이름 재연결과의 분리**
   - 새 Connect는 시작할 때 `preparePendingJournal`(`manager.go:281`)로, 같은 이름이면서 아직 이름이 바뀌지 않은 대기 journal을 먼저 retired 키로 옮깁니다.
   - 그 뒤 첫 OS 변경 전에 인터페이스 소유를 기록합니다(`connect_phases.go:62`). 그래서 새 세션 기록이 이전 정리 기록을 덮어쓰지 않습니다.
3. **새 세션 보호**
   - `retryNetworkCleanup`은 활성 터널이 하나라도 있으면 실행하지 않습니다.
   - baseline(PreModDNS)은 retired 작업이 남아 있는 동안 지우지 않습니다(`clearRecoveredBaseline`, 재시도 루프 끝의 `clean` 검사).
   - 새 세션은 원래 baseline을 재사용합니다(`AdoptPendingRecovery`의 `CapturePreModDNS`).
4. **실패 경로**
   - `rollbackConnect`(`connect_rollback.go`)는 정리에 성공하면 소유 기록을 지우고, 실패하면 retired로 넘기면서 원래 오류를 보존합니다.
   - 초기 소유 기록이 실패하면 OS 변경 없이 엔진을 닫고 실패를 반환합니다.
   - 사용자 알림은 `onRecoveryWarning` → `recovery_warning` 이벤트로 갑니다.
5. **helper 수명**
   - helper가 유휴 종료해도 retired journal은 디스크에 남습니다.
   - 다음 시작의 crash recovery가 그 키로 정리하고 삭제합니다. 실패하면 `AdoptPendingRecovery`가 원래 baseline과 라우팅 상태를 넘겨받습니다.

**참고 (low, 설계)**
- **N-a:** retired 재시도는 활성 터널이 없을 때만 돕니다. 그래서 사용자가 VPN을 계속 켜 두는 환경에서는 실패한 세션의 라우트와 bypass 정리가 오래 미뤄질 수 있습니다. DNS는 baseline 보존으로 정확성이 유지됩니다. 새 세션을 보호하려는 의도된 우선순위이므로, 문서나 경고 문구로 알리는 정도면 충분합니다.
- **N-b:** 첫 연결이 롤백에 성공한 뒤 baseline을 지울지는 `len(m.AllDNSServers()) == 0` 조건으로 정합니다. 그 시점에 실패한 entry가 아직 집계에 포함되면 baseline이 다음 정상 disconnect까지 남을 수 있습니다. 결과는 사용자 원래 DNS 복원이라 대부분 무해합니다. 추론이며 재현하지 않았습니다.
- **N-c:** 이전 IPC 1.3 CLI는 새 상태값 `disconnecting`을 모르므로 통계 행(●)으로 출력합니다. 앱과 함께 배포되는 CLI를 쓰면 문제가 없습니다.

## 5. 미검증 범위
- 실제 Linux nft namespace CI 테스트(M-1), 실제 Windows `ACCESS_DENIED` 재시도(M-2). 각각 사용자의 CI 실행 결과에 의존합니다.
- 실제 OS에서 영구 정리 실패 시나리오(resolv.conf symlink 전환, macOS 서비스 삭제)
- 실제 앱, VPN, 수면 — 요청에 따라 하지 않음

## 6. 환경 사항
- 검토 중 부트 볼륨 여유가 284Mi에서 168Mi로 계속 줄었습니다. Claude의 Go 임시 파일, 캐시, 빌드, 로그는 모두 SSD에 썼으므로, 다른 프로세스가 공간을 쓰는 것으로 보입니다. 다음 작업 전에 확인이 필요합니다.
- 이전 리뷰에서 실제 작업 디렉터리 `frontend/node_modules`에 남았을 수 있는 빈 `.vite-temp`(22:41:16)는 이번 작업에서 건드리지 않았습니다.

## 7. 후속 확인: UI 오류 표시 정리 (`a55c345` 위의 미커밋 3파일)

- 대상: root 작업 트리의 `frontend/src/lib/ErrorNotice.svelte`(신규), `Settings.svelte`, `AutomationEditor.svelte`
- 범위: 읽기만 했습니다. 테스트와 전체 리뷰는 반복하지 않았습니다.
- CI `38751771573`(`a55c345`, 3개 OS 성공, 실제 nft·Windows reader-held 시험 포함)와 headless Chrome 결과는 사용자 보고 기준이고, Claude가 직접 확인하지는 않았습니다.

**판정: 문제없음. 차단 항목 없음.**

| 확인 항목 | 결과 |
|---|---|
| 중복 markup 정리 | 로드 실패(Settings, AutomationEditor), 저장 실패(필드별, AutomationEditor)가 모두 `ErrorNotice` 하나로 표시됨 |
| 접근성 | `role="alert"`, 실제 `<button type="button">`, `:focus-visible` 외곽선, `overflow-wrap: anywhere`와 `min-width: 0`으로 긴 메시지 줄바꿈, 버튼 `white-space: nowrap`과 8px 간격 |
| 설정 읽기 실패 시 재시도 비활성 | 필드 재시도가 `busy={!loaded \|\| busyFields[key]}`로 비활성화되고, 편집 영역은 `fieldset disabled={!loaded}`. `applyToggle`에도 `!loaded` 가드가 있음 |
| 필드 재시도의 의미 | `applyToggle(key, value)`는 이름과 달리 키와 값을 받는 일반 함수라 토글이 아닌 필드(언어, 테마, 목록 폭 등)에도 맞음. 실패 후에는 저장된 의도를 다시 읽어 `settings[key]`에 반영하므로, 재시도는 영속된 값을 다시 적용함(기존 wanted/applied 모델과 일치) |
| 중복 클릭 | Settings는 `busyFields`, AutomationEditor 로드는 `loadGen` 세대 가드로 막음 |
| 저장·로드 로직 | 변경 없음(표시 계층만 바뀜) |

**사소한 개선 제안 (선택)**
- `Settings.svelte:331`의 `{#each Object.entries($settingsErrors) as [key, failure]}`에 key가 없습니다. 오류 하나가 사라지면 DOM이 재사용되면서 남은 `role="alert"` 노드의 텍스트가 바뀌어, 스크린 리더가 다른 오류를 다시 읽을 수 있습니다. `{#each ... as [key, failure] (key)}`로 바꾸면 해결됩니다.
- `applyToggle`이라는 이름은 이제 일반 필드 재적용에도 쓰이므로, `applyField` 같은 이름이 의도를 더 잘 드러냅니다.

## 8. 후속 확인: 브라우저 반례 2건 수정 (`5b1eced`, `5eb0ade`)

- 대상: root의 `frontend/src/stores/settings.js`, `stores/settings.test.js`, `lib/Settings.svelte`, `lib/modal.js`
- 범위: 읽기만 했습니다. 실행, 전체 리뷰, worker는 없었습니다.
- 브라우저 before/after 결과와 CI(`55e4eda` 3개 OS PASS, 새 CI 실행 중)는 사용자 보고 기준입니다.

**판정: 두 수정 모두 원인에 맞게 고쳐졌고 차단 항목은 없습니다.**

| 반례 | 판정 | 근거 |
|---|---|---|
| 설정창 밖에서 바꾼 목록 폭(333) 저장 실패 → Retry가 `settings[key]`(undefined)를 보내 요청값을 잃음 | 해결 | `patchSettings`가 요청을 queue에 넣는 시점에 필드별 마지막 요청값을 공유 `requestedValues`에 보존함(`settings.js:7-8,23`). Retry는 `applyField(key, settingRetryValue(key))`(`Settings.svelte:331`). `undefined`가 든 patch는 RPC를 보내기 전에 거부함. 테스트(`settings.test.js:38-59`)가 다른 화면의 값 변경 뒤에도 333이 유지되는지와 undefined가 전송되지 않는지 확인함. 쓰기 직렬화와 필드별 오류 유지는 그대로임. 같은 필드에 A, B가 연달아 queue되면 재시도 값은 최신 요청(B)이고, B가 성공하면 오류가 지워짐(올바름). `applyField`의 실패 후 재읽기는 화면 값만 갱신하고 재시도 값(store)은 바꾸지 않아 두 역할이 분리됨 |
| `fieldset disabled`가 하위 컨트롤의 `el.disabled`에 반영되지 않아, 읽기가 늦을 때 초기 모달 포커스가 비활성 영역에 남음 | 해결 | `modal.js:8`이 `el.matches(':disabled')`로 바꿔 fieldset에서 상속된 비활성 컨트롤을 제외함(HTML 의미론과 일치). `tabindex`를 가진 일반 요소는 fieldset 비활성의 영향을 받지 않으므로 계속 포커스 대상으로 남는 것도 맞음 |
| 이전 7절 제안 | 반영됨 | `{#each ... (key)}` keyed each, `applyToggle` → `applyField` 이름 변경 |

**사소한 사항 (low, 선택)**
- `Settings.svelte:190-197`의 `save()`는 `patchSettings`의 거부를 조용히 무시합니다. 대부분의 거부는 store가 필드별 오류로 남기므로 화면에 보입니다. 그러나 "missing value" 거부는 `settingsErrors`에 기록되기 전에 일어나므로 화면에 아무것도 남지 않습니다.
- 지금 Settings 필드는 같은 앱의 `GetSettings` 결과에서 오므로 실제로 `undefined`가 들어갈 경로는 찾지 못했습니다(이론상).
- 방어하려면 이 거부도 해당 키의 `settingsErrors`로 기록하면 됩니다.

D-1 노출 구간을 3개 언어 KS 안내와 README에 명시한 것은 문서 변경이고 동작은 바뀌지 않았다는 보고를 기록합니다. 문구 자체는 이번 범위에서 검토하지 않았습니다.


> Codex 확인: 8절의 두 브라우저 반례는 수정 전 실제 실패, 수정 후 통과로
> 대조했다. 마지막 15개 Node 테스트·production frontend build·Chrome
> 시나리오가 통과했다. missing-value 거부는 실제 UI의 값 생성 경로에서
> 발생하지 않는 개발자 입력 계약 위반이며, RPC 전 거부를 유지했다.
> OS 변경 조합을 실제 장치에서 확인했다는 주장에는 포함하지 않는다.
