# WireGuide 최종 코드 리뷰 — 632d7c4 이후 미커밋 최종 스냅샷

> 이 문서는 해당 스냅샷의 당시 리뷰 기록입니다. 후속 수정 판정은 [최종 재검토](claude-quality-final-followup-20261015.md)와 [작업 결과](code-quality-review-20261015.md#독립-리뷰-반영과-최종-검증)를 기준으로 확인하세요.
- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5). 추가 worker 없이 직접 검토했습니다.
- 대상: `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-quality-final-20261015` (632d7c4 이후 미커밋 최종 코드). 스냅샷 자체는 읽기만 했습니다.
- 실행 사본:
  - `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-final-claude-run/base`: 스냅샷 복사본에 사용자가 보낸 수정 파일 2개를 반영
  - `.../rep`: 이전 재현 테스트와 새 재현 테스트용
  - `.../base632`: 632d7c4 비교용
- 환경 변수: `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`, `CGO_CFLAGS=CGO_LDFLAGS=-mmacosx-version-min=12.0`, `MACOSX_DEPLOYMENT_TARGET=12.0`, Go 1.26.9
- 지켰는지 확인한 제약:
  - 실제 Mac 앱, VPN, OS 설정, 수면 시험은 건드리지 않았습니다.
  - `npm ci`/`install`은 하지 않았습니다.
  - 실제 작업 디렉터리와 Git은 수정하지 않았습니다.
  - 예외 1건은 7절에 따로 적었습니다.
- 사실관계 정정 유지: 이전 보고서의 "사용자가 공간을 확보했다"는 표현은 틀렸습니다. Codex가 자기 테스트 바이너리 11개를 보존 이동한 것이 사실입니다. 사용자 파일 이동이 아닙니다.

---

## 0. 즉시 수정이 필요한 blocker

| ID | 심각도 | 위치 | 문제 | 증거 | 수정 |
|---|---|---|---|---|---|
| **B-1** | Blocker (CI) | `internal/network/splitdns_windows_test.go:18` | 삭제된 필드 `m.origDNSIface`, `m.origDNS`를 참조함 | `GOOS=windows go vet ./internal/...`, `GOOS=windows go test -c ./internal/network` 모두 `m.origDNSIface undefined`. Windows CI가 실패함 | 상태 확인 줄을 지우거나 현재 상태 필드로 바꿈. 사본에서 지웠더니 통과함 |
| **B-2** | Blocker (테스트 빌드) | `internal/elevate/repair_darwin_test.go:227` (보내 주신 수정본에도 남아 있음) | shadow를 고친 뒤에도 `t.Fatalf(..., err, version)`의 `version`이 남아, `version` 패키지를 값으로 씀 | `go vet ./internal/elevate`가 `use of package version not in selector`로 실패, `go test`도 build failed | `helperVersion`으로 바꿈. 사본에서 바꿨더니 통과함 |
| **B-3** | **High / 실제 오류 / 이번 N-2 변경이 만든 회귀** | `internal/tunnel/manager.go:280` → `dns_cleanup.go:175-183` | 정리 대기(`pendingNetworkCleanup`)가 하나라도 있으면 모든 새 Connect를 거부함. 영구히 실패하는 정리가 있으면 helper를 재시작하기 전까지 수동 연결과 wake 재연결이 모두 막힘 | **재현:** `rep/internal/tunnel/zz_final_pending_cleanup_test.go` → `connect after permanent cleanup failure: recovering previous connection: previous network cleanup is still pending ... (cleanup attempts=3)` FAIL. 영구 실패가 일어날 수 있는 경로: Linux에서 VPN 연결 중 `/etc/resolv.conf`가 symlink로 바뀌면 `RestoreDNS`가 매번 `resolv.conf changed to a symlink` 반환(`dns_linux.go:325-327`). macOS에서 snapshot의 네트워크 서비스가 삭제되면 `networksetup`이 계속 실패. 이 새 경로에는 저장소 테스트가 없음 | 연결은 막지 않음. 보존된 baseline(PreModDNS)을 새 세션이 재사용하게 하고, 재시도는 지금처럼 터널이 없을 때만 계속함. 원인이 사라지지 않는 실패(서비스 없음, symlink 전환)는 사용자에게 보이는 경고와 명시적 "DNS 원복 포기/재설정" 경로로 끝냄. 최소한 연결 거부 대신 경고를 주고 진행 |

B-1과 B-2만 사본에서 고친 상태로 검증한 결과(2절):
- race 테스트 FAIL 0건
- Windows vet 통과, Windows network 테스트 컴파일 통과

## 1. Medium / Low-Medium (이번 변경의 회귀 또는 불완전 수정)

| ID | 심각도 / 유형 | 위치 | 문제 | 증거 | 수정 |
|---|---|---|---|---|---|
| M-1 | Medium / 실제 오류 (회귀) | `internal/firewall/linux.go:176-179` | 교체 batch가 `delete table inet wireguide`로 시작하는데 `add table`이 없음. nft는 transaction 안에서 없는 테이블을 delete하면 batch 전체를 거부함. 같은 패키지의 DNS 규칙은 이 때문에 `add table` → `delete table` → 재정의 순서를 씀(`dns_rules.go:134-135`). 외부에서 ruleset이 비워진 뒤(firewalld/docker 재시작 등)에는 켜진 kill switch의 permit 추가·제거가 계속 실패함. 이전 코드는 not-found를 무시하고 다시 적용했음 | [코드 + nft 의미론] Codex 테스트 `TestLinuxKillSwitchReplacementIsOneTransactionAndFailureKeepsModel`은 `nftApply`가 항상 성공한다고 가정해 이 조건을 다루지 않음. Linux 전용이라 macOS에서 실행 불가 | `"add table inet wireguide\n"`를 앞에 붙임. 테이블이 없는 경우를 흉내 내는 fake 테스트 추가 |
| M-2 | Medium / 불완전 수정 (이전 M-S4) | `internal/atomicfile/replace_windows.go` `retrySharingViolation` | `ERROR_SHARING_VIOLATION`과 `ERROR_LOCK_VIOLATION`만 재시도함. 다른 프로세스가 `FILE_SHARE_DELETE` 없이 연 파일을 덮어쓰면 흔히 `ERROR_ACCESS_DENIED`가 반환됨 | [1차 근거] Go 툴체인 `cmd/internal/robustio/robustio_windows.go`의 `isEphemeralError`는 동시 읽기 중 Rename 실패로 `ERROR_ACCESS_DENIED`, `ERROR_FILE_NOT_FOUND`, `ERROR_SHARING_VIOLATION`을 재시도함(golang/go#31247, #32188). 실기기 미검증 | `ERROR_ACCESS_DENIED`도 같은 1초 상한 안에서 재시도함. 읽기 쪽도 robustio처럼 재시도하거나 FILE_SHARE_DELETE로 열기 |
| L-1 | Low-Medium / 실제 오류 (이전 L-G10의 일부 재발) | `internal/guiinstance/instance_darwin.go:46-54` `activateOldReservation` | 이전 공용 경로 `/private/tmp/wireguide-gui-<uid>`가 다른 사용자 소유면 오류를 반환함. 그 오류가 `Acquire` → `gui.Run` → 시작 오류 대화상자와 종료로 이어짐. 다른 로컬 사용자가 그 경로를 선점하면 비공개 경로로 옮긴 뒤에도 실행이 막힘. 이제 조용히 실패하지 않고 오류가 표시되는 점은 나아짐 | [코드로 확정] 다른 uid 소유 디렉터리는 root 없이 재현할 수 없음 | 내 소유가 아니면 우리 앱의 이전 예약일 수 없으므로 무시하고 진행함(경고 로그만 남김) |

## 2. 검증 결과

| 명령 (`base`, B-1·B-2 수정 반영 전/후) | 결과 |
|---|---|
| 프론트엔드 `npm test` | 12/12 통과 |
| `vite build` (복사한 node_modules) | 성공. **접근성 경고 0건**(이전 29건). "Svelte config 없음" 안내만 출력됨 |
| `gofmt -l internal main.go` | `internal/diag/ping.go`(이전부터), `internal/wifi/detect_cw_stub.go`, `detect_windows.go`, `gateway_darwin.go` (low) |
| `go vet ./...` (darwin) | 수정 전: elevate(B-2)만 실패, 루트는 dist가 없어서 실패. 수정 후 통과 |
| `GOOS=windows go vet ./internal/...` | 수정 전: network(B-1)만 실패. 수정 후 통과 |
| `GOOS=linux go vet` firewall/network/tunnel/storage/automation/wifi/reconnect/version | 통과 |
| `GOOS=windows/linux go test -c` firewall/network/tunnel/storage/helper/reconnect/wifi/elevate/atomicfile | 수정 전: Windows network만 실패(B-1). 수정 후 모두 통과 |
| `go test -race -count=1 ./...` | 수정 전: elevate build failed, 나머지 21개 ok. 수정 후: FAIL 0, DATA RACE 0 |

## 3. 이전 finding별 해결 여부

이전 보고서의 재현 테스트를 이번 스냅샷 사본(`rep`)에 붙여 다시 실행했습니다(`wifi.Rule` → `automation.Rule`만 기계적으로 고침). 예전 구현을 흉내 내는 테스트는 결과를 그대로 판정에 쓰지 않고, 현재 계약에 맞는 oracle로 해석했습니다.

### High
| ID | 판정 | 근거 |
|---|---|---|
| H-S1 root 경로 보안 | 해결 | `TestCoreUserStore*` 3건 PASS. symlink 유출 테스트는 `path escapes from parent` |
| H-G1 macOS 종료 정리 | 해결 | `ShouldQuit`에서 동기로 정리(632d7c4 후속 리뷰와 같음) |
| H-N1 DNS 복원 오류 은닉 | 해결 | q3 재현 2건 PASS. 직전 후속의 C-1(서비스 목록 실패 → 성공 보고)도 해결: `dns_restore_darwin.go:15-21` |
| D-1 재연결 중 KS 해제 | 설계 정책 유지 (평가 제외) | 사용자 결정대로 유지했고 README 문구를 고침. 별도 bootstrap 허용 정책은 남은 설계 판단 |

### Medium
| ID | 판정 | 근거 |
|---|---|---|
| M-H1 연결 중 터널 종료 | 해결 | q3 PASS(취소된 연결은 커밋되지 않음) |
| M-H2 ForceShutdown | 해결 | `TestCoreFollowupCleanupThenTickDoesNotReinstall` PASS. q3 원래 테스트는 예전 핸들러를 흉내 내므로 oracle 아님 |
| M-H3 wifi Stop 이후 콜백 | 해결 | `TestQ3OnChangedFiresAfterStop` PASS |
| L-H3 / Monitor retry join | 해결 (상한 있는 대기) | `TestQ3StaleRetrySlot…` PASS. `TestQ3StopDoesNotWaitForInFlightReconnect`는 Stop이 5.02초 기다린 뒤 실패함. 테스트의 reconnectFn이 ctx를 무시하기 때문이고, 설계상 5초 상한이 정상. 실제 reconnectFn은 ctx로 취소됨 |
| M-H4 desired-state 덮어쓰기 | 해결 | q3 PASS |
| M-H5 규칙 해제 캐시 | 해결 | q3 테스트가 fixed 사유로 SKIP |
| M-F1 PF 참조 | 해결 | q3 PASS. 직전 후속의 C-3(손상 lease)도 해결: `.corrupt-<ts>`로 보존 후 진행(`pf_lease_darwin.go:136-142`) |
| M-S2 잠금 대기 무제한 | 해결 | 2초 뒤 `ErrStoreBusy`(이전 oracle로는 FAIL이지만 수정된 것) |
| M-S3 설정 스냅샷 덮어쓰기 | 해결 (GUI 계층) | `UpdateSettings(SettingsPatch)`가 `SettingsStore.Update` 안에서 바뀐 필드만 적용함. 전체 Save GUI API는 제거됨. `stores/settings.js`가 요청을 직렬화하고 필드별 오류를 보존함. 재현 테스트는 저장소 수준 `Save`를 직접 부르므로 여전히 `true`이지만, 그 API를 쓰는 GUI/CLI 호출자가 없음 |
| M-S4 Windows 교체 | **부분 해결** | 1절 M-2 |
| M-I1~M-I4 | 해결 | q1 CLI 재현 PASS. M-I3·M-I4는 core 후속 oracle PASS |
| M-I5 구 helper delete 안내 | 해결 (fail-closed) | exit=1, 파일 보존 |
| M-G2 두 새 복사본 동시 종료 | 해결 | `legacy_darwin.go:12-23`이 실행 중 앱 plist의 `WireGuideGUISingleInstanceVersion`(빌드 plist 두 곳에 `1` 있음)으로 새 복사본을 제외함. 재현 테스트는 예전 판정(무조건 legacy)을 주입하므로 oracle 아님 |
| M-G3 연결 중 상태 표시 | 해결 | `lib/tunnel-state.js` 하나를 App, TunnelList, TunnelDetail, `stores/tunnels.js`가 공유함. 다만 1절 아래 L-6 참고 |
| M-G4 설정 읽기 실패 숨김 | 해결 | `loadSettings`가 실패하면 throw. AutomationEditor는 터널별 API 사용 |
| M-G5 보안 토글 실패 숨김 | 해결 | patch 요청 직렬화와 필드별 오류 표시 |
| N-2 정리 실패 시 journal 삭제 | 해결, **그러나 B-3 회귀** | 정리 실패 시 baseline과 journal을 보존하고 재시도함. 다른 터널이 있으면 재시도하지 않음(`retryNetworkCleanup`의 busy 검사) |
| N-3 다중 전역 DNS의 drift | 해결 (코드) | `trackDNSUnion`이 남은 터널들의 합집합을 각 매니저에 동기화함. 실기기 미검증 |
| N-4 resolvconf 정리 | 해결 | `RemoveInterfaceDNS`. 다른 터널이 있어도 그 인터페이스 기여분은 제거함 |
| N-5 Linux 원본 DNS 덮어쓰기 | 해결 | 디스크 journal을 공통 baseline으로 쓰고 원자적으로 기록 |
| F-2 Linux KS | 대부분 해결, **M-1 회귀** | 삭제 실패 시 플래그 유지, recovery가 KS 테이블도 지움, 모델 rollback |

### Low (이전 표)
| ID | 판정 |
|---|---|
| L-H1 watchdog 영속 | 해결 |
| L-H2 PF disable 부분 실패 모델 | 확인 안 함(범위 밖) |
| L-H4 수면 감지 wall time | 해결(darwin `sleep_darwin.go:238-251`, linux `:162`) |
| L-H5 네트워크 변경 trailing edge | 해결(`network_change.go` pending, polling ticker에서 계속 관찰) |
| L-H6 실패 은닉 일부 | 부분 해결(cleanup 오류 로깅 등) |
| L-H8 Windows origDNS 죽은 상태 | 해결(필드 제거). 그 테스트가 B-1을 일으킴 |
| L-S5 rename 고아 메타 | 해결 |
| L-S6 inline 주석 | 해결(검증 오류 0건) |
| L-S7 ExtraKeys 순서·중복 | 해결(`ExtraEntries`로 순서·중복 보존, Serialize 50회 중 1가지 출력) |
| L-S8 규칙 정리 경고 | 해결(`ProfileMutationResult.Warning`) |
| L-S10 update 저장 오류 | 해결(저장 실패 시 메모리 rollback, 로그) |
| L-S11 FIFO | 해결(`O_NONBLOCK` 후 일반 파일 검사) |
| L-S12 ZIP 대소문자 | 해결(`EqualFold`). 단 `List()` 오류를 무시함(low) |
| L-G1 helper_reset 남발 | 확인 안 함 |
| L-G2 history 종료 대기 | 해결(1초) |
| L-G5 rename pending | 해결 |
| L-G7/L-G8 stale detail, rename 중복 | 해결(세대 번호 가드, `if (!renaming) return`) |
| L-G9 시작 실패 숨김 | 해결(`ShowStartupError`) |
| L-G10 공용 예약 경로 | 해결(`_CS_DARWIN_USER_TEMP_DIR`), 단 이전 경로 이전에서 1절 L-1 |
| L-G12 쓰이지 않는 코드 | 부분: `setNativeTrayIcon` 정의가 남아 있음(사용처 재확인 권장) |
| L-G13 i18n | 미해결: tray "Show Window"/"Quit" 고정(`tray.go:594,638,642`) |
| L-G14 UAC 대기 | 해결(`CombinedOutput` + ctx, 취소와 실패 구분) |
| L-G15 접근성 경고 | 해결(빌드 경고 0) |
| C-1/C-2/C-3 (직전 후속) | 해결 (C-2: 서비스 단위 순차, 서비스 간 병렬) |

## 4. 새로 확인한 낮은 등급과 구조 지적

| ID | 유형 | 위치 | 내용과 권장 |
|---|---|---|---|
| L-2 | 구조 / 중복 | `frontend/src/lib/TunnelDetail.svelte:80-140` | `flushNotes`와 `flushLatencyTarget`이 같은 디바운스·저장·오류 패턴을 두 벌 갖고 있음. 하나의 `createDebouncedSaver(field, save)`로 합칠 것 |
| L-3 | 구조 | `internal/domain/config.go:34-46`, `config/parser.go:167-171,300-318` | `ExtraKeys`(map)와 `ExtraEntries`(slice)가 같은 정보를 이중으로 가짐. 지금은 파서만 쓰므로 어긋나지 않지만, 나중에 map만 바꾸는 코드가 생기면 Serialize가 옛 값을 씀. `ExtraEntries`를 단일 원천으로 하고 map은 조회용으로 유도하거나 제거할 것 |
| L-4 | 실제 오류(작음) | `internal/app/import_zip.go:21` | `names, _ := s.tunnelStore.List()`가 오류를 버림. 저장 단계에서 충돌로 걸리긴 함 |
| L-5 | 유지보수 | `internal/update/state.go:109-110` | rollback이 `DismissedVersions`만 깊은 복사함. 지금은 맞지만, 참조형 필드가 추가되면 rollback이 불완전해짐(주석이나 Clone 메서드로 고정) |
| L-6 | 표시 의미 | `frontend/src/lib/tunnel-state.js`, `TunnelDetail.svelte:232`, `TunnelList.svelte:129` vs `tunnel/manager_status.go:68,125,166` | Go가 해제 중 상태를 `connecting`으로 보내므로 프론트의 `"disconnecting"` 분기는 실행되지 않음. 해제 중에도 "connecting"으로 보임. Go가 `disconnecting`을 그대로 보내거나 분기를 정리할 것 |
| L-7 | 구조(부분 해결) | `internal/cli/cli.go:147,166,191,224` | 판정 함수 `helperAbsent`는 공유되지만, 접속 진입점은 여전히 3개(`dialHelper`/`Strict`/`Raw`). 결과 유형을 돌려주는 하나의 `contactHelper`로 합치기를 다시 권함 |
| L-8 | 구조 | 함수 길이(go/ast) | 이번 "파일 분리"는 함수 분해가 아니라 위치 이동임. `gui.Run` 367줄(이전 361), `tunnel.connectPhases` 318(311), `helper.Run` 285(284), `reconnectWithBackoff` 221(221), `helper.restoreDesiredTunnels` 196(`restore.go`로 이동만), `DarwinManager.reapply` 219. 특히 `gui.Run`은 예약, helper, 창, 종료, 작업 단계로, `connectPhases`는 단계별 함수와 공통 rollback으로 나눠야 리뷰와 테스트가 쉬워짐 |
| L-9 | 형식 | 4절 gofmt 목록 | `wifi`의 새로 분리된 파일 3개가 gofmt와 맞지 않음. CI에 `gofmt -l` 추가 권장 |
| L-10 | 표시 | `reconnect/network_darwin.go:199-205` | 보류된 변화가 늦게 나갈 때 로그의 `prev`가 이미 갱신된 값이라 `prev == now`로 찍힘(진단에만 영향) |

### 패키지와 경계 평가 (개선 확인)
- **의존 그래프:** 3개 OS 모두 순환이 없습니다.
  - `storage`와 `cli`가 더 이상 `wifi`(플랫폼 감지, cgo)에 의존하지 않고 순수 `automation`만 씁니다.
  - `helper`, `elevate`, `update`는 버전을 `version` 패키지에서 가져옵니다(이전 "update 전체에 의존" 해소).
  - `automation`과 `version`은 의존이 없습니다.
- **책임 분리:** network(routes/dns 파일), helper(restore 등), firewall 백엔드의 파일 분리는 변경 이유 단위로 나뉘어 Go 관례에 맞습니다. 다만 위 L-8처럼 핵심 함수의 크기는 줄지 않았습니다.
- **Svelte:**
  - `stores/settings.js`(patch, 필드별 오류)와 `lib/tunnel-state.js`가 실제 소비자 경계(여러 컴포넌트가 공유하는 상태 규칙)에 맞게 도입됐습니다.
  - 공통 `lib/modal.js` 도입 후 접근성 경고가 0건입니다.
  - App, TunnelDetail, Settings의 크기 분할은 이번 범위에서 크게 바뀌지 않았습니다(후속 과제).
- **의도적으로 유지한 것(평가 대상 아님):** `update`의 `testing.Testing` 보안 gate, D-1 정책.

## 5. 재현 증거 파일 (사본에만 있음)

- `rep/internal/tunnel/zz_final_pending_cleanup_test.go` (B-3)
- 이전 재현: `rep/internal/**/*_q3review_test.go`, `rep/internal/storage/review_repro_test.go`, `rep/internal/{cli,gui}/review_q1_test.go`, `rep/internal/storage/zz_core_userstore_test.go`, `rep/internal/helper/zz_core_followup_test.go`, `rep/internal/guiinstance/review_legacy_race_darwin_test.go`

## 6. 미검증 범위

- Linux nft 실제 동작(M-1), resolv.conf symlink 전환(B-3 경로)
- Windows MoveFileEx 실제 오류 코드(M-2), UAC
- macOS networksetup의 서비스 삭제 시나리오(B-3), 다른 사용자 소유의 이전 예약 경로(L-1)
- 실제 Mac 앱, VPN, 수면/깨우기 — 요청에 따라 하지 않음

## 7. 작업 중 환경 사항 (투명성)

- **공유 `frontend/node_modules`에 남은 흔적:**
  - 스냅샷의 `frontend/node_modules`는 실제 작업 디렉터리 `/Volumes/SSD/Projects/Personal/wireguide/frontend/node_modules`를 가리키는 symlink였습니다. `cp -R`로 symlink가 그대로 복사된 것을 모르고 첫 `npm run build`를 실행했습니다.
  - 그 결과 실제 작업 디렉터리의 `node_modules`에 빈 디렉터리 `.vite-temp`(mtime 22:41:16)가 남았습니다. Vite가 설정을 임시로 번들했다가 지운 흔적으로 보입니다.
  - 원래 있던 것인지 제가 만든 것인지 확실하지 않아 지우지 않았습니다. 직접 확인을 부탁드립니다.
  - 그 뒤에는 `cp -RL`로 실제 복사본을 만들어 썼고, 이후 이 디렉터리의 mtime은 바뀌지 않았습니다.
- **수정 파일 반영:** 사용자가 보낸 `handlers.go`, `repair_darwin_test.go`를 `base`에 반영했습니다. 후자에 B-2가 남아 있어 사본에서만 추가로 고쳤습니다.
- **디스크:** 부트 볼륨 여유가 834Mi까지 내려간 상태에서 시작했습니다. 모든 Go 임시 파일, 캐시, 빌드는 SSD에서 실행했습니다.

## 8. 후속 변경 반영 판정 (실제 브랜치 `26ae902`)

사용자 요청에 따라 최신 fixes(`wireguide-quality-final-fixes/`)를 반영해 다시 판정했습니다. 판정 기준은 실제 브랜치입니다.

**판정 대상**
- 로컬 HEAD `26ae9022bdcda7f7c85acac4e9b9d2019727ae3c`. `d39648a`(push 완료, CI 38746091936 실행 중으로 전달받음) 바로 다음 커밋입니다.
- `git archive 26ae902` 사본: `wireguide-final-claude-run/g26`.
- 비교용 "원본 스냅샷 + fixes 7개 파일" 사본: `fin`.

**두 사본의 차이**
- `fin`과 `g26`의 차이는 gofmt 정리, 주석 정리, ActiveTunnels 오류 로깅(`app/tunnel_list.go`), 쓰이지 않던 `setNativeTrayIcon` 제거, CI의 gofmt 검사뿐입니다.
- 동작이 달라지는 코드 차이는 없습니다.

### 8.1 `26ae902` 검증 결과

| 명령 | 결과 |
|---|---|
| `node --test` | **14/14 통과** (field-writer 테스트 포함) |
| `vite build` | 성공, 경고 0 |
| `gofmt -l .` | **0건** (CI에도 `gofmt -l` 검사 추가됨, `.github/workflows/ci.yml:53`) |
| `go vet ./...` (darwin), `GOOS=windows go vet ./internal/...`, `GOOS=linux go vet` 대상 패키지 | 모두 통과 |
| `GOOS=windows/linux go test -c` firewall/network/tunnel/storage/helper/reconnect/wifi/elevate/atomicfile | 모두 통과 |
| `go test -race -count=1 ./...` | **저장소 테스트 FAIL 0, DATA RACE 0**. 실패 1건은 Claude가 추가한 B-3 재현 테스트뿐 |

### 8.2 항목별 상태 변화

| ID | `26ae902` 판정 | 근거 |
|---|---|---|
| B-1 Windows 테스트 빌드 | **해결** | sentinel 검증만 남김. Windows vet와 테스트 컴파일 통과 |
| B-2 elevate 테스트 빌드 | **해결** | printf 인자까지 `helperVersion`. darwin vet와 테스트 통과 |
| **B-3 정리 대기가 모든 연결 차단** | **미해결 (High)** | `manager.go:280`, `dns_cleanup.go:175-183` 그대로. `zz_final_pending_cleanup_test.go`가 이 커밋에서도 `BLOCKED: every new connection is refused until helper restart`로 FAIL |
| M-1 Linux nft `add table` 누락 | 미해결 | `linux.go:178` 그대로 |
| M-2 Windows `ACCESS_DENIED` 재시도 | 미해결 | `replace_windows.go:36` 그대로 |
| L-1 이전 예약 경로 선점 | 미해결 | `instance_darwin.go:53` 그대로 |
| L-2 notes/latency 저장 중복 | **해결** | `field-writer.js` 하나로 통합. 프로필별 직렬화, 같은 값 합치기, 실패 후 다음 저장에서 재시도. `saved` 콜백은 `*Saved`만 갱신하고 입력 중인 값은 건드리지 않음(latency는 trim 일치 시에만 정규화). 실패해도 체인이 끊기지 않음(`catch` 후 false). 다른 프로필의 저장과 독립 |
| L-4 ZIP `List()` 오류 무시 | 미해결 (low) | `import_zip.go:21` |
| L-6 `disconnecting` 분기 | 미해결 (low) | Go가 해제 중 상태를 `connecting`으로 보냄 |
| L-7 CLI 접속 진입점 3개 | 미해결 (low, 구조) | `dialHelper*` 3개 |
| L-9 gofmt | **해결** | 0건과 CI 검사 |
| L-G12 쓰이지 않는 tray 코드 | **해결** | `setNativeTrayIcon` 제거 |
| L-G13 tray 문자열 i18n | 미해결 (low) | `tray.go:594,638` |

**참고:** `linux_dns_test.go`가 새 crash cleanup의 `nftFlush`를 mock하도록 고친 것은 맞는 수정입니다. 그 전에는 Linux CI에서 일반 테스트가 호스트의 nft를 실제로 호출할 수 있었습니다.

## 9. 결론 (`26ae902` 기준)

- **새 blocker는 없습니다.** 빌드·CI를 깨던 B-1과 B-2는 해결됐습니다. 저장소의 전체 race/vet/교차 컴파일/프론트엔드 테스트도 통과합니다.
- **main 병합 전 수정을 권하는 항목:**
  - **B-3 (High, N-2 변경이 만든 회귀).** 정리가 영구히 실패하면 helper 재시작 전까지 모든 연결이 막힙니다. 이 새 경로에는 저장소 테스트가 없습니다. 수정과 회귀 테스트를 함께 권합니다.
  - **M-1** Linux nft 교체 batch에 `add table` 추가(한 줄 수정)
  - **M-2** Windows 교체 재시도에 `ERROR_ACCESS_DENIED` 포함
- **L-1과 나머지 low·구조 항목:** 후속 정리로 충분합니다. L-4, L-6, L-7, L-G13, L-3, L-5, L-8, L-10이 해당합니다.
- **D-1:** 기존 명시 정책대로 유지했고, 이번 판정에서 제외했습니다.
- **CI 38746091936:** `d39648a` 기준이라 `26ae902`의 field-writer 변경은 포함하지 않습니다. 그 결과는 Claude가 확인하지 않았습니다.
