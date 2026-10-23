# WireGuide 코드 품질·로직 독립 리뷰 — HEAD `576ae84`

> 이 문서는 해당 스냅샷의 당시 리뷰 기록입니다. 후속 수정 판정은 [최종 재검토](claude-quality-final-followup-20261015.md)와 [작업 결과](code-quality-review-20261015.md#독립-리뷰-반영과-최종-검증)를 기준으로 확인하세요.
- 검토일: 2026-10-15
- 검토자: Claude Code (Opus 5.5) + 이 대화 맥락이 없는 독립 검토자 4명(영역별: q1 IPC·CLI·app·GUI health, q2 storage·import·config·update, q3 helper·reconnect·tunnel·firewall·network·wifi, q4 GUI 네이티브·단일 인스턴스·Svelte)
- 대상: `576ae8401015a67eaf6573638d4769550818b866` (`fix/windows-single-instance`). `git archive`로 만든 고정 사본 `/Volumes/SSD/AppData/korjwl1/gotmp/wireguide-quality-576ae84/{base,q1..q4}`에서만 실행했습니다.
- 제약 준수:
  - 소스, Git, OS 설정, VPN, 관리자 권한, 실행 중인 앱은 바꾸지 않았습니다.
  - 아래 세 가지는 따로 밝힙니다.
    - q1의 CLI 테스트가 실제 경로 `/Library/Application Support/wireguide`에 chmod를 시도했습니다. 권한이 없어 실패했고, 바뀐 것은 없습니다(검토자 보고).
    - q4는 H1을 재현하려고 WireGuide와 무관한 최소 Wails 앱(`q4/tools/termprobe*`)을 빌드해 실행했습니다. 설치된 WireGuide는 건드리지 않았습니다.
    - 그 밖의 재현 테스트는 모두 사본 안에만 있습니다.

먼저 읽은 문서: `docs/DESIGN.md`, `code-quality-review-20261015.md`, `remaining-logic-20261015.md`, `macos-native-verification-20261015.md`, `macos-single-instance.md`, `application-connection-icon.md`. 문서의 주장은 사실로 가정하지 않고, 아래 판정은 모두 현재 HEAD 코드를 기준으로 했습니다.

표기:
- **[재현]**: 테스트를 실행해 확인. 이 표시가 붙은 high/medium 항목은 Claude가 직접 다시 실행해 같은 결과를 확인했습니다.
- **[추론]**: 코드를 읽고 판단.
- 유형: **실제 오류 / 설계 선택 / 구조 개선**

---

## 0. 요약

- 기존 테스트, vet, 빌드는 모두 통과합니다. 그래도 **실제 오류 high 3건**(그중 1건은 보안), **medium 20건 안팎**, 낮은 등급과 구조 개선 다수를 확인했습니다.
- **반복되는 결함 유형이 네 가지 있습니다.**
  1. **실패를 성공으로 보고함**: macOS DNS 복원, CLI `set`, Settings 토글, Linux cleanup, update checker
  2. **종료와 Quit 경로가 계층마다 불완전함**: macOS Cmd+Q, 연결 중 터널, ForceShutdown, wifi 콜백, history 종료 대기
  3. **helper 접속 정책이 명령마다 따로 구현됨**: CLI rename, set, delete, list와 GUI의 백그라운드 복구
  4. **잠금 밖에서 뜬 스냅샷이 더 새로운 상태를 덮어씀**: desired-state 저장, 설정 전체 저장, Settings 화면
- 이번 커밋 범위(`fc1c073..576ae84`)의 `SubscribeContext`, 구독 교체, Tunnel.Delete의 helper 쪽 직렬화, history latch, 배지 브러시는 검토 범위에서 올바르게 구현됐습니다(6절). 다만 같은 커밋이 만든 정책이 인접 경로까지 적용되지 않은 곳이 있습니다(M-I1, M-I2, M-I5, L-G1).

---

## 1. High

### H-S1 · 실제 오류(보안) · [재현] root helper가 사용자 소유 프로필 저장소의 symlink를 따라감
- **위치:**
  - `internal/helper/helper.go:338`: root helper가 `appSupport/tunnels`(사용자 쓰기 가능)로 저장소를 만듦
  - `internal/helper/profile_ops.go:37,126`: `handleRename`, `handleDelete`
  - `internal/storage/tunnels.go:83-95,101-119,141-160`, `tunnel_lock.go:31-45`, `config/parser.go:91`
- **재현:** `q2/internal/storage/review_repro_test.go`
  - `TestReviewSymlinkedTunnelsDirEscapes`: `tunnels`를 외부 디렉터리로 symlink하자 `Delete("pf")`가 외부의 `pf.conf`를 지웠습니다. `Rename`은 escape 검사를 통과했습니다(디렉터리와 대상을 모두 EvalSymlinks로 풀어 비교하기 때문). `.imports.lock`도 symlink가 가리키는 곳에 생성됐습니다.
  - `TestReviewLoadSymlinkLeaksLine`: `x.conf`를 비밀 파일로 symlink하자 Load 오류 문자열에 비밀 줄 내용이 그대로 담겼습니다(`parsing x: line 1: invalid syntax: "root:$6$SECRETHASH:..."`).
- **영향:**
  - IPC가 허용한 같은 사용자 프로세스가 root helper를 통해 다음을 할 수 있습니다(같은 사용자 → root 권한 상승).
    - 임의 위치의 `*.conf`, `*.meta.json` 삭제와 이름 변경
    - root만 읽을 수 있는 파일의 줄 내용 유출
  - 유출 경로는 helper 로그 → GUI 로그 broadcast입니다([추론]).
  - DESIGN의 "지정한 사용자에게 VPN 작업을 허용한다"는 신뢰 모델을 벗어납니다.
- **권장 수정:**
  - helper가 사용자 저장소에 접근할 때는 경로 구성요소마다 `Lstat`으로 소유 uid를 확인하고 symlink를 거부합니다.
  - 파일은 `O_NOFOLLOW`로 열거나 Go 1.24+의 `os.Root`를 씁니다. 가능하면 사용자 uid로 권한을 낮춰 작업합니다.
  - helper가 내는 parse 오류에서는 줄 내용을 빼고 줄 번호만 남깁니다.

### H-G1 · 실제 오류 · [재현: 최소 Wails 앱 probe + Wails 소스 확인] macOS에서 Cmd+Q, Dock 종료, 로그아웃 시 종료 정리가 실행되지 않음
- **위치:** `internal/gui/gui.go:328-333`. `doShutdown`이 `events.Mac.ApplicationWillTerminate` 리스너에서만 호출되고, `ShouldQuit`은 쓰지 않습니다.
- **근거:**
  - Wails v3 alpha.74의 `applicationWillTerminate`는 이벤트를 채널에 넣고 즉시 반환합니다(`application_darwin_delegate.m:172-174`).
  - 리스너는 별도 goroutine에서 실행됩니다(`application.go:579-584`). 그래서 AppKit이 리스너를 기다리지 않고 종료합니다.
  - 반면 `ShouldQuit`은 `applicationShouldTerminate:`에서 동기로 호출됩니다(`application_darwin_delegate.m:41`).
  - 창이 보일 때는 `Regular` 정책이라(`dock_darwin.go:16`) Dock과 앱 메뉴의 Quit이 있습니다.
  - q4의 probe에서 300ms 리스너가 3번 중 3번 끝까지 실행되지 못했습니다.
- **영향:**
  - Disconnect/Shutdown RPC와 history 종료가 실행되지 않습니다.
  - helper는 GUI 연결이 끊겨도 터널을 유지하는 설계이므로, tray도 Dock도 없는 상태로 VPN과 kill switch가 계속 남습니다.
  - tray의 Quit과 결과가 달라서, "두 경로가 같은 상태를 남긴다"는 주석과도 맞지 않습니다.
- **권장 수정:**
  - `ShouldQuit`에서 정리가 끝나지 않았으면 정리를 시작하고 false를 반환합니다. 정리가 끝나면 `app.Quit()`으로 다시 들어와 true를 반환합니다(q4 probe로 2번 중 2번 순서 확인).
  - 다른 방법: `ShouldQuit` 안에서 제한 시간(약 4초)을 두고 동기로 정리합니다. 로그아웃이 취소되는 부작용을 고려해 선택합니다.

### H-N1 · 실제 오류 · [재현] macOS DNS 복원 쓰기가 모두 실패해도 nil을 반환함
- **위치:** `internal/network/dns_restore_darwin.go:15-34`(`ResetDNSToSystemDefault`), `:183-247`(`RestoreDNSFromSnapshot`). 서비스별 오류를 로그로만 남깁니다.
- **재현:** `TestQ3RestoreDNSFromSnapshotReportsWriteFailure`, `TestQ3ResetDNSToSystemDefaultReportsWriteFailure` 모두 "returned nil although every write failed"로 FAIL.
- **영향:** `tunnel/recovery.go:238-252`의 "정밀 복원 실패 → reset → ok=false" 경로가 실행되지 않습니다. 그래서 `:296-298`이 crash journal을 지우고, 사용자는 죽은 터널의 DNS에 묶인 채 다음 시작에도 재시도가 없습니다.
- **권장 수정:** 오류를 `errors.Join`으로 모아 반환합니다. 호출부는 이미 오류를 처리합니다. 같은 패턴인 N-6도 함께 고칩니다.

### (high 영향) D-1 · 설계 선택 · [추론] 재연결과 연결 중 kill switch를 통째로 끔
- **위치:** `helper/firewall_suspend.go:37-46`, `reconnect/monitor.go:677`, `helper/connect.go:42-49`. DESIGN 438-450에 문서화돼 있습니다.
- **영향:**
  - wake, 네트워크 변경, 헬스 재연결 중 teardown부터 endpoint 해석(peer당 최대 10초)과 연결까지의 구간에서 평문 트래픽이 물리 NIC로 나갑니다.
  - 터널 A만 재연결해도 정상인 터널 B의 permit이 사라집니다.
- **판단:** 문서화된 선택이지만, 근거가 "utun 이름이 바뀐다"뿐이고 kill switch의 목적과 정면으로 충돌합니다.
- **권장:** 기본 차단은 유지한 채 endpoint UDP와 해석용 DNS만 임시로 허용하고, 연결 뒤 인터페이스 permit만 교체합니다. 백엔드에 이미 `Add/RemoveKillSwitchTunnel`이 있습니다. 바꾸지 않는다면 사용자 문서에 이 구간을 명시해야 합니다.

---

## 2. Medium

### 종료·수명

**M-H1 · 실제 오류 · [재현] 종료가 연결 중인 터널을 내리지 못함**
- **위치:**
  - `tunnel/manager.go:456-481`: Connecting 상태를 10초 기다린 뒤 `ErrTimeout`. `:359-397`의 "Disconnect landed" 분기는 도달하지 않습니다.
  - `reconnect/monitor.go:258-309,513-532`: retry goroutine이 `wg`에 포함되지 않음
  - `helper/lifetime.go:192`: cleanup은 `IsConnected()`일 때만 실행
  - restore와 automation 연결은 `context.Background()`를 씀
- **재현:** `TestQ3DisconnectAllGivesUpOnSlowConnect` → `DisconnectAll returned after 10.048s; active=[slow]`, 이후 `IsTunnelConnected=true`
- **영향:** 정상 Quit인데도 DNS와 라우트가 바뀐 채 종료되고, 복구는 다음 실행의 journal에만 기댑니다.
- **권장:**
  - entry마다 connect cancel 함수를 두고, `DisconnectTunnel`이 Connecting이면 cancel한 뒤 기다립니다.
  - Phase 3 커밋 전에 ctx를 확인합니다.
  - cleanup은 `DisconnectAll`을 조건 없이 부릅니다.
  - restore와 automation에는 helper 수명 ctx를 넘깁니다.
  - Monitor.Stop은 retry goroutine까지 기다립니다.

**M-H2 · 실제 오류 · [재현] ForceShutdown cleanup 직후 주기 reconcile이 kill switch를 다시 설치함**
- **위치:** `helper/handlers.go:112-137`. `h.done`과 `connectMu` 없이 `firewall.Cleanup()`을 부르고 `os.Exit(0)`합니다. `dns_protection.go:141`의 tick이 그 사이에 끼어듭니다.
- **재현:** `TestQ3ForceShutdownCleanupRacesReconcileTick` → `kill switch reinstalled after ForceShutdown cleanup`
- **영향:** 죽은 helper 뒤에 PF/nft 규칙이 남아, 다음 helper가 뜰 때까지 인터넷이 차단됩니다.
- **권장:** ForceShutdown도 `cleanupOnce`와 `close(h.done)`를 먼저 거치게 합니다.

**M-H3 · 실제 오류 · [재현(monitor 수준)] wifi Stop 뒤에도 콜백이 automation을 실행함**
- **위치:** `wifi/monitor.go:128-147`. Linux DBus debounce, Windows Wlan 콜백, `ReportExternalSSID`를 Stop이 기다리지 않습니다. `automationConnect`는 `h.done`을 확인하지 않습니다.
- **재현:** `TestQ3OnChangedFiresAfterStop` → `onChanged invoked 2 time(s) after Stop`. 종료 중에 실제로 터널이 올라오는지는 [추론]입니다.

### 상태 일관성

**M-H4 · 실제 오류 · [재현] `persistDesiredState`가 오래된 스냅샷으로 새 기록을 덮어씀**
- **위치:** `helper/desired_state.go:214-262`. 스냅샷은 `mu`와 `wifiMu` 아래에서 뜨고, 쓰기는 `desiredMu` 아래에서 합니다. connectMu 없이 이 함수를 부르는 곳이 있습니다(`handleSetDNSProtection`, `pendingDesiredCfgs`, `withdrawPendingDesired`).
- **재현:** `TestQ3PersistDesiredStateStaleSnapshotOverwritesNewer` → `in-memory wanted=0, on-disk wanted=[A]`
- **영향:** 사용자가 끈 터널이 crash 복구 때 되살아나거나, 원하던 터널이 복구에서 빠집니다.
- **권장:** 스냅샷을 `desiredMu` 안에서 뜹니다. 잠금 순서는 desiredMu → mu → wifiMu이며, 역순 경로는 없습니다.

**M-H5 · 실제 오류 · [재현] automation의 "끊기"를 다음 wake 재연결이 되돌림**
- **위치:** `helper/wifi_rules.go:132-141`. 이미 내려간 터널에는 `CancelRetryFor(name)`만 부르는데, wake 재시도의 키는 `""`입니다.
- **재현:** `TestQ3RuleDisconnectLeavesTornDownTunnelCached` FAIL
- **권장:** `teardownTunnelHeld`와 같은 캐시 정리를 하거나, `reconnectFn("")`에서 규칙을 다시 확인합니다.

**M-F1 · 실제 오류 · [재현] 시작 복구가 실패한 뒤 이전 PF 참조 journal이 덮어써짐**
- **위치:** `firewall/darwin.go:739-744`(flush 실패 시 일찍 반환), `:779-782`(다음 Enable이 빈 lease를 기록)
- **재현:** `TestQ3FailedRecoveryThenEnableLosesCrashedPFReference` → `crashed reference 999/pid 7 never released`
- **영향:** 이전 helper의 PF 참조가 재부팅 전까지 남아, PF가 원래 꺼진 상태로 돌아가지 않습니다.
- **권장:** 메모리 토큰이 비어 있으면 디스크 lease를 먼저 읽어 합친 뒤 씁니다.

**M-S2 · 실제 오류 · [재현] 프로세스 간 저장소 잠금 대기에 제한이 없고, helper가 connectMu를 쥔 채 기다림**
- **위치:** `storage/tunnel_lock.go:11-28`, `flock_unix.go:11`, `flock_windows.go:13`
- **재현:** `TestReviewLockWaitIsUnbounded` → 다른 프로세스가 잠금을 쥔 동안 `Delete`가 3초 넘게 반환하지 않음
- **영향([추론]):**
  - `handleRename`과 `handleDelete`는 connectMu를 쥔 채 이 잠금을 기다립니다.
  - `pingRetryGuard`도 `LoadWithMeta`를 통해 배타 잠금을 기다립니다.
  - 그래서 CLI가 Ctrl-Z로 멈추면 helper의 모든 connect/disconnect가 막힙니다.
- **권장:**
  - non-blocking 재시도에 deadline을 둡니다.
  - 읽기 전용 경로는 shared lock을 씁니다.
  - helper는 저장소 잠금을 connectMu보다 먼저, timeout과 함께 잡습니다.

**M-S3 · 실제 오류 · [재현] GUI 설정 저장이 전체 스냅샷을 덮어써 다른 쓰기를 잃음**
- **위치:** `app/settings_ops.go:137-143`(이전 값을 잠금 밖에서 읽고 전체를 Save), `frontend/src/stores/ui.js:32-38`, `Settings.svelte:190-229`
- **재현:** `TestReviewSettingsSnapshotSaveResurrectsDeletedRules` → 삭제한 터널의 규칙이 되살아남(`true`). issue #12가 막으려던 "같은 이름에 규칙이 다시 붙는" 상황입니다.
- **영향:** Settings 화면이 열려 있는 동안 `ctl set`으로 바꾼 값도 되돌아갑니다.
- **권장:** 화면별로 자기 필드만 바꾸는 `UpdateSettings(patch)` API를 두고 `SettingsStore.Update` 안에서 적용합니다. GUI의 전체 Save는 없앱니다.

**M-S4 · 실제 오류 · [추론] Windows에서 읽기 중인 핸들이 원자적 교체를 실패시킴**
- **위치:** `atomicfile/replace_windows.go`
- **근거:** Go `syscall.Open`의 share mode에는 `FILE_SHARE_DELETE`가 없습니다. 그래서 helper나 GUI가 파일을 읽는 순간 `MoveFileEx(REPLACE_EXISTING)`가 sharing violation으로 실패합니다. 재시도가 없고, 작성자 테스트도 Windows에서는 skip합니다.
- **권장:** 짧은 backoff로 재시도하거나, 읽기를 `FILE_SHARE_DELETE` 래퍼로 통일합니다.

### CLI·GUI의 helper 접속 정책 (이번 커밋 정책이 인접 경로에 적용되지 않음)

**M-I1 · 실제 오류 · [재현] `ctl rename`이 응답 없는 helper나 호환되지 않는 helper를 우회해 로컬 파일 이름을 바꿈**
- **위치:** `cli/tunnels.go:272-291`. 같은 커밋의 `cmdDelete`(326행)는 "응답이 멈춘 helper는 터널이 꺼졌다는 증거가 아니다"라는 정책을 따르지만, rename은 따르지 않습니다.
- **재현:**
  - `TestQ1RenameFallsBackLocallyWhenHelperIncompatible` → `exit=0 ... betaExists=true`
  - `...Hung` → 15초 뒤 같은 결과
- **영향:** 연결 중이거나 복구 대기 중인 터널의 설정이 connectMu 밖에서 이름이 바뀌어, 이후 재연결과 복구가 옛 이름을 찾지 못합니다.

**M-I2 · 실제 오류 · [재현] `ctl set killswitch on`이 적용되지 않았는데 exit 0**
- **위치:** `cli/settings.go:43-48`. 바로 위 주석("스크립트가 차단 중이라고 믿게 하면 안 된다", issue #10)과 반대로 동작합니다.
- **재현:** `TestQ1SetKillSwitchReportsSuccessWithIncompatibleHelper` → `exit=0`

**M-I3 · 실제 오류 · [재현] 오래 걸리는 RPC 하나가 helper 장애로 오인됨**
- **위치:**
  - 서버가 한 연결의 요청을 순서대로 처리함(`ipc/server.go:351-398`)
  - health ping이 같은 제어 연결에서 2초 제한(`gui/helper_lifecycle.go:287-304`)
  - `MarkInflight`가 Connect/Disconnect/Delete에만 붙어 있음
  - `ReportSSID`는 helper 안에서 동기로 automation connect까지 수행함(`helper/handlers.go:253-261`)
- **재현:** `TestQ1SlowUnmarkedRPCLooksLikeHelperDeath` → `health ping err=context deadline exceeded HasInflight=false`, `user RPC err=client closed; helper applied=true`
- **영향:**
  - "helper가 응답하지 않음" 경고가 잘못 뜨고, 표시가 초기화되고, 불필요한 재연결이 일어납니다.
  - helper는 설정을 적용했는데 GUI에는 실패로 보여 상태가 어긋납니다.
- **권장:** health 확인을 별도 연결(`ipc.ProbeHelper`)로 합니다. 차선책은 `TunnelService.call` 계층 전체에서 in-flight를 표시하는 것입니다.

**M-I4 · 실제 오류(설계 문서 위반) · [재현 + 추론] Windows/Linux 백그라운드 복구가 helper를 끄고 권한 상승을 직접 실행함**
- **위치:** `gui/helper_lifecycle.go:361-366`. macOS가 아니면 `recoveryDial`이 `ensureHelper` 전체 경로를 씁니다. DESIGN 698-700의 "백그라운드 복구는 재실행 안내만 한다"는 약속은 macOS에서만 지켜집니다.
- **재현:** `TestQ1EnsureHelperWithShutsDownOldMinorAndSpawns` → `shutdowns=1 spawns=1`
- **[추론]:** helper가 죽은 상태라면 Windows `SpawnHelper`가 ctx를 무시하고 `Start-Process -Verb RunAs`를 띄운 뒤 바로 반환합니다(`elevate/spawn_windows.go:17-46`). 그래서 health tick마다 UAC 창이 반복해서 뜰 수 있습니다.
- **권장:** 모든 OS에서 백그라운드 경로는 연결과 버전 확인만 하고, 설치와 업그레이드는 사용자가 명시적으로 요청했을 때만 실행합니다.

**M-I5 · 실제 오류(UX) · [재현] 구 helper(IPC 1.3)와 새 CLI 조합의 `ctl delete`가 원시 오류만 출력함**
- **위치:** `cli/tunnels.go:313-322`
- **재현:** `delete: method not found: Tunnel.Delete`, exit 1. 실패 쪽으로 닫혀 있어 안전합니다.
- **권장:** `MinorOf(ping.Version) < 4`이면 "앱을 다시 열어 helper를 업그레이드하라"는 안내를 출력합니다.

### GUI·프론트엔드

**M-G2 · 실제 오류 · [재현(모델)] 새 버전 복사본 두 개를 동시에 실행하면 둘 다 종료될 수 있음**
- **위치:** `guiinstance/instance_darwin.go:58-62`, `legacy_darwin.go:13-17`. "구버전 앱이 실행 중인지"를 bundle ID로만 판정합니다.
- **재현:** `review_legacy_race_darwin_test.go`(LaunchServices 목록 지연 모델) → 3번 중 3번 "got 0 GUI primaries". 실제 LaunchServices의 지연은 측정하지 않았습니다.
- **권장:** `CFBundleVersion`이 예약 기능 도입 버전보다 낮을 때만 구버전으로 판정하거나, 실행 시각과 활성화 소켓 유무를 함께 봅니다.

**M-G3 · 실제 오류 · [재현(SSR 렌더링)] 연결 중·해제 중 터널이 "연결됨/No Handshake"로 표시되고 tray·Dock과 어긋남**
- **위치:** helper의 `ActiveTunnels`에 connecting과 disconnecting이 포함됨(`tunnel/manager_status.go:278`). 프론트는 이를 "연결됨"으로 씀(`stores/tunnels.js:36-53`, `TunnelDetail.svelte:231-235`, `TunnelList.svelte:16`, `App.svelte:679`). 그래서 `isConnecting` 분기에 도달하지 않습니다.
- **권장:** `lib/tunnel-state.js` 하나에 Go의 `connectedStatusIndicators`와 같은 규칙을 두고 목록·상세·배지가 같이 씁니다. node 테스트를 붙입니다.

**M-G4 · 실제 오류 · [추론] 설정 읽기 실패를 숨기고, 이후 저장이 기본값으로 덮어씀**
- **위치:** `Settings.svelte:154-178`, `AutomationEditor.svelte:76-79`
- **문제:** 읽기 실패를 콘솔에만 남기고 기본값이나 빈 규칙으로 편집을 허용합니다. 사용자가 무엇이든 하나 바꾸면 kill switch 설정이나 그 터널의 기존 규칙이 덮어써집니다.
- **권장:** 읽기에 실패하면 오류를 표시하고 편집·저장을 막습니다(M-S3의 patch API와 함께).

**M-G5 · 실제 오류 · [추론] 보안 토글 실패가 사용자에게 보이지 않음**
- **위치:** `Settings.svelte:281-324`
- **문제:** `SetKillSwitch` 등이 실패하면 콘솔에만 남기고 `!현재값`으로 되돌립니다. 그래서 빠르게 두 번 누르면 값이 틀어지고, 실패가 디바운스 저장보다 늦게 오면 적용되지 않은 값이 저장됩니다.
- **권장:** 토글마다 요청을 직렬화하고, 실패하면 이전 값으로 되돌리면서 오류를 표시하는 공통 함수 하나로 묶습니다.

### [추론] medium: Linux/네트워크 백엔드 (실기기·명령 주입 재현 없음)
- **N-2:** 정상 Disconnect에서 DNS 복원이 실패해도 journal과 saved 맵을 지웁니다(`connect_phases.go:428-437,464-468`, `dns_restore_darwin.go:117-125`).
- **N-3:** macOS 전역 DNS 터널이 둘이면 각 매니저의 `lastDNS`가 달라, route 이벤트마다 서로를 drift로 보고 다시 씁니다(`reapply_darwin.go:98-101,230-234`, `monitor_darwin.go:132-152`).
- **N-4:** Linux resolvconf에서 다른 터널이 남아 있으면 `resolvconf -d`를 건너뜁니다(`connect_phases.go:412-437`, `linux.go:832-837`).
- **N-5:** Linux resolv.conf 직접 쓰기에서 두 번째 터널이 `original-dns.json`을 덮어씁니다. 쓰기가 원자적이지 않고 실패는 로그만 남습니다(`linux.go:31,619-625,756-771`).
- **F-2:** Linux kill switch 쪽 문제 세 가지입니다(`linux.go:172-179,222-239,287-296`).
  - 테이블 교체가 `delete table`과 `nft -f`로 나뉘어 그 사이 차단이 풀립니다. 같은 패키지의 DNS 규칙은 한 배치로 처리합니다.
  - Disable이 삭제 전에 플래그를 false로 바꿔, 삭제 실패를 재시도하지 않습니다.
  - `RecoverFromCrash`가 kill switch 테이블을 지우지 않습니다.

---

## 3. Low (실제 개선거리)

| ID | 유형 | 위치 | 내용과 권장 |
|---|---|---|---|
| L-H1 | 실제 오류 [재현] | `helper/profile_ops.go:131-133` | delete가 watchdog 차단을 메모리에서만 지우고 파일에는 반영하지 않습니다. 같은 이름으로 다시 가져온 터널이 automation에서 계속 차단됩니다. |
| L-H2 | 실제 오류 | `firewall/darwin.go:430-436,551-558` | flush는 성공하고 `disablePf`만 실패하면 모델은 enabled인데 규칙이 없는 상태가 됩니다. |
| L-H3 | 실제 오류 [재현, DATA RACE] | `reconnect/monitor.go:216,504` | Stop 중 handover가 끊기면 retry slot이 남고, `stopCh`를 잠금 없이 읽습니다(운영에서는 Start 1회라 영향 낮음). |
| L-H4 | 실제 오류 | `reconnect/sleep_darwin.go:238-257`, `sleep_linux.go:162-175` | 수면 감지 fallback이 monotonic 시간을 비교해 수면 gap을 놓칩니다. `Round(0)`로 wall time을 비교해야 합니다. |
| L-H5 | 실제 오류 | darwin 네트워크 변경 감지 | 2초 cooldown 안의 마지막 상태(trailing edge)를 버립니다. |
| L-H6 | 실패 은닉 | `linux.go:676-681`, Linux `Cleanup/Reset`, darwin/Windows `RemoveRoutes`, `helper/lifetime.go:198` | 실패를 nil로 반환하거나 오류를 버립니다(H-N1과 같은 유형). |
| L-H7 | 성능 | `tunnel/manager_dns.go:13-48` | `Manager.mu`를 잡은 채 fsync를 합니다. |
| L-H8 | 정리 | 다수 | ForceShutdown 주석(1초)과 코드(3초)가 다릅니다. `manager.go:131`에 낡은 "(domain)" 표현이 있습니다. Windows `origDNS`는 쓰이지 않습니다. `helper/ping_health_test.go`가 `internal/app`(Wails cgo)를 import해 `GOOS=linux go vet ./internal/helper`가 cgo 없이 실패합니다. |
| L-S5 | 실제 오류 [재현] | `storage/tunnels.go:184-216`, `:65` | rename 대상에 남은 고아 메타가 새 터널에 붙거나 rename이 실패합니다. 고아 메타 초기화 실패도 무시됩니다. |
| L-S6 | 실제 오류 [재현] | `config/parser.go:89-94` | 값 뒤의 inline `#` 주석을 지원하지 않습니다(wg/wg-quick은 지원). 가져온 설정이 예측대로 동작해야 한다는 원칙에 어긋납니다. |
| L-S7 | 실제 오류 [재현] | `parser.go:161-164,193-196,231-233,250-252` | ExtraKeys가 map이라 Serialize 결과가 50회 중 7가지로 달라지고, 중복 키를 잃습니다. 순서를 지키는 `[]KV`를 권장합니다. |
| L-S8 | 실패 은닉 | `app/tunnel_ops.go:200-206,244-251` | rename/delete 후 규칙 정리 실패를 로그로만 남깁니다. 부분 성공 경고로 반환하기를 권장합니다. |
| L-S9 | 실제 오류 [추론] | `storage/settings.go:154-197` | 손상된 설정 격리 rename이 잠금 밖에서 일어나, 정상 파일을 격리할 수 있습니다. |
| L-S10 | 실패 은닉 | `update/checker.go:344-346`, `scheduler.go:300,311`, `state.go:105-109` | 200이 아닌 응답을 "업데이트 없음"으로 처리합니다. 저장 오류를 버립니다. 메모리를 먼저 바꾼 뒤 저장합니다. |
| L-S11 | 실제 오류 [추론] | `app/import_qr.go:98-110` | Stat보다 open을 먼저 해서 FIFO를 드롭하면 RPC가 멈춥니다. |
| L-S12 | 실제 오류 [추론] | `app/import_zip.go:21-34` | 대소문자를 구분하는 FS에서 대소문자만 다른 이름을 고유 이름 생성이 고려하지 않습니다. |
| L-G1 | 실제 오류 [재현] | `gui/event_bridge.go:62-66`, `App.svelte:183-193` | 이벤트 스트림만 다시 구독해도 `helper_reset`을 보내 `criticalErrors`를 비웁니다. 살아 있는 helper의 critical error 표시가 사라집니다(장애 은닉). |
| L-G2 | 실제 오류 [추론] | `app/tunnel_history.go:233-249` | `reconcileMu`를 잡은 채 10초 `GetStatus`를 호출해, helper가 멈추면 종료가 최대 약 14초 걸립니다. |
| L-G3 | 실제 오류 [추론] | `cli/tunnels.go`(delete) | macOS 소켓 backlog가 가득 차면 ECONNREFUSED가 나서 오프라인 삭제가 허용될 수 있습니다. 오프라인 삭제는 root 소유의 복구 의도를 정리하지 못합니다. |
| L-G4 | 설계 선택 | `helper/profile_ops.go:114-125` | GUI는 활성 transport만 삭제를 거부하고, 재연결·복구 대기 중인 터널은 조용히 철회 후 삭제합니다. 의도라면 UI에 표시해야 합니다. |
| L-G5 | 실제 오류 | `helper/profile_ops.go`(rename) | `handleRename`이 `registerPendingRestore()`를 호출하지 않아, 시작 복구 중 rename하면 의도가 사라질 수 있습니다. |
| L-G6 | 실제 오류 | `cli/tunnels.go:295,342`, `app/tunnel_list.go:68`, `ipc ClientHolder.Set` | 오류를 경고 없이 무시합니다. drain 대기(최대 20초)가 `done`을 보지 않습니다. 종료 뒤의 `Set`이 client를 닫지 않을 수 있습니다. |
| L-G7 | 실제 오류 [추론] | `TunnelDetail.svelte:249-260` | `loadDetail`에 터널 전환 가드가 없어, 늦게 온 A의 응답이 B 화면에 그려질 수 있습니다. |
| L-G8 | 실제 오류 [추론] | `TunnelDetail.svelte:372` | Enter 뒤 blur로 rename이 두 번 호출될 수 있습니다. |
| L-G9 | 실패 은닉 | `main.go:100`, `guiinstance` | 단일 인스턴스 활성화 실패가 `log.Fatal`(stderr)로만 남고, 사용자에게는 앱이 그냥 사라진 것처럼 보입니다. |
| L-G10 | 보안 위생 | `/private/tmp/wireguide-gui-<uid>` | 예측 가능한 공용 경로라 다른 로컬 사용자가 선점하면 실행이 막힙니다(DoS). `_CS_DARWIN_USER_TEMP_DIR` 사용을 권장합니다. |
| L-G11 | 실제 오류 [추론] | `gui/tray.go:435-523`, `event_bridge.go:211` | 아이콘 갱신과 표시 초기화가 서로 다른 잠금 조건에서 네이티브 호출을 해, 배지가 실제 상태와 어긋날 수 있습니다. |
| L-G12 | 정리 | `gui` | 쓰이지 않는 코드가 있습니다(`trayOnIconLight`, `setNativeTrayIcon`, `TrayIconStyle`). `init()`에서 아이콘 4종을 생성하는 비용(측정: 약 0.95ms, 3.6MB, 456회 할당)이 helper·CLI 프로세스에도 붙습니다. |
| L-G13 | i18n | tray 메뉴, 토스트, 배너 | 영어로 고정된 문자열이 있습니다. `$t(k) \|\| 'fallback'`의 fallback은 동작하지 않습니다(키가 없으면 키 문자열이 반환됨). |
| L-G14 | 실제 오류 | `elevate/spawn_windows.go` | `Wait`하지 않아 UAC 취소와 시간 초과를 구분하지 못합니다. |
| L-G15 | 접근성 | 빌드 경고 29건 | 모달 backdrop, dialog의 tabindex, tablist, 드래그 핸들 관련입니다(작성자 문서에도 남김으로 기록). |

---

## 4. 구조 권고 (추상화 수가 아니라 소비자 경계, 책임, 장애 경로 기준)

### 4.1 측정 근거
- **긴 함수**(go/ast, 테스트 제외): `gui.Run` 361줄·분기 42, `tunnel.Manager.connectPhases` 311·53, `helper.Run` 284·33, `reconnect.Monitor.reconnectWithBackoff` 221·31, `network.DarwinManager.reapply` 219·33, `AddRoutes` 208·30, `helper.restoreDesiredTunnels` 196·32, `WindowsManager.addFullTunnelRoutes` 189, `tunnel.NewEngine` 182, `helper.disconnectHeld` 158.
- **패키지 의존 그래프**(darwin/windows/linux): 순환이 없습니다. `domain`은 의존이 없고, `firewall`은 `atomicfile`만, `reconnect`는 `domain`(Windows는 `network`도)만 씁니다. 계층 방향은 대체로 맞습니다.

### 4.2 Go
1. **helper 접속 정책 한 곳으로 모으기 (가장 효과가 큼).** CLI의 `dialHelper` / `dialHelperStrict` / `dialHelperRaw`와 명령별 fallback이 제각각이라 M-I1, M-I2, M-I5가 생겼습니다. `contactHelper()`가 `Absent / NotRunning / Unreachable / Incompatible(minor)` 같은 결과 유형을 돌려주고, 변경 명령은 모두 이를 쓰게 합니다. GUI의 "백그라운드 재연결 정책"도 OS별 함수 하나로 모읍니다(M-I4). `newClient`의 handshake Ping 결과를 노출하면, 지금 Ping을 다시 보내는 6곳이 정리됩니다.
2. **health 확인을 제어 연결에서 분리합니다(M-I3).** `startHelperHealthMonitor`는 ping, in-flight 추정, 스트림 복구, 알림, 복구가 한 루프에 섞여 있고, in-flight 표시를 호출하는 쪽이 기억해야 하는 구조입니다.
3. **helper의 "caller holds connectMu" 계약.** `ksApplied`, `fwSuspendDepth` 등이 주석으로만 보호됩니다. M-H2, M-H4가 바로 이 계약을 어긴 경로입니다. 잠금 순서 문서를 한 곳에 두고, 테스트 빌드에서 계약 위반을 잡는 검사를 권합니다.
4. **`helper/desired_state.go`(694줄)를 나눕니다.** 파일 형식과 boot 판정, pending 레지스트리, restore 오케스트레이션이라는 세 가지 변경 이유가 섞여 있습니다. `desired_store.go` / `pending_restore.go` / `restore.go`로 나누기를 권합니다. `helper.Run`(284줄)은 배선, 복구, goroutine 시작 단계로 나눕니다.
5. **`gui.Run`(361줄)을 단계별로 나눕니다.** 예약, helper 연결과 재시도, 창 생성, 종료 정리, 백그라운드 작업 단계입니다. 종료 정리를 함수로 빼면 H-G1의 `ShouldQuit`과 tray Quit이 같은 경로를 쓰고, 종료 순서를 테스트할 수 있습니다.
6. **`reconnectWithBackoff`의 중복.** "현재 entry이면 삭제" 블록이 5번, backoff 계산이 3번 반복됩니다. 두 도우미로 빼면 M-H1의 수명 처리(wg 포함)를 한 곳에서 고칠 수 있습니다. `helper/reconnect.go:105-109`는 `alreadyConnectedIsOK`와 중복입니다.
7. **network 백엔드.** `linux.go`(943줄)와 `windows.go`(830줄)를 darwin처럼 routes/dns/persist로 나눕니다. darwin의 DNS 캡처, 복원 쓰기, bypass 삭제 루프가 2~3번씩 중복되는데, 하나로 모으면 H-N1과 L-H6의 오류 집계를 한 번에 고칠 수 있습니다.
8. **firewall.** darwin의 `pfWasEnabled`, `WasEnabled`, `isPfEnabled()`는 이제 결정에 쓰이지 않고 쓰기만 됩니다(실제 결정은 토큰과 PID로 함). `windows.go`(795줄)는 세션 수명과 필터 관리로 나누면 좋습니다.
9. **패키지 경계.**
   - `wifi`가 규칙 모델(automation, rules, settle)과 OS 감지(CoreWLAN cgo, route, gateway)를 함께 갖고 있습니다. 그래서 규칙 타입만 쓰는 `storage`와 `cli`까지 플랫폼 감지 코드를 끌어옵니다. 규칙 모델을 순수 패키지(예: `internal/automation`)로 분리하면 소비자 경계와 맞습니다.
   - 앱 버전이 `update.CurrentVersion()`에 있어서, `helper`와 `elevate`가 버전 문자열 하나 때문에 업데이트 다운로드·서명 패키지에 의존합니다. 작은 `version` 패키지를 권합니다.
   - 운영 패키지 `update`가 `testing`을 import합니다(`checkUpdateURL`, `activePublicKey`). build tag나 주입 방식으로 바꾸기를 권합니다.
10. **storage.** `TunnelStore.Rename`(약 90줄)을 `resolveInside` / `checkRenameTarget` / `moveConfigAndMeta`로 나눕니다. `preCheckWritable`의 hardlink probe는 효과가 없으므로 제거를 권합니다. 쓰이지 않는 코드(`Scheduler.Latest`, `ResetNotifyMemory`, NUL 구분을 분리하지 않는 `domain.Scripts()`)도 있습니다.
11. **gofmt 미적용 파일.** 예: `internal/domain/config.go`, `internal/update/require_signed_release.go`, `internal/cli/install_skills.go`. CI에 `gofmt -l` 검사를 넣기를 권합니다.

### 4.3 Svelte
1. **`lib/tunnel-state.js`.** 터널 상태 판정 함수를 하나로 둡니다(M-G3). 목록, 상세, 사이드바 배지, StatsDashboard가 같이 쓰고 node 테스트를 붙입니다.
2. **`stores/settings.js`.** App과 Settings가 따로 하는 settings 읽기를 하나로 합치고, 실패 상태와 patch 저장을 소유하게 합니다(M-S3, M-G4, M-G5를 한 곳에서 해결).
3. **공통 `Modal.svelte`.** backdrop, Escape, 포커스, role, tabindex 처리가 대화상자 8곳에 중복돼 있습니다. 접근성 경고 대부분이 여기서 해결됩니다.
4. **`App.svelte`(1431줄, 이 중 약 577줄이 CSS).**
   - 가져오기 함수 7개 → `lib/import-flow.js`(기존 `imports.js` 테스트 방식 그대로 적용 가능)
   - 편집 모달 → `TunnelEditorModal.svelte`
   - 토스트 → `stores/toast.js`
   - `CriticalErrorBanner`, `Sidebar` 분리
5. **`TunnelDetail.svelte`.** 메모와 지연 측정 대상의 디바운스 저장 로직을 `createDebouncedSaver` 하나로 합칩니다. `InlineRename`을 분리합니다(L-G8 수정과 함께). 세 곳에 중복된 `formatBytes`는 `lib/format.js`로 옮깁니다.
6. **`Settings.svelte`(1182줄).** 탭별 컴포넌트로 나누고, 업데이트 로직은 About 탭으로 모읍니다.
7. **Go GUI.** `tray.go`의 아이콘 그리기(22-331행)를 `tray_icons.go`로 옮깁니다. `runtime.GOOS`로 흩어진 tray 분기는 native tray와 Wails tray를 나눈 작은 인터페이스로 정리합니다. 두 구현이 이미 완전히 다르게 동작하므로 실제 소비자 경계에 맞습니다.

---

## 5. 프로젝트 정체성과의 합치

- **잘 맞는 부분:**
  - 일반 GUI와 권한 있는 helper의 분리, 그리고 그 경계의 IPC
  - 수동 On/Off 존중: `reconnectFn`이 connectMu 아래에서 latch와 cache를 다시 확인함
  - Windows WFP와 PF 소유권의 실패 처리 규율
- **약한 부분:**
  - "실패를 숨기지 않는다": 0절의 유형 1. 각 계층에서 반복됩니다.
  - "종료와 복구의 신뢰성": 유형 2
  - "권한 분리": H-S1. root helper가 사용자 경로를 신뢰합니다.
- 이 세 가지는 개별 수정과 함께, 리뷰 체크리스트(오류를 nil로 바꾸는 코드, 종료 경로 목록, root에서의 사용자 경로 접근)로 남길 것을 권합니다.

---

## 6. 확인한 결과 올바른 부분 (근거)

- **IPC `SubscribeContext`:**
  - Close가 구독 응답 대기를 끊고, 교체 시 이전 연결을 닫습니다.
  - 실패하면 정리하고, `releaseSubscription`은 자기 연결이 맞는지 확인한 뒤에만 지웁니다.
  - Close와 Subscribe가 경쟁해도 `eventMu` 아래에서 `IsClosed`를 다시 확인합니다.
  - 부분 쓰기가 일어나면 연결을 닫고 마감 시간을 복구합니다(q1 코드 확인과 race 통과).
- **Windows 파이프 "없음"과 "사용 중" 구분:** go-winio의 `ERROR_PIPE_BUSY` 재시도와 `PathError{Errno}` 감싸기에 근거해 올바릅니다.
- **Tunnel.Delete(helper 쪽):** connectMu 아래에서 상태 확인, 의도 철회, 파일 삭제를 함께 처리합니다. GUI가 활성 터널 삭제를 거부하고, CLI는 끊은 뒤 삭제하며 headless helper도 씁니다. 기존 테스트가 통과합니다.
- **minor 버전 확인:** 설치 경로는 업그레이드하고, macOS 백그라운드 경로는 재실행을 안내합니다(Windows/Linux는 M-I4).
- **history:** `reconcileMu`와 `historyClosed` latch로 종료 뒤 들어온 이벤트를 무시합니다.
- **storage 잠금:** 호출마다 새로 열어서 같은 프로세스 안의 서로 다른 store 사이에서도 잠금이 충돌합니다. `O_EXCL`로 lock을 만들고 chown하므로 symlink 악용이 없습니다(디렉터리 symlink는 H-S1). `UpdateMeta`와 `SaveMeta`의 존재 확인은 잠금 안에서 일어납니다.
- **atomicfile, ZIP·QR·설정 크기 경계, update scheduler 직렬화와 304 처리, 서명 검증 순서:** q2가 확인했습니다.
- **PF 소유권:** `-s References`의 정확한 토큰 열과 PID를 대조합니다. 조회 실패는 보수적으로 처리하고, PID 없는 journal로는 해제하지 않으며, boot UUID가 다르면 건너뜁니다.
- **macOS DNS 체크포인트:** OS에 쓰기 전에 기록하고, 기록이 실패하면 쓰기를 막습니다. 세대 번호가 있고, 여러 터널이 같은 원본 기준을 씁니다.
- **네이티브 리소스와 스레드:** native tray의 KVO 해제와 release 순서, cgo 버퍼 복사, Windows HICON 해제와 COM 스레드가 맞습니다. 배지 브러시 재사용은 측정상 호출당 2회, 20B 할당입니다(시작 시에만 실행되어 효과는 작음).
- **프론트엔드 구독 정리:** `createEventScope`와 각 컴포넌트의 onDestroy가 맞게 되어 있습니다. en/ko/ja 키와 자리표시자가 일치합니다.
- **reconnect, tunnel의 의존 방향:** `tunnel/errors.go`와 `status.go`는 순수 별칭이고 순환이 없습니다.

---

## 7. 실행한 명령과 결과

공통 환경 변수는 `GOTMPDIR=TMPDIR=/Volumes/SSD/AppData/korjwl1/gotmp`입니다. GOCACHE는 원래부터 `/Volumes/SSD/AppData/korjwl1/cache/go-build`였습니다.

| 명령 (`base` 사본) | 결과 |
|---|---|
| `go version` | go1.26.9 darwin/arm64 |
| `npm test` / `npm run build` | 8/8 통과 / 성공. 접근성 경고 있음(q4 집계 29건) |
| `go vet ./...` (darwin), `GOOS=windows go vet ./internal/...`, `GOOS=linux go vet` (firewall/network/tunnel/diag/storage/ipc) | 모두 통과 |
| `go test -race -count=1 ./...` | 20개 internal 패키지 모두 ok, DATA RACE 경고 0 |
| 검토자별 race 테스트 (재현 테스트 추가 전) | q1 ipc/cli/app/gui ok · q2 storage/config/domain/update/app/atomicfile ok · q3 helper/reconnect/tunnel/firewall/network/wifi ok · q4 gui/guiinstance/elevate/launchd ok |
| Claude가 직접 다시 실행한 재현 테스트 | q2 `TestReview*`(storage) · q1 `TestQ1*`(gui, cli; HOME은 임시 디렉터리) · q3 `TestQ3*`(network, helper, tunnel, firewall). 위에 [재현]으로 적은 결과와 같음 |
| 측정 | 함수 길이와 분기 수(go/ast), 패키지 의존 그래프(3개 OS, `go list`) |

재현 테스트 위치(사본에만 있음):
- `q1/internal/{cli,gui}/review_q1_test.go`
- `q2/internal/storage/review_repro_test.go`
- `q3/internal/**/*_q3review_test.go`
- `q4/internal/guiinstance/review_legacy_race_darwin_test.go`, `q4/internal/gui/review_init_bench_test.go`, `q4/tools/termprobe*`, `q4/frontend/review/*`

### 환경 사항
- 리뷰 중 부트 볼륨이 가득 차서(ENOSPC) 일부 셸 실행이 실패했습니다. Codex가 이 작업의 비활성 검증 바이너리 11개를 보존 이동해 공간을 확보한 뒤 영향을 받은 재현 테스트를 모두 다시 실행했고, 결과는 위와 같습니다. ENOSPC로 실패한 실행은 결함 판정에 쓰지 않았습니다.
- q3 검토자가 원인으로 추정한 "기본 GOCACHE가 부트 볼륨에 쌓임"은 사실이 아닙니다. GOCACHE는 원래부터 SSD에 있었습니다.
- 부트 볼륨 사용량의 대부분은 Data 볼륨(197Gi)과 swap 파일(5GiB)이고, 이번 리뷰의 산출물은 아닙니다. 사용자 파일이나 캐시는 정리하지 않았습니다.

## 8. 미검증 범위
- 실기기 미검증:
  - macOS: 실제 Cmd+Q 종료 시나리오(설치된 앱에서는 시험하지 않음), LaunchServices의 실제 지연(M-G2), 다른 VPN이나 full tunnel 상태의 경로
  - Windows: UAC 반복(M-I4), 공유 위반(M-S4)
  - Linux: resolvconf/nft 동작(N-2~N-5, F-2)
  - 실제 잠자기와 깨우기는 요청에 따라 보류했습니다.
- 현재 설치되어 실행 중인 앱은 `930dc4a`/IPC 1.3이라, 이번 HEAD의 동작은 실행해 보지 않았습니다.

## 9. 우선순위 제안
1. **즉시:** H-S1(보안), H-G1(macOS 종료), H-N1(DNS 복원 오류 은닉)
2. **다음:** 종료·수명 묶음(M-H1, M-H2, M-H3), 상태 일관성(M-H4, M-H5, M-F1, M-S2, M-S3), helper 접속 정책 통합(M-I1~M-I5, 구조 4.2-1·4.2-2)
3. **GUI:** M-G2~M-G5와 Svelte 구조 4.3-1·4.3-2(상태 판정과 settings store)
4. **이후:** 3절의 low 항목, 4절의 나머지 구조 정리. D-1(KS 일시 해제)은 정책 결정이 필요합니다.
