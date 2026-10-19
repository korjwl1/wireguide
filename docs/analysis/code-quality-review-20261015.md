# 코드 구조·안정성·성능·보안 검토 — 2026-10-15

> 최종 확인(2026-10-16): 기능·안내 코드 219d7a5의 Windows/macOS/Linux CI가 모두 통과했다. 프런트엔드 15개 테스트와 Chrome 반례 재검증, Claude 후속 검토도 완료했다. 재연결 중 방화벽 일시 해제는 기존 정책으로 남기고 노출 구간을 UI·README에 명시했다.
검토 시작: `1ae75d5`, 브랜치: `fix/windows-single-instance`.
첫 검토의 최종 기능 변경 검증 대상: `ef31b4f`.
이후 [미완료 로직 후속 작업](remaining-logic-20261015.md)은 `f5fc9f1`까지
추가 수정한 내용과 별도의 검증 결과를 기록한다.

## 설계 판단

현재 프로그램의 기본 패키지 경계는 유지하는 편이 맞다. `domain`은
표준 라이브러리에만 의존하고, `app`/`gui`는 Wails 쪽 어댑터,
`helper`는 권한 있는 조정자, `tunnel`은 실제 WireGuard 실행 엔진이다.
`tunnel`을 순수 도메인 계층으로 설명하던 주석은 실제 역할에 맞게 고쳤다.
helper가 사용자 저장소를 읽는 것은 자동 연결·복구·이름 변경의 일관성을
위한 의도된 동작이다. GUI만 저장소에 접근한다는 설명도 수정했다.

Go의 [공식 모듈 구성 안내](https://go.dev/doc/modules/layout)와
[코드 리뷰 지침](https://go.dev/wiki/CodeReviewComments)을 기준으로,
응집된 패키지는 유지하고 변경 이유가 다른 코드를 파일로 분리했다.
새 인터페이스는 DNS 변경 전에 원본을 기록하는 실제 경계에 추가했다.
사용자가 직접 끈 터널, 자동화 차단, 같은 부팅 내 복구, GUI 없는 실행의
기존 정책은 유지했다.

주요 분리:

| 기존 파일 | 분리한 책임 |
|---|---|
| `helper/helper.go` | 백그라운드 실행, 소켓 채택, 재연결, 수명 관리, 방화벽 일시 중지, 설정 복원 |
| `network/darwin.go` | 라우트 설치·정리, 네트워크 변경 재적용, DNS 적용, DNS 복원·기록 |
| `cli/cli.go` | 터널 명령, 자동화 명령, 설정 명령, 진단 |
| `update/checker.go` | 다운로드, 서명, 체크섬, 플랫폼별 자산 선택 |
| `firewall/windows.go` | DNS 정책과 필터 수명 관리 |
| `app/file_ops.go` | ZIP 가져오기, QR/제한된 파일 읽기, 설정 편집·내보내기 |
| `frontend/src/App.svelte` | 가져오기 변환·이름 생성, 이벤트 구독 소유권 |

운영체제 파일의 suffix와 build constraint를 유지했다. Svelte의 scoped
CSS는 해당 컴포넌트에 남겼다. 파일 길이만 줄이기 위한 CSS 전역화나
제품 화면 개편은 하지 않았다.

## 발견해서 수정한 문제

| 영역 | 수정 내용과 근거 |
|---|---|
| 파일 저장 | `atomicfile`에 임시 파일·파일 sync·교체·실패 시 정리를 모았다. Unix 디렉터리 sync는 지원 여부에 따라 best effort, Windows 교체는 `MoveFileEx`의 replace/write-through를 사용한다. 설정·메타데이터·이력·복구·PF·업데이트 상태에 적용했다. |
| 복구 기록 | 기존 inode를 직접 덮어쓰던 저장을 교체 방식으로 바꿨다. 수정 전 `TestSaveActiveStateReplacesSnapshot`이 실패했다. |
| 설정 잠금 | 잠금 파일을 열거나 잠금을 얻지 못해도 `Save`가 진행하던 경로를 막았다. 수정 전 `TestSettingsSaveFailsWhenLockUnavailable`이 실패했다. |
| 프로필 가져오기 | 존재 검사와 저장을 프로세스 간 잠금으로 묶어 동시 GUI/CLI 가져오기가 기존 개인키를 덮어쓰지 않도록 했다. 두 저장소가 같은 이름을 동시에 가져오는 재현 테스트는 수정 전 두 번 모두 성공했다. |
| 디렉터리 검사 | 쓰기 가능 여부 검사에서 고정 파일명을 만들고 지우던 동작을 고유 임시 파일로 바꿨다. 수정 전 기존 파일이 삭제되는 테스트가 실패했다. |
| QR | 디코딩 전에 헤더의 크기·픽셀 수를 검사한다. 최대 8 MiB, 16 Mi 픽셀, 한 변 8192로 제한한다. 실제 PNG 헤더를 변형한 거절 사례와 정상 QR 디코딩을 검증했다. |
| ZIP | 경로·브라우저 가져오기 모두 압축 크기를 제한한다. 전체 항목 256개, 설정의 선언된 해제량 32 MiB, 항목별 실제 읽기 1 MiB를 검사한다. 전체 예산은 저장 전에 검사한다. 긴 이름의 충돌과 대문자 `.CONF` 처리도 수정했다. |
| 설정 읽기 | CLI와 저장소가 `ParseReader`를 사용해 전체 파일을 먼저 읽지 않도록 했다. 끝없는 입력에서도 1 MiB+1에서 읽기를 멈추는 테스트가 있다. |
| 내보내기 | 기존 파일의 넓은 권한이나 symlink 대상을 그대로 쓰지 않고 새 개인 파일로 교체한다. Unix 파일 권한은 0600이며, Windows 접근 권한은 선택한 디렉터리의 ACL에도 좌우된다. |
| IPC | 이벤트가 없는 상태에서도 끊어진 구독 연결을 감지한다. 쓰기 제한 시간, 짧은 쓰기 처리, 이벤트 프레임 크기 검사를 추가했다. 프레임은 구독자별로 다시 만들지 않고 한 번 만든다. 조용한 연결 종료 재현은 수정 전 실패했다. |
| GUI 수명 | 시작 RPC를 기다리기 전에 이벤트를 등록한다. 컴포넌트 종료 후 뒤늦은 구독을 막고, OS 테마 구독을 해제할 수 있게 했다. 비동기 핸들러 오류도 처리한다. |
| GUI 갱신 | 파일명 목록뿐 아니라 설정 파일 수정과 메타데이터 변경도 감지한다. 임시 파일은 제외하며, 읽기 실패로 가짜 삭제 이벤트를 만들지 않는다. |
| Windows 삭제 | 터널·endpoint 필터 삭제 실패 시 트랜잭션을 abort하고 ID를 보존한다. endpoint 교체도 삭제·추가를 한 트랜잭션으로 처리한다. |
| Windows 정책 | DNS 예외에 터널 LUID 조건을 적용했다. 킬 스위치를 끌 때 공유 세션 전체를 닫지 않고 해당 기능의 필터만 제거하고 DNS 정책을 같은 트랜잭션에서 바꾼다. 다른 보호 기능은 같은 세션에서 계속 유지된다. |
| DNS 원본 기록 | macOS DNS 적용 전에 정확한 원본을 기록한다. 기록 실패는 OS 쓰기를 막는다. 뒤에 연결한 터널의 스냅샷에 앞 터널의 DNS가 들어 있어도, 모든 일반 DNS 터널의 기록은 같은 원본 기준을 사용한다. 새 서비스만 원본 기준에 추가한다. 실패한 기록은 재시도하며 변경 없는 확인은 다시 쓰지 않는다. |

DNS의 적용 전 원본 누락, 여러 터널의 잘못된 원본, 기록 실패 후 변경은
`dns_checkpoint_test.go`에서 수정 전 재현했다. 새 서비스 추가와 동시
스냅샷 갱신도 테스트한다. 기존 버전이 이미 원본 정보를 잃은 기록은
정확한 과거 설정을 재구성할 정보가 없을 수 있다.

## 성능 측정

Apple M4, 같은 입력, 각 변경 전후 동일 Go 버전으로 각각 3회 측정했다.
전체 프로그램 CPU 사용률이나 VPN 전송 속도 개선을 뜻하는 수치는 아니다.

| 경로 | 변경 전 | 변경 후 |
|---|---|---|
| macOS 라우트 512개 정렬, Go 1.25.12 | 약 8.5 ms, 4.97 MB, 227,265회 할당 | 약 0.085 ms, 9,472 B, 1회 할당 |
| macOS 라우트 8개 정렬, Go 1.25.12 | 약 4.2 µs, 2,537 B, 110회 할당 | 약 0.33 µs, 128 B, 1회 할당 |
| 일반 설정 파싱, Go 1.26.9 | 약 4.0 µs, 66,792 B | 약 1.15 µs, 1,496 B |

정렬의 같은 prefix 순서와 호출자 입력을 보존한다. 파서는 짧은 입력에
필요한 버퍼로 시작하고 긴 줄의 기존 1 MiB 상한을 유지한다.
이벤트 기반 SSID 감지, 제한된 로그·통계 버퍼, 구독자 없는 helper의
상태 조회 생략은 유지했다. 버퍼 재사용을 “할당 없음”으로 설명하던
주석도 실제 객체 할당과 구분하도록 고쳤다.

## 보안 의존성

프로젝트가 실제 사용하던 Go 1.25.12로 다시 분석했을 때 표준
라이브러리의 취약 경로가 추가로 확인됐다. 도구 자체가 Go 1.26으로
실행된 첫 검사만으로 결과를 확정하지 않았다.

| 대상 | 변경 |
|---|---|
| Go / CI / 릴리스 빌드 | 1.25.12 → 1.26.9 |
| `golang.org/x/image` | 0.44.0 → 0.45.0: QR의 WebP 디코더 메모리 할당 취약점 |
| `github.com/go-git/go-git/v5` | 5.19.1 → 5.19.2: Wails 경유 참조 경로 취약점 |
| `golang.org/x/net` | 0.57.0 → 0.60.0: HTTP 관련 수정 |
| 관련 최소 의존성 | crypto/sys/text/sync 버전을 위 수정 버전이 요구하는 버전으로 조정 |

수정 후 macOS와 Windows 대상 symbol 검사에서 취약 호출 경로 0건,
취약 패키지 가져오기 0건이다. 모듈 검사에는 사용하지 않는
`x/crypto/openpgp`의 미유지 경고 `GO-2026-5932` 한 건이 남는다.
`npm audit --omit=dev`는 0건이다. 이 검사는 알려진 취약점 검사이며
알려지지 않은 취약점이 없다는 증명은 아니다.

Go 1.26은 Go 1.25와 같은 macOS 12 이상을 지원한다. 실제 Go 요구사항과
맞지 않던 앱 plist와 CGo의 10.15 표기를 12.0으로 맞췄다. Go 1.27은
macOS 13 이상이 필요하므로 이번 수정은 1.26.9를 사용한다.

IPC는 지정한 로컬 사용자에게 VPN 작업을 허용하는 모델이다.
동일 사용자 악성 코드에 대한 바이너리 인증이나 샌드박스로 설명하지
않도록 주석·설계 문서를 고쳤다. 설정의 실행 스크립트는 계속 무시하며,
릴리스 서명 검증과 업데이트 HTTPS/호스트 검사는 유지했다.

근거:

- [Go 취약점 검사 안내](https://go.dev/doc/security/vuln/)
- [WebP 취약점 GO-2026-6222](https://pkg.go.dev/vuln/GO-2026-6222)
- [go-git 취약점 GO-2026-6214](https://pkg.go.dev/vuln/GO-2026-6214)
- [Go 릴리스 이력](https://go.dev/doc/devel/release)
- [Go 최소 OS 요구사항](https://go.dev/wiki/MinimumRequirements)
- [WFP 세션·트랜잭션 규칙](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

## 검증 결과

- 로컬 Go 1.26.9: `go test -race ./...`, `go vet ./...` 성공.
- 프런트엔드: Node 테스트 8개, production build 성공. CI에도 테스트를 추가했다.
- macOS: `production,requireSignedRelease` 태그와 12.0 CGo deployment 설정으로
  실제 실행 파일 빌드 성공. 설치·실행·배포는 하지 않았다.
- [최종 CI 38700138058](https://github.com/korjwl1/wireguide/actions/runs/38700138058):
  정확히 `ef31b4f`에서 Windows·macOS·Linux 모두 성공. Linux 패키징 포함.
  Linux/macOS는 race, Windows는 실제 Windows 러너에서 race 없이 테스트했다.
- macOS 읽기 전용 실기기 검사: 실제 7개 서비스의 DNS·검색 도메인을
  캡처하고 OS 쓰기 전 기록 콜백을 호출하는 순서 확인. 초기 연결과
  이미 활성 상태인 터널의 DNS 재적용 모두 검사했다. 쓰기 호출 0회.
- 관리자 인증 후 `fc70480`에서 시험 실행 파일을 새로 빌드해
  `TestMacOSLiveProductionNetworking` 재시험 성공(12.14초), 독립 복구
  러너 종료 코드 0. 실제 utun 통신, DNS 보호, PF 킬 스위치·주기적 복구,
  helper 강제 종료·복원을 확인했다. DNS·기본 경로·인터페이스 목록은
  전후 바이트 단위로 같고 PF도 원래의 비활성 상태로 돌아왔다.
  세부 범위·실행 파일 해시는 [실기기 검증](macos-native-verification-20261015.md)의
  재시험 기록에 남겼다. 앞서 취소했던 인증 요청과 별도로 실행한 시험이다.
- 실제 잠자기 시험은 사용자의 요청대로 보류했다. Windows 러너의
  필터 테스트는 실제 Windows API 래퍼를 대체하므로 실제 VPN/WFP 패킷
  경로 검증까지 완료했다는 의미는 아니다.

## 남은 판단·검증

1. Svelte 빌드에는 기존 모달·드래그 요소의 접근성 경고가 남아 있다.
   후속 UI 작업은 모달 공통화, 포커스 관리, 키보드 조작을 함께 검증해야 한다.
2. 실제 잠자기·깨우기와 Windows 실기기 패킷 검증이 남아 있다.
   macOS 재시험은 아래 기록의 제한된 범위에 대한 증거이며 전체 GUI
   설치·업그레이드나 실제 네트워크 이동까지 검증한 것은 아니다.
3. PF 참조 소유권 확인, 자동 연결 소유권 지속성, Windows 사전 검사,
   DNS 진단과 백업 처리의 미완료 표시는
   [후속 로직 작업](remaining-logic-20261015.md)의 수정·검증 결과로 갱신했다.
   이전 검토 원문은 당시 상태의 기록으로 보존한다.

커밋마다 관련 이슈 번호를 달아 같은 브랜치에 push했다. main 병합,
기존 PR 닫기, 릴리스 발행은 이 검토의 결과에 포함되지 않는다.

## 전체 재검토 후속 — `fc1c073` → `576ae84`

사용자의 추가 코드 리뷰 요청으로 패키지 의존 관계, 최근 변경의 수명·동시성,
저장소 변경, helper의 연결 전이, GUI 이력, 업데이트 캐시와 프런트엔드의
이벤트·버퍼 수명을 다시 점검했다. 이전에 확인한 전체 프로그램 구조를
바탕으로 오류가 재현되는 경계와 변경 책임을 정리했다.

### 수정

| 커밋 | 수정 |
|---|---|
| `b52f8b3` | 이벤트 구독의 dial/쓰기/응답/직렬화 대기에 context를 적용. 구독 교체와 종료 시 연결을 닫고, 이벤트 스트림만 끊겨도 기존 health tick에서 제어 연결을 유지하며 복구한다. 이전 client 콜백을 걸러내고 잘못된 Wi-Fi·종료 주석을 고쳤다. |
| `6f727bf` | config·metadata 변경과 쌍 읽기에 같은 프로세스 간 파일 잠금을 적용. metadata 존재 확인을 잠금 안으로 옮기고, 새로운 프로필이 남은 sidecar를 상속하지 않게 했다. root가 최초로 만든 잠금은 사용자 디렉터리 소유자에게 돌려준다. metadata 책임은 별도 파일로 분리했다. |
| `b4cebe5` | 공통 작업 오류를 `domain`으로 이동하고 엔진 API는 alias로 호환한다. `reconnect`는 도메인 상태·오류와 소비자 인터페이스에만 의존한다. default Off·열린 무신호 채널을 잘못 설명한 주석도 수정했다. |
| `97f789b` | `Tunnel.Delete`에서 활성 상태 확인·복구 취소·파일 삭제를 helper의 `connectMu` 안에서 직렬화한다. GUI는 활성 삭제를 거부하고 CLI는 먼저 해제한다. headless helper도 사용하며 timeout/권한/프로토콜 오류를 offline으로 취급하지 않는다. IPC 1.4가 필요한 GUI는 같은 앱 버전의 오래된 helper도 setup에서 교체한다. 연결·해제·프로필 handler를 파일로 분리했다. |
| `97f789b` | 목록 생성 중복을 제거하고 다중 활성 터널을 모두 표시한다. 목록과 이력을 파일로 분리하고, 이력 갱신·수동 해제 힌트·종료를 직렬화한다. 종료 뒤 늦게 받은 상태가 이력을 다시 열지 못한다. |
| `674fd5b` | 수동·예약 업데이트 확인을 직렬화한다. 304 응답에도 마지막 정상 릴리스 정보를 유지하고, 새 프로세스는 body 없는 validator만으로 시작하지 않는다. 외부 호출자에게 결과/Latest의 내부 포인터를 노출하지 않는다. |
| `576ae84` | 연결 배지의 brush와 색상 저장소를 픽셀마다 만들지 않고 재사용한다. |

기존 GUI/helper 분리, 도메인의 표준 라이브러리 전용 의존성, OS suffix와
build constraint를 유지했다. `helper`의 파일 구분은 연결·해제·프로필 변경의
책임에 맞췄다. 이번 변경은 Wails/Svelte 화면이나 자동 연결의 제품 정책을
개편하지 않는다. CLI의 오프라인 편집은 실제 absent/refused listener에서
유지한다. 공통 타입의 alias는 기존 Go 호출자 호환을 위한 것이다.

Go 공식 [모듈 구성](https://go.dev/doc/modules/layout)과
[리뷰 지침](https://go.dev/wiki/CodeReviewComments)을 다시 확인했다.
패키지 경계는 의존 방향과 응집도로 판단했다. 예를 들어 저장소의 Wi-Fi
규칙 모델 의존은 현재 설정 JSON·마이그레이션 계약의 일부이며, 이를
새 패키지로 옮기기만 하는 작업은 이번 오류 수정의 필수 조건이 아니다.

### 재현과 검증

- 원본에서 종료한 client의 Subscribe가 성공하고, 두 번째 Subscribe가
  첫 스트림을 남기는 테스트가 실패했다. 수정 후 실제 소켓 테스트 통과.
- 메타데이터 삭제 후 갱신 허용, 독립 저장소의 동시 필드 유실을 수정 전
  재현했다. 수정 후 cross-store 쓰기·기존 저장소 테스트 통과.
- 이력 종료 latch를 뺀 기준에서 늦은 status가 열린 이력을 만드는 테스트가
  실패했다. 수정 후 종료 후 갱신 거부 테스트 통과.
- helper 삭제의 cached recovery 취소·sibling 보존·연결 전이 대기,
  CLI의 headless 요청과 helper 실패 보존, 다중 터널 목록 표시를 검사한다.
- 업데이트의 200→실패→304, 재시작 첫 요청, 외부 snapshot 변경,
  대기 중 취소를 per-instance fetch seam으로 검사한다.
- 전체 `go test -race ./... -count=1` 성공. 최종 이벤트 콜백 순서/취소 보완
  후 `ipc`/`gui` race 재검사도 성공. `go vet ./...` 성공.
- macOS 12 deployment 설정, `production,requireSignedRelease` build 성공.
  프런트엔드 Node 테스트 8개와 production build 성공. 기존 접근성 경고는
  앞 절의 범위와 같다.

Apple M4에서 같은 배지 입력으로 각 3회 측정:

| 배지 그리기 함수 | 이전 | 이후 |
|---|---|---|
| 시간 | 151.9–152.8 µs/op | 85.0–85.1 µs/op |
| 할당 | 74,400 B/op, 7,440 allocs/op | 20 B/op, 2 allocs/op |

이 함수는 초기 아이콘 생성에 사용된다. 전체 앱 CPU·VPN 전송 성능을
측정한 결과로 해석하지 않는다. 기존 픽셀·투명도·상태 전이 테스트도 통과했다.

3-OS CI: [38727991141](https://github.com/korjwl1/wireguide/actions/runs/38727991141),
정확한 코드 SHA `576ae8401015a67eaf6573638d4769550818b866`로 수동 실행했다.
이 기록 작성 시 CI와 기존 Claude 세션의 독립 리뷰는 진행 중이며,
최종 판정은 아래에 추가한다. 이번 후속 검토에서 OS 네트워크 설정이나
실행 중인 설치 앱은 바꾸지 않았다. 실제 잠자기 시험은 계속 보류다.


## 독립 리뷰 반영과 최종 검증

2026-10-15~16 후속 검토는 기존 Claude Code 세션으로 진행했다.
[최초 검토](claude-quality-review-20261015.md),
[core 재검토](claude-quality-core-followup-20261015.md),
[전체 후속 검토](claude-quality-final-review-20261015.md),
[수정 후 최종 재검토](claude-quality-final-followup-20261015.md)를 보존했다.
최종 재검토는 추가 worker 없이 진행했고, 새 blocker가 없다고 판정했다.
리뷰 답변을 그대로 완료 근거로 쓰지 않고 직접 재현과 테스트를 대조했다.

### 구조와 동작

| 영역 | 반영한 내용 |
|---|---|
| 패키지 경계 | 자동화 규칙·판정·settle을 순수 `automation`으로 분리했다. storage/CLI는 OS Wi-Fi 감지에 의존하지 않는다. 버전은 `version`에서 공급한다. |
| 파일·함수 경계 | helper의 저장/대기/복구, Windows·Linux의 DNS/라우팅을 나눴다. GUI 초기 helper 설정과 종료 수명, 연결 rollback을 분리했다. 재시도 슬롯 정리·backoff와 CLI 접속 정책을 공통 함수로 묶었다. |
| 설정 | 선택 필드만 원자적으로 합친다. 읽기 실패 시 편집을 막고, 저장 또는 적용 실패는 필드별 오류·재시도로 표시한다. 다른 writer의 자동화 규칙을 덮어쓰지 않는다. |
| 화면 상태 | 공통 터널 상태 판정, 실제 disconnecting 전달, 상세 응답 세대 검사, rename 중복 방지를 적용했다. 통계는 선택한 연결을 기준으로 집계한다. |
| 프런트 공통 코드 | 프로필 필드 저장 순서와 중복 제거, 공통 모달 포커스·키보드 처리, 공통 오류·재시도 컴포넌트를 사용한다. 영어·한국어·일본어 알림과 native 메뉴를 정리했다. |
| 재접속·종료 | Wi-Fi 콜백과 retry worker를 종료 대기에 포함했다. wall clock과 마지막 네트워크 변화 처리를 보완했다. GUI 정상 종료·tray 종료·시작 실패가 같은 정리 경로를 쓴다. |
| DNS 복구 | 실패 시 원본과 journal을 보존한다. retired journal을 새 세션과 다른 파일로 옮겨 동명 재연결도 기록을 덮어쓰지 않는다. 실패한 시작 복구도 원본을 인계한다. 활성 터널이 없는 동안 재시도하고 사용자에게 경고한다. |
| 방화벽 | Linux 교체를 add→delete→재정의 한 transaction으로 만들었다. 외부 ruleset 삭제 이후에도 복구한다. 삭제 실패 시 모델을 유지한다. macOS PF lease 증거를 보존하고 손상 파일을 격리한다. |
| 파일·IPC | Windows의 열린 reader 충돌을 제한 시간 내 재시도한다. 종료한 ClientHolder의 재등록을 막고 drain을 즉시 취소한다. helper 접속 오류를 부재로 오인하지 않는다. |
| 가져오기·모델 | FIFO를 거부하고 ZIP 이름 대소문자를 확인하며 목록 읽기 오류를 반환한다. inline 주석과 반복 unknown key를 보존하고 ordered entries 하나를 사용한다. |
| 업데이트 | HTTP 실패를 업데이트 없음으로 숨기지 않는다. 저장 실패 시 메모리를 rollback하고 clone 계약을 공통화했다. |

Go 파일은 formatter를 적용하고 CI gate를 추가했다.
관례 판단은 [Go module layout](https://go.dev/doc/modules/layout)와
[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)를 기준으로 했다.
의존 순환은 세 OS 모두 없으며, 순수 모델은 OS나 GUI에 의존하지 않는다.
긴 OS 절차와 composition root를 줄 수만 맞추려고 별도 추상화로 감싸지는 않았다.

Windows 재시도는 실제 CI에서 열린 파일 교체의 `ACCESS_DENIED`를 재현한 뒤
Go [robustio 구현](https://go.dev/src/cmd/internal/robustio/robustio_windows.go)과
[Windows 파일 교체 제약](https://learn.microsoft.com/en-us/windows/win32/fileio/moving-and-replacing-files)을 확인해 보완했다.
1초 상한 뒤에도 실패하는 실제 ACL 오류는 그대로 반환한다.

### 검증 근거

- 로컬 `go test -race -count=1 ./...`, `go vet ./...` 성공.
- macOS 12 설정의 업데이트 서명 검증 활성 production build 성공. 설치 앱은 교체하지 않았다.
- Windows/Linux 대상 package 교차 컴파일 성공. 실제 러너 검증은 아래 CI를 기준으로 한다.
- 프런트엔드 Node **15개**와 production build 성공, 접근성 빌드 경고 **0건**.
- 실제 headless Chrome + 가짜 backend로 설정/자동화 읽기 실패 후 쓰기 차단,
  보안 설정 적용 오류·재시도, 모달 포커스 제한·복원, 키보드 규칙 재정렬을 확인했다.
  브라우저 runtime 오류 0건. 화면의 오류와 재시도 표시도 캡처해 확인했다.
- 수정 전 `632d7c4` 사본에서 DNS journal 유실, inline 주석,
  종료한 holder 재등록·drain 테스트가 실제 실패했다. 수정 후에는 통과했다.
- 영구 cleanup 실패 후 새 연결·동명 재연결, retired journal의 crash 삭제,
  실패한 startup 복구의 원본 보존, 초기 연결 rollback journal을 fake OS로 검사했다.
- `a55c345`의 [CI 38751771573](https://github.com/korjwl1/wireguide/actions/runs/38751771573):
  Windows/macOS/Linux 모두 성공. Linux 격리 network namespace에서
  `TestLinuxKillSwitchInKernel`, `TestLinuxDNSRulesInKernel` 실제 통과.
  Windows에서는 reader handle을 연 채 path/root publication을 실제 검사했다.
- 앞 CI `d39648a`의 Windows 실패는 무시하지 않았다. 오류 코드 누락과 테스트
  shadow를 수정한 뒤 위 CI에서 재검증했다.

프런트엔드 빌드와 Go embed 로딩은 순서대로 실행해야 한다.
중간 검증에서 둘을 겹쳐 실행해 제거된 dist 파일을 찾던 실행은 완료 근거에서
제외하고, 안정된 dist로 전체 race/vet/production build를 다시 성공시켰다.

### 남긴 설계 판단과 실제 환경 범위

- 기존 reconnect의 kill switch/DNS protection 일시 해제 정책(D-1)은 유지했다.
  이 구간에는 물리 NIC로 일반 트래픽이 나갈 수 있다. README의 누출 없음 설명을
  실제 동작에 맞게 수정했다. 차단을 유지하면서 bootstrap DNS와 endpoint UDP만
  허용하는 동작은 별도의 cross-platform 정책 변경이며 이번 수정 완료 주장에 포함하지 않는다.
- retired 작업은 새 세션을 보호하기 위해 활성 터널이 없을 때 정리한다.
  장시간 연결을 유지하면 이전 정리가 지연될 수 있지만 journal과 baseline은 남는다.
- `testing.Testing`으로 production 서명 키 override를 차단하는 기존 gate는 유지했다.
- 실제 macOS 서비스 삭제·resolv.conf 소유 전환·UAC 취소 등의 현장 조합은
  장치 시험으로 단정하지 않는다. 호스트 잠자기 시험은 사용자가 보류했다.
- 설치된 앱, 현재 VPN, 사용자 프로필, OS 네트워크 설정은 이 리뷰 작업에서 변경하지 않았다.

임시 바이너리 11개를 보존 이동한 주체는 Codex다. 이전 보고서의 사용자 이동
표현은 정정했다. 사용자 파일이나 다른 프로젝트 파일을 이동한 것이 아니다.


### 최종 표시 정리

`ErrorNotice.svelte`로 설정·자동화의 오류·재시도 표시를 통합했다.
Claude의 표시 계층 후속 검토도 차단 항목 없음으로 끝났다.
권고한 오류 row key와 `applyField` 이름까지 반영했다.
이 변경은 `a55c345`의 검증된 Go 코드와 비교해 프런트엔드 파일 3개뿐이며,
최신 Node 14개·build·Chrome 시나리오는 다시 통과했다.
당시 표시 정리 검증 SHA는 `55e4edaaf02f7d84894545459788d5ca5f34667b`다.

현재 설정 화면의 킬 스위치 안내도 세 언어에서 같은 한계를 설명하도록
수정했다. 이후 변경은 이 안내 문구와 문서이며 VPN 동작은 바꾸지 않았다.
기능 코드 최종 [CI 38753259307](https://github.com/korjwl1/wireguide/actions/runs/38753259307)
(`55e4edaaf02f7d84894545459788d5ca5f34667b`)는 세 OS 모두 성공했다.
안내 문구도 최신 frontend 15개 테스트·build와 브라우저 검사로 확인했다.


### 마지막 브라우저 반례 보완

- 설정 창 밖에서 바꾼 목록 너비 저장이 실패한 뒤 Retry가
  `settings[key]`의 undefined를 전송해 요청값을 잃는 경로를 실제 Chrome에서
  재현했다(`undefined !== 333`). 공유 store가 필드별 마지막 요청값을
  보존하게 하고, 재시도는 그 값을 쓰도록 수정했다. undefined patch는 RPC
  전에 거부한다. 쓰기 직렬화와 다른 필드 오류 보존은 유지한다.
- 늦은 설정 읽기 중 fieldset에서 상속된 비활성 상태가 `el.disabled`에
  반영되지 않아 모달 초기 포커스가 밖에 남는 경로도 Chrome에서 실패했다.
  `:disabled` 판정으로 수정하고 같은 시나리오가 통과하는 것을 확인했다.
- Node **15개**, build 경고 0, read failure 후 쓰기 차단과 초기 포커스,
  security apply 오류·retry, 포커스 순환·복원, 키보드 규칙 재정렬,
  다른 화면의 목록 폭 retry를 다시 확인했다. browser runtime 오류 0건.
- Claude는 이 네 파일을 추가로 읽고 두 수정이 원인에 맞으며 차단 항목은
  없다고 판정했다. 전체 스캔이나 OS 실험을 반복한 결과로 표현하지 않는다.

마지막 코드·설계 안내 커밋은
`219d7a54cfc20d44bf06d1c68d5ccc96b20568c9`다.
이후 최종 보고서 커밋은 분석 문서만 포함한다.


### 최종 CI 판정

[CI 38758226705](https://github.com/korjwl1/wireguide/actions/runs/38758226705),
정확한 SHA `219d7a54cfc20d44bf06d1c68d5ccc96b20568c9`:

- Windows (test): 성공
- macOS (test): 성공
- Linux (test + package): 성공
- Linux 실제 격리 `TestLinuxKillSwitchInKernel`, `TestLinuxDNSRulesInKernel`: 성공
- 원시 로그의 실패·data race·fatal error 표식: 0건

최신 frontend dist로 macOS production build도 다시 성공했다.
이 최종 보고서 이후 실행 중인 앱이나 환경을 바꾸지 않았으며,
가짜 backend 검증용 localhost 서버만 종료했다.
