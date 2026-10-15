# 잔여 로직 수정 결과 — 2026-10-15

대상: `0844ca9..f5fc9f1`, 브랜치 `fix/windows-single-instance`.

앞선 작업에서 낮은 우선순위로 남긴 구현 항목을 처리했다. 이 항목들은
프로젝트에 맞지 않아 제외한 기능이 아니었다. 사용자가 요구한 범위인데도
후속 항목으로 남긴 것은 작업을 끝내지 못한 것이었다.

## 반영한 내용

| 항목 | 처리 및 근거 | 커밋 |
|---|---|---|
| Windows 사전 검사 P-1 | 지원하지 않는 split DNS는 킬 스위치를 내리기 전에 거절한다. 플랫폼 어댑터의 읽기 전용 검사를 helper에서 먼저 호출하고, 터널 단계의 검사도 유지한다. Windows 테스트는 disable 호출 0회와 연결 의도·인터페이스 무변경을 확인한다. | `554b342` (#48) |
| 자동 연결 소유권 N-6 | 첫 성공한 연결 의도 기록에 자동 연결 여부를 함께 넣는다. helper 재시작 후 LAN 충돌을 다시 검사하며, 충돌 중에는 pending 의도와 소유권을 유지해 다른 네트워크에서 재시도할 수 있다. 수동 연결·해제는 소유권을 넘겨받거나 제거한다. LAN 충돌은 중복을 억제한 이벤트와 en/ko/ja GUI 메시지로 알린다. | `a7c811b` (#12/#44/#49) |
| PF 소유권 B-6/B-7 | `pfctl -s References`의 정확한 토큰 열로 우리 참조의 생존을 검사한다. 외부 stop 뒤 다른 프로그램이 PF를 켰어도 우리 토큰을 다시 확보한다. 조회 실패는 기존 토큰을 버리거나 새 참조를 중복 확보하는 근거로 쓰지 않는다. | `f8755ec` (#48/#44) |
| 실기기에서 발견한 PF 토큰 재사용 | macOS는 stop 뒤 같은 토큰 숫자를 다른 프로세스에 다시 발급할 수 있었다. 발급 `pfctl` PID와 토큰을 함께 기록·대조하고 종료·크래시 복구에도 같은 확인을 적용한다. 소유권을 증명할 PID가 없는 이전 기록으로는 참조를 해제하지 않는다. | `f634db7` (#48/#44) |
| PF 재시도·연결 B-5/B-1 | 복구 실패는 최대 30초의 backoff를 두고 재시도한다. 실제 주기 작업 본문을 분리해 테스트가 그 본문을 거쳐 repair를 호출하는지 검사한다. | `f8755ec` (#48/#44) |
| DNS 진단 D-1/D-2 | Linux의 알려진 resolved stub은 D-Bus DNS·Domains·DefaultRoute 정책에서 upstream을 구한다. `~.` 소유자가 있으면 그 경로를 우선하고 도메인 전용 링크를 전역 누수 후보로 섞지 않는다. 알 수 없는 중계기는 불완전한 검사로 표시한다. macOS와 Linux 직접 resolver의 IPv6 zone을 보존하고, GUI에는 resolver 범위와 실제 응답에 따른 개별 누수 표시를 전달한다. | `a8cff20`, `f5fc9f1` (#6/#48) |
| 백업 L4-x | 자동화가 바뀌지 않은 저장은 백업 쓰기에 의존하지 않는다. 다운그레이드로 고아가 된 이전 사본은 내용 해시를 붙인 복구 파일에 보존한 뒤 새 백업을 쓴다. 현재 설정만 실행하고, 복구 사본·백업 오류는 설정 화면에 표시한다. | `c89e680` (#12/#6) |
| 종료 P-2 | fallback이 빨리 끝나도 정상 정리에 남은 grace를 제공한다. 정리가 끝난 종료와 제한 시간 초과로 강제 종료한 경우를 구분하며, 후자는 실패 종료로 복구가 가능하게 한다. | `520d20c` (#44/#48) |
| 추가 경쟁 조건 | 시작 복구의 느린 사전 조회 전에 pending 의도를 등록한다. 사용자의 이름 지정·전체 해제가 먼저 읽은 복구 목록보다 우선한다. 소유권도 함께 등록하므로 다른 터널의 자동 연결 정보가 중간 저장에서 사라지지 않는다. 저장소가 없을 때 의도를 유지하고, 빈 복구가 끝난 뒤에는 정상 idle 종료를 다시 예약한다. | `a3fb205` (#44/#49) |

기존 JSON에 자동 연결 정보가 없으면 수동 의도로 취급한다. 이전 버전이
기록하지 않은 연결 출처를 추측해서 사용자의 명시적 경로 정책을 바꾸지
않는다. 새 자동 연결부터 소유권이 함께 기록된다.

## 참고한 API와 적용 방식

- PF: 이 Mac의 Apple `pfctl(8)` 문서에서 `-E`, `-X`, `-s References`를
  확인했다. [Amnezia의 PF 구현](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/platforms/macos/daemon/macosfirewall.cpp)도
  참조 목록으로 소유권을 확인한다. 우리의 구현은 Go 잠금·부팅 UUID·원자적
  복구 기록에 맞추고 부분 문자열 대신 토큰 열을 정확히 비교한다.
- DNS: [systemd의 VPN DNS 안내](https://github.com/systemd/systemd/blob/main/docs/RESOLVED-VPNS.md)와
  [resolve1 API](https://github.com/systemd/systemd/blob/main/man/org.freedesktop.resolve1.xml)의
  구조와 라우팅 정책을 확인했다. 현재 의존성인 godbus를 사용하며, 영문
  `resolvectl` 출력이나 평탄화된 resolver 파일에 의존하지 않는다.

## 검증

- `go test -race ./...` 성공. helper 전체 race 테스트도 별도로 성공했다.
- `go vet ./...` 성공.
- 프런트엔드 Node 테스트 8개와 production build 성공.
- macOS `production,requireSignedRelease` 빌드 성공. 설치된 앱·helper는 교체하지 않았다.
- 종료 grace와 복구 중 수동 Off는 수정 전 실패를 재현한 뒤 수정 후 통과했다.
- Windows 전용 사전 검사 테스트는 교차 컴파일과 Windows CI에서 성공했다.
- [최종 CI 38708013316](https://github.com/korjwl1/wireguide/actions/runs/38708013316)는
  정확히 `f5fc9f1bd4347113f0adf420c450b15d6f1f11d1`에서 macOS·Windows·Linux
  모두 성공했다. Linux/macOS는 race, Windows는 실제 Windows 러너에서
  race 없이 전체 테스트·vet을 실행했다. Linux 실행 파일·DEB 패키징과
  동적 라이브러리 검사도 성공했다.

로컬 로그는 SSD scratch의 `wireguide-followup-*` 파일에 보존했다.
바인딩 생성기는 현재 Go 1.26.9로 재빌드한 고정 Wails 버전을 사용했다.

## 호환성과 실행 범위

구형 IPC 1.2 CLI의 headless pending 판정 C-1은 그 구형 실행 파일의
클라이언트 로직이다. 현재 배포에 묶이는 CLI는 1.3 메타데이터를 사용한다.
새 helper가 구형 CLI의 "요청을 보내기 전에 종료"하는 코드를 바꿀 수는
없으므로 설치된 앱과 함께 제공되는 CLI를 사용해야 한다.

OS 호출이 멈추면 제한 시간 안에 반드시 정리를 끝내는 보장은 할 수 없다.
종료 감독자·최종 fallback·복구 기록으로 그 실패를 처리한다. 이는
미구현한 재시도 기능과 구분되는 실행 한계다.

최신 PF 수정 `f634db7`의 [확장 macOS 실기기 시험](macos-native-verification-20261015.md)은
24.08초에 통과했다. 외부 PF stop/start와 다른 소유자의 종료, 전역 DNS 터널
두 개의 강제 종료·복구를 추가 검증했다. DNS·기본 경로·인터페이스가 원복됐고,
전체 Go race 테스트와 vet도 다시 통과했다. 실제 잠자기·물리 네트워크 이동·
Windows WFP 패킷·여러 Linux 배포판의 resolved 실행 검증은 별도다.

최근 이슈 본문·댓글 및 PR #50–#53 통합의 구현 보완을 기록한 문서다.
#28 프로토콜 추가, #36 직접 설치용 자동 업데이트, #47 RPM PR 같은
별도 기능·패키징 백로그의 완료를 선언하지 않는다. main 병합·원본 PR
닫기·릴리스 발행은 수행하지 않았다.
