# Walkthrough: WP01 - .conf Parser + Validator

**생성일**: 2026-04-04
**커밋 수**: 1

## 요약
WireGuard .conf 파일의 파싱, 유효성 검사, 직렬화를 구현했다. 외부 INI 라이브러리 없이 직접 파서를 구현하여 의존성을 최소화했다. 18개 테스트가 모두 통과한다.

## 변경된 파일
| 상태 | 파일 | 설명 |
|------|------|------|
| A | internal/config/types.go | Config 타입 정의 + HasScripts/IsFullTunnel 헬퍼 |
| A | internal/config/parser.go | INI 파서 + Serialize 직렬화 |
| A | internal/config/validator.go | 유효성 검사 (키, CIDR, endpoint, 필수 필드) |
| A | internal/config/parser_test.go | 18개 테스트 케이스 |
| D | internal/config/config.go | placeholder 삭제 |

## 주요 결정 사항
- **결정**: gopkg.in/ini.v1 대신 직접 INI 파서 구현
  - **이유**: WireGuard .conf는 매우 단순한 INI (섹션 2종류, key=value만). 외부 의존성 추가보다 ~50줄 직접 구현이 더 가벼움.
  - **고려한 대안**: gopkg.in/ini.v1 — 범용 INI 파서이나 WireGuard 특화 기능(다중 [Peer] 등)에 맞추려면 어차피 래핑 필요.

- **결정**: scripts.go 별도 파일 대신 types.go에 HasScripts()/Scripts() 메서드로 통합
  - **이유**: 스크립트 감지는 단순 필드 체크. 별도 파일의 복잡성이 정당화되지 않음.

- **결정**: Validate()가 에러를 하나씩이 아닌 전체 목록으로 반환
  - **이유**: 사용자에게 모든 문제를 한번에 보여주는 UX 요구사항 (spec FR-003).

## 작업 메모리 노트
> - Parser는 대소문자 무시 (`strings.ToLower`) — WireGuard 공식 도구도 이렇게 동작
> - Validator는 `ValidationResult.Errors` 슬라이스로 모든 에러 수집 — UI에서 목록 표시용
> - `IsFullTunnel()`은 WP03 풀터널 라우팅 분기에서 사용 예정
> - `HasScripts()`는 WP04 ScriptWarning.svelte에서 사용 예정
> - Serialize()는 WP06 export 기능에서 사용 예정

## 커밋
| 해시 | 메시지 |
|------|--------|
| 18649bb | [WP01] Implement .conf parser, validator, and serializer |
