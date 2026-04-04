# Implementation Plan: WireGuide Phase 3+4 — Advanced Features

**Branch**: `003-phase3-features` | **Date**: 2026-04-05 | **Spec**: [spec.md](./spec.md)

## Clarification Decisions

| # | 질문 | 결정 |
|---|------|------|
| 1 | 앱별 스플릿 터널링 | **제외** — README에 "향후 검토" 기재 |
| 2 | 자동 업데이트 범위 | **자동 설치까지** (다운로드 + 설치) |
| 3 | 멀티 터널 충돌 | **CIDR 겹침 검사 + 외부 인터페이스(Tailscale 등) 감지** |

## Summary

Phase 3+4는 편의 기능과 고급 기능을 추가한다. WiFi 자동 연결, 스플릿 터널링 UI, 통계 대시보드, QR import, 키 생성, 자동 업데이트, 미니 모드, 진단 도구, 키보드 단축키, 멀티 터널(충돌 감지), DNS 테스트, 라우트 시각화.

## Phases (5 phases)

### Phase 1: WiFi Auto-connect + Split Tunneling UI
P1 기능. WiFi SSID 감지 + 자동 연결 규칙 + AllowedIPs 프리셋 UI.

### Phase 2: QR Import + Key Generation + Stats Dashboard
P2 기능. QR 디코딩, 키페어 생성, 실시간 속도 그래프 + 연결 이력.

### Phase 3: Auto-update + Multi-tunnel + Conflict Detection
자동 업데이트(GitHub Releases), 동시 멀티 터널, 라우팅 충돌 감지(Tailscale 등 외부 포함).

### Phase 4: Mini Mode + Keyboard Shortcuts + Diagnostics
미니 모드 위젯, Cmd+1~9 단축키, CIDR 계산기, 속도 테스트.

### Phase 5: DNS Leak Test + Route Visualization + Polish
DNS 누출 테스트, 라우트 시각화, README 업데이트.
