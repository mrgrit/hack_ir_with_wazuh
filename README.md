# hack_ir_with_wazuh — 공격을 만들고 Wazuh 로 찾는 실습

| 모듈 | 내용 | 파일 |
|---|---|---|
| Module 01 | Wazuh 위협 탐지 DQL 예시집 — 웹·리눅스·Windows·통합 61개 + osquery 2개, 고급: 90일 로그 상관분석 | [`slides/`](slides/) (PPTX·PDF, 726장) |

- 모든 실습을 실습 인프라 [kt66](https://github.com/mrgrit/kt66) 에서 **직접 실행·캡처**했다 (2026-10-31, Wazuh 4.10.0).
- **프로젝터용 재구성**: 글씨를 큼직하게 키우고, 화면 캡처는 한 페이지에 하나씩만 크게 넣어 뒷자리에서도 보이도록 했다. 그래서 한 예시가 개념 → 개요 → 공격 실행 → 검색 준비 → 결과 화면(결과 수·결과 표·펼친 문서) → 읽는 법 순서로 여러 장에 나뉜다.
- 슬라이드 구성: 예시마다 공격 실행(터미널 화면 + 구문 풀이)과 SIEM 에서 찾기(클릭·입력 순서 + 결과 읽는 법)가 이어지고, 처음 보는 개념은 개념 슬라이드(SQLi·XSS·Log4Shell·리버스 셸·Sysmon·LSASS·MITRE ATT&CK·osquery …)로 먼저 설명한다.
- 학생은 대시보드에서 직접 클릭·입력한다. 고급편의 집계도 Discover·Visualize·Dev Tools 에서 손으로 한다.

## 문서

- [`docs/Module01_해설.md`](docs/Module01_해설.md) — 실습별 명령·DQL·결과·원본과 달라진 점·읽는 법, 고급편 정답
- [`docs/강사_준비.md`](docs/강사_준비.md) — 수업 전 체크리스트 (Windows Defender 해제, 인덱스 패턴, 공격자 VM 도구, 합성 데이터)
- [`analytics/`](analytics/) — 고급편 합성 데이터 생성기, Dev Tools 집계 쿼리
- [`answers/`](answers/) — 고급편 정답 수치(JSON)

## 원본 대비 바뀐 점 (요약)

- DQL 61개 중 22개 수정: 특수문자 미이스케이프로 문법 오류 6개, 필드 종류(keyword)·Windows 경로의 두 겹 역슬래시 등으로 결과 0건, kt66 주소 대역 차이, 인덱스 변경(아카이브·취약점 상태)
- '대체·미구성·설치 후' 로 남아 있던 실습을 모두 실제로 동작하게 했다: auditd·Sysmon·osquery·Windows 에이전트·VirusTotal·ClamAV·Active Response·방화벽 로그
- 실습용 Windows 에서는 Defender 를 끈다 (이유와 일시/영구 방법은 슬라이드·강사 준비 문서)
