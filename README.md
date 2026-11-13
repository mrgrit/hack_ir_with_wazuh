# hack_ir_with_wazuh — 공격을 만들고 Wazuh 로 찾는 실습

| 모듈 | 내용 | 파일 |
|---|---|---|
| Module 01 | Wazuh 위협 탐지 DQL 예시집 — 웹·리눅스·Windows·통합 61개 + osquery 2개, 고급: 90일 로그 상관분석 | [`slides/`](slides/) (PPTX·PDF, 726장) |
| Module 02 | 집계 기초 (신규) — 왜 집계인가, Terms·Cardinality·Date Histogram·Filters·Sum/Max/Avg·bucket_selector, Dev Tools·Visualize | [`slides/`](slides/) Module02 (PPTX·PDF) |
| Module 03 | 집계 기반 침해분석·대응 — PURPLE 13개 라운드(R01~R15), 라운드당 90일 240만 건을 집계로 추적 | [`slides/`](slides/) Module03 (PPTX·PDF) · 번들 [`purple-agg/`](purple-agg/) |

- 모든 실습을 실습 인프라 [kt66](https://github.com/mrgrit/kt66) 에서 **직접 실행·캡처**했다 (2026-10-31~11-01, Wazuh 4.10.0, OpenSearch 7.10.2).
- **프로젝터용 재구성**: 글씨를 큼직하게 키우고, 화면 캡처는 한 페이지에 하나씩만 크게 넣어 뒷자리에서도 보이도록 했다. 그래서 한 예시가 개념 → 개요 → 공격 실행 → 검색 준비 → 결과 화면(결과 수·결과 표·펼친 문서) → 읽는 법 순서로 여러 장에 나뉜다.
- 슬라이드 구성: 예시마다 공격 실행(터미널 화면 + 구문 풀이)과 SIEM 에서 찾기(클릭·입력 순서 + 결과 읽는 법)가 이어지고, 처음 보는 개념은 개념 슬라이드(SQLi·XSS·Log4Shell·리버스 셸·Sysmon·LSASS·MITRE ATT&CK·osquery …)로 먼저 설명한다.
- 학생은 대시보드에서 직접 클릭·입력한다. 고급편의 집계도 Discover·Visualize·Dev Tools 에서 손으로 한다.

## 책 시리즈 — 해킹·침해대응 실무 with Wazuh

이 저장소의 모듈을 원천으로 책을 쓴다. 1·2권은 실습별 구성, 3권부터는 공격기법마다 공격 → 개념 → 분석 → 파이썬 모듈 → AI 대응을 한 단원에서 끝내는 종단 구성이다. 전체 계획은 [`docs/집필계획.md`](docs/집필계획.md).

| 권 | 제목 | 상태 | 저장소 |
|---|---|---|---|
| 1권 | 시스템 침투와 SIEM 분석 (Module 01 실습 01~30·62) | REV04 마스터링, 1~11장·부록 A | [book_1](https://github.com/mrgrit/hack_ir_with_wazuh_book_1) |
| 2권 | Windows 침해 탐지와 통합 보안관제 (실습 31~61·63) | REV01 교정본, 492쪽 | [book_2](https://github.com/mrgrit/hack_ir_with_wazuh_book_2) |
| 3권 | (가제) 공격기법별 탐지와 자동 대응 1 — 리눅스·웹 | 기획 | 미정 |
| 4권 | (가제) 공격기법별 탐지와 자동 대응 2 — Windows·내부 | 기획 | 미정 |
| 5권 | (가제) 통합편 — 킬체인·사각지대·무인 관제 | 기획 | 미정 |

## 문서

- [`docs/집필계획.md`](docs/집필계획.md) — 시리즈 전체 집필 계획 (권별 현황, 3권 이후 종단 단원, 자산 재배치, 정할 것)
- [`docs/Module01_해설.md`](docs/Module01_해설.md) — 실습별 명령·DQL·결과·원본과 달라진 점·읽는 법, 고급편 정답
- [`docs/강사_준비.md`](docs/강사_준비.md) — 수업 전 체크리스트 (Windows Defender 해제, 인덱스 패턴, 공격자 VM 도구, 합성 데이터)
- [`analytics/`](analytics/) — 고급편 합성 데이터 생성기, Dev Tools 집계 쿼리
- [`answers/`](answers/) — 고급편 정답 수치(JSON)

## Module 02·03 — 집계 트랙 (purple-agg)

집계(aggregation) 중심의 침해분석·대응 트랙. 실제 공격은 하지 않고, 라운드별 생성기가 **정상 99.9% + 공격 로그**를 Wazuh 인덱서에 적재해 **집계로 찾고** 규칙으로 막는다. 외부 IP 는 전부 가상이다.

- **Module 02 집계 기초**: 검색(필터) vs 집계, 버킷 vs 지표, 여섯 집계(Terms·Cardinality·Date Histogram·Filters·Sum/Max/Avg·bucket_selector), Dev Tools·Visualize, 축 뒤집기, 결과 읽는 법. 모든 화면을 purple-r01 실제 데이터로 캡처.
- **Module 03 라운드 R01~R15**(로그로 재현 가능한 13개): 라운드마다 시나리오 → 집계 문항(쿼리 화면 + 결과표 + Visualize 따라하기) → 모니터 → 규칙 팩 → 대응. 결과 숫자는 kt66 에서 실제 적재·질의해 동봉 정답 키와 맞췄다(기준일 2026-11-01).
- **번들 [`purple-agg/`](purple-agg/)**: 생성기 13개·정답 키·실습 YAML·강의 MD·규칙 팩(Suricata·ModSecurity·Wazuh·Sigma·osquery·Sysmon). 사용법은 번들 [`README`](purple-agg/README.md).

실행(요약): `python3 r01_baseline.py check` → `gen --anchor 2026-11-01` → `ask Q0` → `dsl Qn`/`ask Qn`. 인덱서 기본 `https://10.20.32.110:9200` (admin).

### 검증하며 고친 것
- 집계 정렬 `order: {"blocked>_count": "desc"}` 는 OpenSearch 7.10 이 거부한다(단일 버킷 filter 집계는 `{"blocked": "desc"}` 로 정렬) — R03 Q2·MON, R09 Q1 수정.
- 라운드 R01·R02·R04·R05·R06·R07·R08·R09·R10·R12·R13·R15 의 모든 집계 문항이 동봉 정답 키와 일치함을 kt66 인덱서에서 확인. 규칙 팩(Sigma 멀티문서·Suricata sid·Wazuh 필드)·실습 YAML 은 그대로 통과.

## Module 01 — 원본 대비 바뀐 점 (요약)

- DQL 61개 중 22개 수정: 특수문자 미이스케이프로 문법 오류 6개, 필드 종류(keyword)·Windows 경로의 두 겹 역슬래시 등으로 결과 0건, kt66 주소 대역 차이, 인덱스 변경(아카이브·취약점 상태)
- '대체·미구성·설치 후' 로 남아 있던 실습을 모두 실제로 동작하게 했다: auditd·Sysmon·osquery·Windows 에이전트·VirusTotal·ClamAV·Active Response·방화벽 로그
- 실습용 Windows 에서는 Defender 를 끈다 (이유와 일시/영구 방법은 슬라이드·강사 준비 문서)
