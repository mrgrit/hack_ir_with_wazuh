# 퍼플 집계 R15 — 최종 — 혼합 체인과 미끼

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

사람의 느린 체인 + AI 의 빠른 체인 + '허가된 점검·정상 백업'이라는 미끼 — 집계로 찾고 근거로 제외한다

## 2. 시나리오 (로그로만 재현)

```
R15 최종 — 사람의 느린 체인 + AI 의 빠른 체인 + 허가된 점검·정상 백업이라는 '미끼'.

Red(로그로만 재현)
  사람(두 달): D-60 피싱 → park.jiwoo PC(WINWORD → powershell) → 30분±6분 HTTPS 비콘
              → D-21 그 PC 에서 관리자 계정으로 관리콘솔 SSH → D-9·D-3 DNS 터널
  AI(3분): D-1 03:00 챗봇 프롬프트 인젝션 → http_fetch 로 관리콘솔 내부 API(사용자 내보내기) SSRF → 외부 전송
  미끼: ① 허가된 외부 점검업체(D-14, govportal 경로 대입) ② neobank 매일 01시 백업 업로드(정상)
Blue: 지금까지의 집계 기법을 골라 쓰고, 미끼(허용 목록)를 근거와 함께 제외한다.
```

## 3. 데이터

- 총 2,467,369건 · 공격 3,906건 · 정상(배경 포함) 99.842%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | KT66-WIN-01 프로세스 생성 — 부모 × 자식 (드문 쌍) | Windows 프로세스 부모×자식 — WINWORD→powershell 은 정상 PC 에 없다. | Split rows: Terms `data.win.eventdata.parentProcessName` size 4 · 정렬 _count asc → Split rows: Terms `data.win.eventdata.newProcessName` size 2 |
| Q2 | KT66-WIN-01 외부 목적지 — 건수·활동 일수·업로드 MB | PC 의 외부 목적지 — 30분 간격으로 두 달, 업로드는 작게. | Split rows: Terms `data.dest_ip` size 3 → Split rows: Date Histogram `timestamp` 간격 1d → Metric: Sum `data.flow.bytes_toserver` |
| Q3 | 서버 SSH 로그인 — bastion(10.20.30.201)이 아닌 출발지 | bastion 이 아닌 출발지의 서버 SSH — 사용자 PC 에서 관리콘솔로. | Split rows: Terms `data.srcip` size 5 → Split rows: Terms `agent.name` size 2 → Split rows: Terms `data.srcuser` size 1 |
| Q4 | DNS — 서로 다른 질의 이름 200개 이상인 도메인 | 서로 다른 질의 이름 200개+ 도메인 — R08 과 같은 기법, 다른 도메인. | Split rows: Terms `data.domain` size 20 · 정렬 n desc → Metric: Unique Count `data.query` → Split rows: Terms `data.srcip` size 1 → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q5 | 관리콘솔 웹 — 출발지별 요청·응답 합계 MB (내부 출발지 포함) | 관리콘솔 응답 MB — 내부 출발지(AI 서버)가 사용자 내보내기를 대량으로. | Split rows: Terms `data.srcip` size 4 · 정렬 b desc → Metric: Sum `data.bytes` |
| Q6 | 서버존 → 외부 업로드 — 목적지별 MB·활동 일수 (매일 반복 = 정상 백업 후보) | 매일 같은 시각 GB 업로드 = 정상 백업 후보. 미끼를 '근거와 함께' 제외한다. | Split rows: Terms `data.dest_ip` size 4 · 정렬 up desc → Metric: Sum `data.flow.bytes_toserver` → Split rows: Terms `data.src_ip` size 1 → Split rows: Date Histogram `timestamp` 간격 1d |
| Q7 | 404 고유 URL 100개 이상 IP (허용 목록 대조용) | 404 고유 URL 100+ IP — 허가된 점검업체와 대조(허용 목록). | Split rows: Terms `data.srcip` size 20 · 정렬 u desc → Metric: Unique Count `data.url` → Split rows: Terms `data.user_agent` size 1 → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |

**모니터:** bastion 이 아닌 내부 출발지의 서버 SSH 로그인 — 트리거 `ctx.results[0].aggregations.src.buckets.size() > 0`

![스크린샷: r15 핵심 집계 시각화](images/r15-viz.png)

## 5. 규칙 팩 (`rules/r15/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9615000 | PURPLE R15 authorized scanner (allowlist) |
| Suricata | 9615001 | PURPLE R15 AI server calls admin export API (SSRF) |
| Suricata | 9615002 | PURPLE R15 user PC SSH to server (bypass bastion) |
| Suricata | 9615003 | PURPLE R15 DNS tunnel - long hex label |
| ModSecurity | 91501 | PURPLE R15 export API from service host %{REMOTE_ADDR} |
| ModSecurity | 91502 | PURPLE R15 authorized scanner |
| Wazuh | 191501 (L0) | PURPLE R15: 허가된 점검업체 $(srcip) — 경보 억제(허용 목록) |
| Wazuh | 191502 (L0) | PURPLE R15: neobank 정상 백업 업로드 — 억제 |
| Wazuh | 191503 (L12) | PURPLE R15: 사용자 PC $(srcip) 에서 서버로 SSH $(dstuser) — bastion 우회 |
| Wazuh | 191504 (L14) | PURPLE R15: Office 문서가 $(win.eventdata.newProcessName) 실행 — 매크로 초기 침투 |
| Wazuh | 191505 (L13) | PURPLE R15: AI 서버가 관리콘솔 사용자 내보내기 API 호출 $(url) — 도구 SSRF |
| Wazuh | 191506 (L15) | PURPLE R15: 2분에 내보내기 API 10페이지 이상 — 대량 유출 진행 [빈도 10/120s] |
| Sigma | 단건 | PURPLE R15 Office Spawns Shell |
| Sigma | 단건 | PURPLE R15 AI Server Calls Export API |
| Sigma | 상관 | PURPLE R15 Export Burst - 10 pages in 2 min |
| osquery | purple_r15_office_children | R15: (Windows) Office 자식 셸 |
| osquery | purple_r15_beacon_sockets | R15: (Windows) powershell 의 외부 443 연결 |
| Sysmon | ProcessCreate | rules/r15/sysmon.xml |
| Sysmon | DnsQuery | rules/r15/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

허용 목록(점검업체·백업)은 억제 규칙(191501·191502)으로 '알고 허용', 나머지 191503~191506 은 사람·AI 체인 각각 차단·격리. 최종 보고서에 제외 근거(문서·일정·반복성 집계)를 남긴다.

![스크린샷: r15 대응 기록](images/r15-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
