# 퍼플 집계 R03 — 초기 침투(웹) — 차단 뒤 통과로 바뀐 IP

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

차단(403)이 반복되던 IP 가 어느 순간 통과(200)로 바뀐다 — 같은 IP 의 응답 코드 구성비로 WAF 우회를 찾는다

## 2. 시나리오 (로그로만 재현)

```
R03 초기 침투(웹) — WAF 에 막히다가 어느 순간 '통과하기 시작한' IP 를 집계로 잡는다.

Red(로그로만 재현) — 공격자 X, 표적 neobank(10.20.40.83)
  1) 경로 탐색(소량) → 2) /api/history?page= 에 SQLi 대입 — WAF 차단(403)
  3) 인코딩·주석·대소문자 섞기로 우회 — 200·500 응답  4) UNION 덤프 — 응답 크기 수 MB
Blue: WAF 차단 상위(교육용 DVWA 소음 구분) → 같은 IP 의 차단·통과 동시 존재 → 응답 크기 이상 → 우회 패턴 → 500 → 타임라인
```

## 3. 데이터

- 총 2,442,618건 · 공격 1,490건 · 정상(배경 포함) 99.939%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | WAF 차단 상위 IP 와 대상 vhost | WAF 가 막은 것부터 — 차단이 많은 IP 는 '시도한' IP 다. | Split rows: Terms `data.srcip` size 6 → Split rows: Terms `data.vhost` size 1 |
| Q2 | neobank — 같은 IP 의 차단(403)·통과(200)·오류(500) 동시 집계 (차단 순) | filters 집계로 403·200·500 을 같은 IP 버킷에 나란히 — 403 만 있는 IP 와 403+200 이 같이 있는 IP 는 전혀 다르다. | Split rows: Terms `data.srcip` size 5 · 정렬 blocked>_count desc → (하위 필터: data.id:"403") → (하위 필터: data.id:"200") → (하위 필터: data.id:"500") |
| Q3 | neobank /api/history — IP 별 최대·평균 응답 크기 (최대 순) | 응답 크기의 최대값이 평균의 수백 배면 그 요청이 덤프다. | Split rows: Terms `data.srcip` size 5 · 정렬 mx desc → Metric: Max `data.bytes` → Metric: Average `data.bytes` → Metric: Sum `data.bytes` |
| Q4 | WAF 를 통과한 요청의 우회 흔적 — 패턴별 건수 | 통과한 요청 안에 우회 흔적(주석·이중 인코딩)이 있으면 CRS 가 놓친 것이다. | Split rows: Filters (2_double_enc / 3_mixed_case / 4_char_fn / 5_newline) |
| Q5 | neobank 500 응답 상위 IP | 500 은 쿼리가 깨졌다는 뜻 — SQLi 도구가 문법을 맞추는 과정의 흔적. | Split rows: Terms `data.srcip` size 5 |
| Q6 | 공격 IP 218.136.73.91 의 10분 단위 응답 코드 흐름 (본 공격일) | 10분 버킷으로 403 → 200 전환 시점을 본다. 전환 시각이 '우회 성공' 시각이다. | Split rows: Date Histogram `timestamp` 간격 10m → Split rows: Terms `data.id` size 4 |
| Q7 | 공격 IP 218.136.73.91 — 활동 일수와 처음·마지막 접근 (장기 탐침) | 본 공격 전 몇 주의 탐침 — 처음·마지막·활동 일수. | Split rows: Terms `data.srcip` size 1 → Split rows: Date Histogram `timestamp` 간격 1d → Metric: Min `timestamp` → Metric: Max `timestamp` |

**모니터:** 같은 IP 가 같은 사이트에서 403 20회 이상 + 200 20회 이상 (차단 뒤 통과) — 트리거 `ctx.results[0].aggregations.by_ip.buckets.size() > 0`

![스크린샷: r03 핵심 집계 시각화](images/r03-viz.png)

## 5. 규칙 팩 (`rules/r03/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9603001 | PURPLE R03 SQLi obfuscation - inline comment + UNION (mixed case) |
| Suricata | 9603002 | PURPLE R03 SQLi obfuscation - double URL encoding of quote |
| Suricata | 9603003 | PURPLE R03 SQLi tool cadence - 50 /api/history param requests in 5 min |
| ModSecurity | 90301 | PURPLE R03 double URL encoding |
| ModSecurity | 90302 | PURPLE R03 SQL inline-comment obfuscation |
| ModSecurity | 90304 | PURPLE R03 repeat offender (%{ip.r03_blocks} blocks) |
| Wazuh | 190301 (L8) | PURPLE R03: 10분에 /api/history 4xx 20회 이상 $(srcip) — SQLi 대입 중 [빈도 20/600s] |
| Wazuh | 190302 (L13) | PURPLE R03: 차단이 반복되던 $(srcip) 의 SQLi 요청이 200 으로 통과 — WAF 우회 성공 [순서 7200s] |
| Sigma | 단건 | PURPLE R03 SQLi Request Blocked |
| Sigma | 단건 | PURPLE R03 Obfuscated SQLi Passed |
| Sigma | 상관 | PURPLE R03 Blocked then Bypassed (same source) |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

190302(차단→통과) 발생 시 그 IP 를 즉시 차단(firewall-drop 30분)하고, 통과한 우회 패턴을 ModSec 90301·90302 로 막는다. 덤프된 기간의 /api/history 응답은 유출 범위 산정에 쓴다.

![스크린샷: r03 대응 기록](images/r03-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
