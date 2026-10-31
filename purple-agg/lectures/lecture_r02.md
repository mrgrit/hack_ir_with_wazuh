# 퍼플 집계 R02 — 정찰·탐색 — 넓게 훑는 IP 찾기

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

많이 온 IP 가 아니라 '넓게 훑은' IP — 고유 URL 수·고유 포트 수·활동 일수로 정찰을 가른다

## 2. 시나리오 (로그로만 재현)

```
R02 정찰·탐색 — 많이 온 IP 가 아니라 '이상하게 넓게 훑은' IP 를 찾는다.

Red(로그로만 재현)
  A: 외부 포트 스캔 — 공개 VIP 8개 × 상위 100포트 (FW DROP + IDS)
  B: 웹 콘텐츠 탐색 — govportal·mediforum 에 경로 사전 대입(평범한 브라우저 UA 로 위장)
  C: 분산 저속 정찰 — 300개 IP 가 neobank API 의 숨은 경로 2개를 1~2번씩
Blue: 요청량 상위(정상 대량 이용자) → 404 상위 → IP별 고유 URL → 경로별 고유 IP → 포트 다양성
```

## 3. 데이터

- 총 2,441,323건 · 공격 1,676건 · 정상(배경 포함) 99.931%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 웹 요청 수 상위 10 IP — 많이 온 IP 는 누구인가 | 요청 수 1위는 대개 정상 대량 사용자(NAT·봇)다 — '많이'는 정찰의 신호가 아니다. | Split rows: Terms `data.srcip` size 10 → Split rows: Terms `data.user_agent` size 1 |
| Q2 | 404 응답을 가장 많이 받은 IP 상위 5 | 404 는 '없는 것을 찾았다'는 뜻 — 404 상위가 첫 번째 거름망이다. | Split rows: Terms `data.srcip` size 5 |
| Q3 | 404 IP 별 서로 다른 URL 수·vhost 수 (고유 URL 순) | 고유 URL 수가 수백인 IP 는 사람이 아니다. 404 건수보다 cardinality 가 정찰을 가른다. | Split rows: Terms `data.srcip` size 5 · 정렬 urls desc → Metric: Unique Count `data.url` → Metric: Unique Count `data.vhost` |
| Q4 | neobank API(/api/) 404 — 경로별 서로 다른 IP 수 | 같은 숨은 경로를 서로 다른 IP 수백 곳이 한두 번씩 — IP 별 집계로는 안 보이고 경로별 집계로만 보인다. | Split rows: Terms `data.url` size 5 · 정렬 ips desc → Metric: Unique Count `data.srcip` |
| Q5 | 숨은 API 경로를 두드린 IP 들의 국가 분포 | 분산 정찰 IP 의 국가 분포 — 한 나라 집중이면 같은 인프라일 가능성. | Split rows: Terms `GeoLocation.country_name` size 6 → Metric: Unique Count `data.srcip` |
| Q6 | 방화벽 차단(DROP) — IP 별 서로 다른 포트·목적지 수·활동 일수 | FW DROP 은 IP 별 '서로 다른 포트 수'로 본다. 포트 40개+ 는 스캔. | Split rows: Terms `data.srcip` size 5 · 정렬 ports desc → Metric: Unique Count `data.dstport` → Metric: Unique Count `data.dstip` → Split rows: Date Histogram `timestamp` 간격 1d |
| Q7 | 두 정찰 IP(142.66.143.170, 221.49.17.120)의 일별 활동 (일 단위, 많은 날 순) | 두 정찰 IP 의 일별 활동 — 하루짜리 폭주와 장기 저속이 섞여 있다. | Split rows: Date Histogram `timestamp` 간격 1d → Split rows: Terms `decoder.name` size 2 |
| Q8 | 404 고유 URL 상위 IP 의 활동 일수·처음·마지막 (장기 정찰 판별) | 처음·마지막·활동 일수로 장기 정찰을 판별한다(실제 로그의 재방문 패턴). | Split rows: Terms `data.srcip` size 5 · 정렬 urls desc → Metric: Unique Count `data.url` → Split rows: Date Histogram `timestamp` 간격 1d → Metric: Min `timestamp` → Metric: Max `timestamp` |

**모니터:** 404 를 받은 서로 다른 URL 이 100개 이상인 IP — 트리거 `ctx.results[0].aggregations.by_ip.buckets.size() > 0`

![스크린샷: r02 핵심 집계 시각화](images/r02-viz.png)

## 5. 규칙 팩 (`rules/r02/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9602001 | PURPLE R02 inbound SYN sweep - 40 SYN/60s from one source |
| Suricata | 9602002 | PURPLE R02 404 storm - 30 not-found responses/120s to one client |
| Suricata | 9602003 | PURPLE R02 hidden neobank API path probe |
| ModSecurity | 90201 | PURPLE R02 hidden API probe |
| ModSecurity | 90203 | PURPLE R02 404 storm - client throttled (%{ip.r02_404}) |
| Wazuh | 190201 (L10) | PURPLE R02: 같은 IP 가 2분에 4xx 30회 이상 — 웹 경로 대입 의심 $(srcip) [빈도 30/120s] |
| Wazuh | 190202 (L6) | PURPLE R02: 숨은 API 경로 탐침 $(srcip) $(url) |
| Wazuh | 190203 (L12) | PURPLE R02: 하루에 서로 다른 IP 20곳이 같은 숨은 API 를 탐침 — 분산 저속 정찰 [빈도 20/86400s] |
| Wazuh | 190204 (L3) | PURPLE R02: FW 차단 $(srcip) → $(dstip):$(dstport) |
| Wazuh | 190205 (L10) | PURPLE R02: 1분에 서로 다른 포트 40개 이상 차단 — 포트 스캔 $(srcip) [빈도 40/60s] |
| Sigma | 단건 | PURPLE R02 Hidden API Path Probe |
| Sigma | 상관 | PURPLE R02 Distributed Probe - 20 sources per day |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

스캔 IP(190205)는 firewall-drop 10분, 분산 정찰(190203)은 IP 차단이 소용없다 → 숨은 API 를 외부에서 404 로 숨기고(ModSec 90201) 경로 자체를 닫는다.

![스크린샷: r02 대응 기록](images/r02-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
