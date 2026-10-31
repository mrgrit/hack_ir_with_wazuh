# 퍼플 집계 R01 — 가시성 베이스라인 — 정상의 모양과 서버발 비콘

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

정상의 모양을 집계로 재고, 그 위에서 서버발 비콘 하나를 찾는다

## 2. 시나리오 (로그로만 재현)

```
R01 운영체제 수립 + 가시성 베이스라인 — 정상의 모양을 집계로 재고, 그 위에서 튀는 것을 본다.

Red(로그로만 재현): juiceshop 서버(10.20.40.81)에 심긴 Caldera sandcat 이 C2 로 30~60초마다 POST /beat.
                   Discovery 명령(whoami·pwd·ls·ifconfig·which)은 로그가 남지 않는다(가시성 0).
Blue: 엔드포인트별 정상 분포 → 서버발 외부 목적지 집계 → 시간 규칙성 → 모니터.
```

## 3. 데이터

- 총 2,444,723건 · 공격 2,262건 · 정상(배경 포함) 99.907%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 이벤트 출처(에이전트)별 분포 — 정상의 모양 ① | 어느 센서가 얼마나 말하는지부터 본다 — 정상의 크기를 모르면 이상의 크기도 모른다. | Split rows: Terms `agent.name` size 15 |
| Q2 | 웹 엔드포인트별 요청 수와 서로 다른 방문 IP 수 — 정상의 모양 ② | 웹 7개 vhost 는 포트가 아니라 각자의 가상 IP(198.51.100.x)를 가진다. 요청 수와 방문 IP 수의 비율이 서비스의 성격이다. | Split rows: Terms `data.vhost` size 10 → Metric: Unique Count `data.srcip` |
| Q3 | 주별 이벤트 추이 (7일 버킷, KST) — 기간 전체의 모양 | 90일 전체를 7일 버킷으로 접으면 계절성·공백·급증이 한 화면에 보인다. | Split rows: Date Histogram `timestamp` 간격 7d |
| Q4 | 서버존(10.20.40.x)에서 밖으로 나간 연결 — 목적지 상위 | 서버는 먼저 말을 걸지 않는다 — 서버존발 외부 연결 중 '출발지 1곳 × 매일'은 사람이 아니라 프로그램이다. | Split rows: Terms `data.dest_ip` size 8 → Metric: Unique Count `data.src_ip` → Split rows: Date Histogram `timestamp` 간격 1d |
| Q5 | 출발지 1곳뿐인 목적지(53.81.8.74) — 일별 요청 수 (가장 많은 날 순) | 같은 목적지의 일별 건수 — 평소 24건(1시간 주기)인데 하루만 수백 건이면 운영자가 붙은 날이다. | Split rows: Date Histogram `timestamp` 간격 1d |
| Q6 | 같은 목적지 요청의 경로·메서드·UA 조합 | 경로·메서드·UA 조합이 하나뿐이면 사람이 아니라 에이전트다. | Split rows: Terms `data.http.url` size 5 → Split rows: Terms `data.http.http_user_agent` size 3 |
| Q7 | 지금 경보(rule.level ≥ 7)는 무엇을 보고 있나 — 상위 5 | 지금의 경보는 무엇을 보고 있나 — 비콘은 경보 상위에 없다(가시성 ✔ 탐지 ✘). | Split rows: Terms `rule.description` size 5 |

**모니터:** 서버존발 외부 목적지 중 출발지가 1곳이고 500회 이상인 곳 (비콘 후보) — 트리거 `ctx.results[0].aggregations.by_dst.buckets.size() > 0`

![스크린샷: r01 핵심 집계 시각화](images/r01-viz.png)

## 5. 규칙 팩 (`rules/r01/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9601001 | PURPLE R01 server-zone HTTP POST to non-80 port (beacon candidate) |
| Suricata | 9601002 | PURPLE R01 Caldera sandcat beacon URI /beat |
| Wazuh | 190101 (L3) | PURPLE R01: 서버존 $(src_ip) → $(dest_ip):$(dest_port) POST $(http.url) |
| Wazuh | 190102 (L10) | PURPLE R01: 같은 서버가 같은 외부 목적지로 하루 20회 이상 POST — 비콘 의심 $(src_ip) → $(dest_ip) [빈도 20/86400s] |
| Sigma | 단건 | PURPLE R01 Server Zone POST to Non-standard Port |
| Sigma | 상관 | PURPLE R01 Beacon - 20 POSTs per day to same destination |
| osquery | purple_r01_outbound_nonstd | R01: 외부 비표준 포트로 연결된 프로세스 (비콘 후보) |
| osquery | purple_r01_tmp_exec | R01: /tmp·/dev/shm 에서 실행 중인 프로세스 (sandcat 기본 드롭 위치) |
| Sysmon | NetworkConnect | rules/r01/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

비콘 목적지는 kt66-fw 의 egress 블록리스트에, 감염 서버는 격리 후보로. 경보(190102)는 purple-ar 가 기록만 한다.

![스크린샷: r01 대응 기록](images/r01-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
