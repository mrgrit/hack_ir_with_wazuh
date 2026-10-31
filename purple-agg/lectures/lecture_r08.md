# 퍼플 집계 R08 — C2·유출 — 규칙성과 볼륨

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

석 달 내내 한 시간마다 같은 곳, 이름이 긴 DNS 질의 수백 개, 새벽의 대용량 업로드 — 규칙성과 볼륨

## 2. 시나리오 (로그로만 재현)

```
R08 C2·유출 — 석 달 내내 한 시간마다 같은 곳, 이름이 긴 DNS 질의 수백 개, 새벽의 대용량 업로드.

Red(로그로만 재현) — 감염 PC KT66-WIN-01(10.20.70.10)
  1) HTTPS 비콘: D-80 부터 1시간(±25%) 간격 — 사용자가 없는 밤·주말에도
  2) 비표준 포트 백업 채널 8443: 실제 로그 재방문 패턴으로 드문드문
  3) DNS 터널: 서브도메인에 데이터를 실은 TXT 질의 — 세 번의 새벽(실제 로그 시간대 분포)
  4) 유출: D-1 새벽 파일 공유 서비스로 300~800MB 업로드 6회
Blue: 내부 출발지별 흐름 → 감염 PC 목적지 → 일별·시간대 규칙성 → 도메인별 서브도메인 수 → 업로드 합계 → 포트 분포
```

## 3. 데이터

- 총 2,447,143건 · 공격 3,273건 · 정상(배경 포함) 99.866%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 사용자존(10.20.70.x) 출발지별 외부 연결 수 (상위 5) | 사용자존 출발지별 외부 연결 수 — 감염 PC 가 꼭 1위는 아니다. | Split rows: Terms `data.src_ip` size 5 |
| Q2 | KT66-WIN-01(10.20.70.10)의 목적지 상위 — 포트·활동 일수 | 목적지별 활동 일수 — 80일 내내 매일 가는 곳은 업데이트 서버이거나 C2 다. | Split rows: Terms `data.dest_ip` size 5 → Split rows: Terms `data.dest_port` size 1 → Split rows: Date Histogram `timestamp` 간격 1d |
| Q3 | 1위 목적지(112.177.128.164) — 6시간 버킷: 밤·주말에도 일정한가 (앞 8개) | 6시간 버킷 — 사람은 밤에 자고 주말에 쉰다. 비콘은 안 쉰다. | Split rows: Date Histogram `timestamp` 간격 6h |
| Q4 | DNS — 등록 도메인별 서로 다른 질의 이름 수 · 평균 질의 길이 (상위 5) | 도메인별 '서로 다른 질의 이름 수' — 정상 도메인은 수십, 터널은 수백·수천. | Split rows: Terms `data.domain` size 5 · 정렬 names desc → Metric: Unique Count `data.query` → Metric: Average `data.query_len` |
| Q5 | 내부 → 외부 업로드 합계(bytes_toserver, MB) 상위 목적지 | 업로드 합계(MB) — 평소 KB 단위인 PC 가 새벽에 GB. | Split rows: Terms `data.dest_ip` size 5 · 정렬 up desc → Metric: Sum `data.flow.bytes_toserver` → Metric: Unique Count `data.src_ip` |
| Q6 | 사용자존 외부 연결 — 목적지 포트 분포 | 목적지 포트 분포 — 443 이 대부분인데 8443 이 끼어 있다. | Split rows: Terms `data.dest_port` size 5 → Metric: Unique Count `data.src_ip` |

**모니터:** 서로 다른 서브도메인 200개 이상을 질의한 도메인 (DNS 터널 후보) — 트리거 `ctx.results[0].aggregations.dom.buckets.size() > 0`

![스크린샷: r08 핵심 집계 시각화](images/r08-viz.png)

## 5. 규칙 팩 (`rules/r08/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9608001 | PURPLE R08 DNS tunnel - 40+ hex char label |
| Suricata | 9608002 | PURPLE R08 user zone to external 8443 (non-standard TLS) |
| Suricata | 9608003 | PURPLE R08 large upload over TLS (>100MB, stream) |
| Wazuh | 190801 (L5) | PURPLE R08: 16진수 40자 이상 서브도메인 질의 $(query) from $(srcip) |
| Wazuh | 190802 (L12) | PURPLE R08: 15분에 긴 서브도메인 질의 100회 이상 $(srcip) — DNS 터널 [빈도 100/900s] |
| Wazuh | 190803 (L6) | PURPLE R08: 사용자 PC → 외부 8443 흐름 $(dest_ip) |
| Wazuh | 190804 (L10) | PURPLE R08: 하루에 같은 외부 8443 목적지로 10회 이상 — 백업 C2 채널 [빈도 10/86400s] |
| Wazuh | 190805 (L3) | PURPLE R08: 사용자 PC → 외부 443 흐름 |
| Wazuh | 190806 (L8) | PURPLE R08: 하루 22회 이상 같은 PC→같은 외부 443 — 비콘 후보 (규칙성은 집계로 확인) [빈도 22/86400s] |
| Sigma | 단건 | PURPLE R08 Long Hex Subdomain Query |
| Sigma | 상관 | PURPLE R08 DNS Tunnel - 100 queries in 15 min |
| osquery | purple_r08_8443 | R08: 비표준 포트 외부 연결 프로세스 (Windows/Linux 공용) |
| osquery | purple_r08_dns_cache | R08: (Windows) DNS 캐시의 긴 이름 |
| Sysmon | DnsQuery | rules/r08/sysmon.xml |
| Sysmon | NetworkConnect | rules/r08/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

C2·유출 목적지를 kt66-fw egress 블록리스트(nft set)에 넣고 감염 PC(10.20.70.10) 격리. DNS 터널 도메인은 DNS 싱크홀.

![스크린샷: r08 대응 기록](images/r08-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
