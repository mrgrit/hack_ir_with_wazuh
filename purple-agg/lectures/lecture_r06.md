# 퍼플 집계 R06 — 자격증명 접근 — 분산 대입과 피싱

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

IP 당 1~2번뿐인 분산 대입은 IP 별 집계로 안 보인다 — 계정별 '서로 다른 IP 수'로 뒤집어 본다

## 2. 시나리오 (로그로만 재현)

```
R06 자격증명 접근 — IP 당 1~2번뿐인 분산 대입, 낯선 발신 도메인, 두 번째 나라에서의 로그인.

Red(로그로만 재현)
  1) 웹메일 비밀번호 분산 대입(spray): 1,200개 IP(대부분 국내)가 D-60~D-1 에 걸쳐 1~2번씩 — 3개 계정 성공 → 몇 주에 걸쳐 다른 출구 IP 로 재로그인
  2) 피싱: 유사 도메인에서 직원 40명에게 3분 안에 발송 → 1명(lee.yuna) 계정이 해외에서 로그인·메일함 열람
Blue: IP 별 실패(소용없음) → 계정별 실패 IP 수 → 계정별 외부 성공 IP 수 → 해외 성공 → 희귀 발신 도메인 → 메일함 열람량
```

## 3. 데이터

- 총 2,445,007건 · 공격 3,637건 · 정상(배경 포함) 99.851%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 웹메일 로그인 실패 — IP 별 상위 5 (IP 당 횟수) | IP 별 실패 상위는 내부 사용자의 오타(3~4건) — 분산 대입 IP 는 1~2건이라 상위에 없다. IP 기준 임계값(5회)은 아무것도 못 잡는다. | Split rows: Terms `data.srcip` size 5 |
| Q2 | 웹메일 로그인 실패 — 계정별 서로 다른 출발 IP 수 (상위 5) | 축을 뒤집는다: 계정별 '서로 다른 출발 IP 수'. 정상 계정은 1~2, 표적 계정은 수십. | Split rows: Terms `data.srcuser` size 5 · 정렬 ips desc → Metric: Unique Count `data.srcip` |
| Q3 | 웹메일 로그인 성공 — 계정별 서로 다른 '외부' IP 수 (2 이상) | 성공한 외부 IP 가 2곳 이상인 계정 — 본인 + 누군가. | Split rows: Terms `data.srcuser` size 300 · 정렬 ips desc → Metric: Unique Count `data.srcip` → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q4 | 웹메일 로그인 성공 — 국외 출발지 | 국외 출발지 성공 — GeoLocation 집계 한 번이면 끝난다. | Split rows: Terms `data.srcuser` size 5 → Split rows: Terms `GeoLocation.country_name` size 2 |
| Q5 | 수신 메일(전달됨) — 발신 도메인 중 드문 것 (적은 순 3) · 수신자 수 | 발신 도메인을 적은 순으로 — 한 번도 안 보던 유사 도메인이 3분 안에 40명에게. | Split rows: Terms `data.from_domain` size 3 · 정렬 _count asc → Metric: Unique Count `data.to` |
| Q6 | 웹메일 — 서로 다른 메일을 가장 많이 연 IP (상위 5) | 서로 다른 메일(_uid)을 가장 많이 연 IP — 사람은 수백 통을 몇 분에 열지 않는다. | Split rows: Terms `data.srcip` size 5 · 정렬 urls desc → Metric: Unique Count `data.url` |

**모니터:** 외부 IP 2곳 이상에서 로그인에 성공한 웹메일 계정 — 트리거 `ctx.results[0].aggregations.by_user.buckets.size() > 0`

![스크린샷: r06 핵심 집계 시각화](images/r06-viz.png)

## 5. 규칙 팩 (`rules/r06/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9606001 | PURPLE R06 webmail login failure (marker for aggregation) |
| Suricata | 9606002 | PURPLE R06 mailbox bulk read - 100 message views in 10 min |
| ModSecurity | 90602 | PURPLE R06 account %{tx.r06_user} locked - %{resource.fail} failures from many IPs |
| Wazuh | 190601 (L3) | PURPLE R06: 웹메일 로그인 실패 $(srcuser) from $(srcip) |
| Wazuh | 190602 (L3) | PURPLE R06: 웹메일 로그인 성공 $(srcuser) from $(srcip) |
| Wazuh | 190603 (L10) | PURPLE R06: 한 계정 $(srcuser) 을 일주일에 서로 다른 IP 5곳이 실패 — 분산 대입(spray) [빈도 5/604800s] |
| Wazuh | 190604 (L13) | PURPLE R06: 분산 대입 대상 계정 $(srcuser) 의 로그인 성공 — 계정 탈취 의심 [순서 604800s] |
| Wazuh | 190605 (L6) | PURPLE R06: 회사 도메인을 흉내 낸 발신 도메인 $(from) |
| Wazuh | 190606 (L12) | PURPLE R06: 유사 도메인 발신자가 10분에 20명 이상에게 발송 — 피싱 캠페인 [빈도 20/600s] |
| Sigma | 단건 | PURPLE R06 Webmail Login Failure |
| Sigma | 상관 | PURPLE R06 Password Spray - 5 sources per account per week |
| Sigma | 단건 | PURPLE R06 Lookalike Sender Domain |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

190604(분산 대입 대상 계정 로그인 성공) → 계정 세션 폐기·비밀번호 재설정·MFA 강제. IP 차단은 1,200개 IP 에 소용없다. 190606(피싱) → 발신 도메인 차단·수신함 회수.

![스크린샷: r06 대응 기록](images/r06-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
