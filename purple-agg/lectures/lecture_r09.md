# 퍼플 집계 R09 — 중간 종합 — 석 달짜리 체인

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

R03~R08 의 집계를 한 인덱스에서 다시 쓰고, 날짜순으로 이어 붙여 석 달짜리 체인을 복원한다(무예고)

## 2. 시나리오 (로그로만 재현)

```
R09 중간 종합 — 석 달에 걸친 사람 속도의 전체 체인 (R02~R08 기법 결합, 무예고)

Red(로그로만 재현) — 표적 govportal(10.20.40.84) → neobank·mediforum
  ① D-85~D-40 정찰(재방문 패턴)  ② D-35 SQLi: 차단→우회→덤프  ③ D-34 밤 웹셸 업로드·명령
  ④ D-33 권한상승(sudo 오용)·계정 생성·cron  ⑤ D-20 shadow 열람 → govportal 에서 neobank·mediforum 으로 SSH
  ⑥ D-5 neobank → 외부 대용량 전송  ⑦ D-4 로그 삭제
Blue: R03·R04·R05·R07·R08 의 집계를 한 인덱스에서 다시 쓰고, 날짜순으로 이어 붙여 체인을 복원한다.
```

## 3. 데이터

- 총 2,461,018건 · 공격 862건 · 정상(배경 포함) 99.965%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 차단 20회+ · 통과 20회+ 를 함께 가진 외부 IP (R03 기법) | R03 기법 — 같은 IP 의 차단 20+ · 통과 20+. | Split rows: Terms `data.srcip` size 100 · 정렬 blocked>_count desc → (하위 필터: data.id:"403") → (하위 필터: data.id:"200") → Metric: Max `data.bytes` → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q2 | 웹서버 프로세스(apache2)가 실행한 셸 — 호스트별 (R04 기법) | R04 기법 — 웹서버가 띄운 셸. | Split rows: Terms `agent.name` size 5 |
| Q3 | 관리자가 아닌 sudo 사용자 (R05 기법) | R05 기법 — 관리자 목록 밖의 sudo 사용자. | Split rows: Terms `data.srcuser` size 5 → Split rows: Terms `agent.name` size 2 |
| Q4 | 서버존 출발 SSH (bastion 이 아닌 곳에서 들어온 로그인) (R07 기법) | R07 기법 — bastion 이 아닌 서버에서 들어온 SSH. | Split rows: Terms `agent.name` size 5 → Split rows: Terms `rule.id` size 2 |
| Q5 | 서버존 → 외부 업로드 합계 MB 상위 (R08 기법) | R08 기법 — 서버존 → 외부 업로드 합계. | Split rows: Terms `data.dest_ip` size 3 · 정렬 up desc → Metric: Sum `data.flow.bytes_toserver` → Metric: Unique Count `data.src_ip` |
| Q6 | 체인 복원 — 공격 관련 이벤트의 날짜별·종류별 건수 | 모든 단계를 날짜×종류로 — 석 달짜리 체인이 한 표에 선다. | Split rows: Date Histogram `timestamp` 간격 1d → Split rows: Terms `decoder.name` size 4 |

**모니터:** 서버존 IP 에서 들어온 SSH 로그인 성공 — 트리거 `ctx.results[0].aggregations.tgt.buckets.size() > 0`

![스크린샷: r09 핵심 집계 시각화](images/r09-viz.png)

## 5. 규칙 팩 (`rules/r09/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9609001 | PURPLE R09 server-to-server SSH (not via bastion) |
| Suricata | 9609002 | PURPLE R09 server zone large upload (>100MB) |
| ModSecurity | 90901 | PURPLE R09 script under /files (govportal upload dir) |
| Wazuh | 190901 (L10) | PURPLE R09: 서버존 출발지 $(srcip) 에서 서버로 SSH 로그인 $(dstuser) — bastion 을 거치지 않음 |
| Wazuh | 190902 (L13) | PURPLE R09: 서버→서버 SSH 실패 직후 성공 $(srcip) — 탈취 자격증명 재사용 [순서 300s] |
| Wazuh | 190903 (L12) | PURPLE R09: 로그·히스토리 삭제 $(file) — 흔적 지우기 |
| Wazuh | 190904 (L12) | PURPLE R09: govportal 파일 폴더에 스크립트 생성 $(file) |
| Sigma | 단건 | PURPLE R09 Server-to-Server SSH Login |
| Sigma | 단건 | PURPLE R09 Log File Deleted |
| osquery | purple_r09_shadow_readers | R09: shadow 를 여는 프로세스 |
| osquery | purple_r09_new_cron | R09: 최근 7일 /etc/cron.d 변경 |
| osquery | purple_r09_lastlog_s2s | R09: 서버존 출발 로그인 |
| osquery | purple_r05_empty_logs | R05: 비워진 인증 로그·히스토리 |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

체인 전체를 한 번에 끊는다: 웹셸·계정·cron 제거(govportal), deploy 키 교체(neobank·mediforum), 유출 목적지 차단, 로그 삭제 구간은 IPS·FW 로 복원.

![스크린샷: r09 대응 기록](images/r09-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
