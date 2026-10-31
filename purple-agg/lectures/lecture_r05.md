# 퍼플 집계 R05 — 권한상승·방어회피 — 끊긴 로그도 신호다

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

www-data 의 sudo, /dev/shm 실행, 그리고 '로그가 0건인 시간' — 사라진 로그도 집계하면 신호다

## 2. 시나리오 (로그로만 재현)

```
R05 권한상승·방어회피 — sudo 를 쓰지 않던 계정, /dev/shm 의 [kworker], 그리고 '로그가 끊긴 2시간'.

Red(로그로만 재현) — mediforum(10.20.40.85), www-data 셸에서
  1) sudo -l 실패 반복 → find -exec 로 root 셸   2) /dev/shm 에 커널 스레드 이름으로 위장한 프로세스
  3) auth.log 비우기·history 삭제·wazuh-agent 중지 → 약 2시간 로그 공백   4) 재시작 후 FIM 이 삭제를 보고
Blue: sudo 사용자 분포 → www-data 명령 → 10분 단위 0건 구간 → 수상 경로 실행 → 삭제 파일 → 타임라인
```

## 3. 데이터

- 총 2,457,928건 · 공격 119건 · 정상(배경 포함) 99.995%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | sudo 사용자 × 결과(rule.id) | sudo 를 쓰는 사람은 정해져 있다(관리자 15명). 목록 밖의 이름이 신호다. | Split rows: Terms `data.srcuser` size 20 · 정렬 _key asc → Split rows: Terms `rule.id` size 2 |
| Q2 | www-data 가 sudo 로 실행하려 한 명령 | www-data 가 sudo 로 무엇을 하려 했나 — 명령이 곧 의도다. | Split rows: Terms `data.command` size 5 |
| Q3 | mediforum 이벤트 1시간 단위 — 0건 구간만 | 대량 로그 서버가 1시간 동안 0건이면 장애이거나, 누가 에이전트를 껐다. | Split rows: Date Histogram `timestamp` 간격 1h → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q4 | 실행 파일 경로 — /tmp · /dev/shm 에서 실행된 것 | /tmp·/dev/shm 에서 실행된 파일 — 디스크에 오래 남기지 않으려는 흔적. | Split rows: Terms `data.audit.exe` size 5 → Split rows: Terms `data.audit.auid` size 1 |
| Q5 | 파일 삭제(FIM 553) 경로 | auth.log·bash_history 삭제는 '지우는 행위' 자체가 남는다(FIM 553). | Split rows: Terms `syscheck.path` size 8 |
| Q6 | mediforum 의 root·www-data 명령 (auditd) — 시간순 첫 10줄 | root·www-data 명령을 시간순으로 — 권한상승 전후가 한 줄로 이어진다. | Split rows: Date Histogram `timestamp` 간격 1m → Split rows: Terms `data.audit.command` size 3 |

**모니터:** 대량 로그 서버 4대 중 1시간 동안 이벤트 0건이 된 구간 — 트리거 `ctx.results[0].aggregations.ag.buckets.stream().anyMatch(b -> b.t.buckets.size() > 0)`

![스크린샷: r05 핵심 집계 시각화](images/r05-viz.png)

## 5. 규칙 팩 (`rules/r05/`)

| 도구 | ID | 내용 |
|---|---|---|
| Wazuh | 190501 (L12) | PURPLE R05: 웹 서비스 계정 $(srcuser) 의 sudo 사용 — 권한상승 시도 |
| Wazuh | 190502 (L10) | PURPLE R05: 10분에 sudo 실패 3회 이상 $(srcuser) [빈도 3/600s] |
| Wazuh | 190503 (L10) | PURPLE R05: 대량 로그 서버 에이전트 연결 끊김 — 로그 공백(방어회피) 가능성 |
| Sigma | 단건 | PURPLE R05 Web Service Account sudo |
| osquery | purple_r05_fake_kthread | R05: 커널 스레드처럼 대괄호 이름인데 실행 파일 경로가 있는 프로세스(위장) |
| osquery | purple_r05_shm_exec | R05: 메모리·임시 경로 실행 또는 삭제된 실행 파일 |
| osquery | purple_r05_empty_logs | R05: 비워진 인증 로그·히스토리 |
| osquery | purple_r05_wazuh_agent | R05: wazuh-agent 동작 상태 |
| Sysmon | ProcessCreate | rules/r05/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

190501(서비스 계정 sudo)·190503(에이전트 끊김)은 즉시 담당자 호출. 공백 구간은 다른 센서(IPS·FW)로 메워 그 시간의 행위를 복원한다.

![스크린샷: r05 대응 기록](images/r05-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
