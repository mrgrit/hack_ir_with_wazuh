# 퍼플 집계 R04 — 실행·지속성 — 수천 건 속 한 건

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

수천 건의 정상 업로드·명령 속에서 업로드 폴더의 .php 한 건, apache2→sh 한 쌍을 찾는다

## 2. 시나리오 (로그로만 재현)

```
R04 실행·지속성 — 업로드 이미지 수천 장 속 PHP 한 개, cron 실행 수만 건 속 /tmp 스크립트 하나.

Red(로그로만 재현) — 공격자 W, 표적 mediforum(10.20.40.85)
  1) 이미지로 위장한 웹셸 업로드(FIM 554) → 2) 웹셸로 명령 실행(웹 GET + auditd: apache2 → sh)
  3) 지속성: 계정 생성(5902)·/etc/passwd·shadow 변경·cron.d 추가·root authorized_keys·rc.local
  4) cron 이 10분마다 /tmp/.x/update.sh 실행 (auditd)
Blue: 업로드 FIM 확장자 분포 → 부모-자식 프로세스 쌍 → 업로드 경로 PHP 호출 IP → /etc·/root 변경 → 주기 실행 → 타임라인
```

## 3. 데이터

- 총 2,457,124건 · 공격 997건 · 정상(배경 포함) 99.959%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 파일 추가(FIM 554) — 업로드 폴더 확장자별 | 업로드 폴더에는 이미지가 쌓인다 — 확장자 분포에서 .php 한 줄이 튄다. | Split rows: Filters (1_jpg / 2_png / 3_pdf / 4_php) |
| Q2 | auditd — 부모 프로세스 × 실행 파일 쌍 | 부모×자식 쌍은 대부분 몇 가지로 고정된다. apache2→sh 는 정상에 없다. | Split rows: Terms `data.audit.parent` size 5 → Split rows: Terms `data.audit.exe` size 4 |
| Q3 | 업로드 폴더의 .php 를 호출한 IP | 그 .php 를 부른 IP 는 하나 — 업로드한 IP 와 같은가? | Split rows: Terms `data.srcip` size 5 → Metric: Unique Count `data.url` |
| Q4 | /etc · /root 아래 파일 변경(FIM)과 계정 생성 | /etc·/root 변경과 계정 생성이 웹셸 호출 뒤에 붙어 있으면 지속성 확보다. | Split rows: Terms `agent.name` size 3 → Split rows: Terms `rule.description` size 4 |
| Q5 | cron 이 실행한 파일 — 건수와 처음·마지막 시각 | cron 이 실행한 파일의 처음·마지막 — 몇 주 동안 살아 있었나. | Split rows: Terms `data.audit.exe` size 3 → Metric: Min `timestamp` → Metric: Max `timestamp` → Metric: Unique Count `agent.name` |
| Q6 | mediforum 침투 첫날 타임라인 — 10분 단위 (웹셸 호출·auditd·FIM·계정) | 10분 버킷 타임라인 — 웹셸·auditd·FIM·계정 이벤트가 같은 칸에 모인다. | Split rows: Date Histogram `timestamp` 간격 10m → Split rows: Terms `decoder.name` size 4 |
| Q7 | 웹셸 호출 IP 의 주별 접근 횟수 (장기 잠복) | 웹셸 호출 IP 의 주별 접근 — 한 번 쓰고 버리지 않고 몇 주에 걸쳐 돌아온다. | Split rows: Date Histogram `timestamp` 간격 7d |

**모니터:** 웹서버 프로세스(apache2)가 셸을 실행한 호스트 — 트리거 `ctx.results[0].aggregations.by_agent.buckets.size() > 0`

![스크린샷: r04 핵심 집계 시각화](images/r04-viz.png)

## 5. 규칙 팩 (`rules/r04/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9604001 | PURPLE R04 PHP executed from uploads directory |
| Suricata | 9604002 | PURPLE R04 webshell command parameter (c=) |
| ModSecurity | 90401 | PURPLE R04 script request under /uploads |
| ModSecurity | 90402 | PURPLE R04 PHP upload attempt |
| ModSecurity | 90403 | PURPLE R04 PHP code inside uploaded file |
| Wazuh | 190401 (L12) | PURPLE R04: 업로드 폴더 PHP 호출 $(srcip) $(url) — 웹셸 의심 |
| Wazuh | 190402 (L14) | PURPLE R04: 웹셸 호출 뒤 2시간 안에 계정 생성 $(dstuser) — 지속성 확보 [순서 7200s] |
| Wazuh | 190403 (L12) | PURPLE R04: 업로드 폴더에 스크립트 파일 생성 $(file) |
| Wazuh | 190404 (L12) | PURPLE R04: 지속성 관련 파일 변경 $(file) |
| Sigma | 단건 | PURPLE R04 Webshell Access under Uploads |
| Sigma | 상관 | PURPLE R04 Webshell Used Repeatedly (3 in 1h) |
| osquery | purple_r04_php_in_uploads | R04: 업로드 폴더의 스크립트 파일 |
| osquery | purple_r04_cron_tmp | R04: /tmp·/dev/shm 을 실행하는 cron |
| osquery | purple_r04_new_users | R04: 로그인 가능한 일반 계정 목록(기준선과 비교) |
| osquery | purple_r04_root_keys | R04: root authorized_keys |
| Sysmon | ProcessCreate | rules/r04/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

190401·190403 발생 시 웹셸 파일 격리(이동·해시 기록), 생성 계정 잠금, cron·authorized_keys 원복. purple-ar 은 기록만, 조치는 사람이 확인 후.

![스크린샷: r04 대응 기록](images/r04-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
