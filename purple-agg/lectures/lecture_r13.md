# 퍼플 집계 R13 — AI 레드팀 — 기계 속도의 체인

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

사람이 며칠 걸리는 체인을 3분에 — 기계 속도는 '분·초 단위 집계'에서 튄다

## 2. 시나리오 (로그로만 재현)

```
R13 AI 레드팀 — 사람이 며칠 걸리는 체인을 3분에. 기계 속도는 '분 단위 집계'에서 튄다.

Red(로그로만 재현) — 자율 에이전트(UA python-httpx), 표적 juiceshop → neobank·govportal·mediforum
  · D-30·D-16: 같은 인프라의 '예행 연습' 짧은 폭주 2회 (각 1분, 경로 대입만)
  · D-2 04:11~04:14 본 체인: 경로 대입 420건(52초) → SQLi 120건(차단 40·우회 80, 덤프 4)
    → 탈취 계정 로그인 → node 프로세스가 셸 12회(40초) → juiceshop 에서 서버 3대로 SSH(30초) → neobank 유출
Blue: juice 분당 요청 폭주 → UA 분포 → IP 의 처음·마지막(초) → 분 단위 단계 전이 → SSH 전파 속도 → 경보 레벨
```

## 3. 데이터

- 총 2,471,615건 · 공격 721건 · 정상(배경 포함) 99.971%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | juice.kt66.lab 분당 요청 — 250건 이상인 분 | 정상 피크도 분당 수백 건이지만 '한 IP' 가 아니다 — 분 버킷 + 상위 IP. | Split rows: Date Histogram `timestamp` 간격 1m → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q2 | juice.kt66.lab 의 User-Agent 상위 8 | UA 상위 — python-httpx 는 브라우저가 아니다. | Split rows: Terms `data.user_agent` size 8 |
| Q3 | python-httpx 출발지 — 건수·처음·마지막(초)·활동 일수 | 처음·마지막(초)이 3분 — 사람이 며칠 할 일을 3분에. | Split rows: Terms `data.srcip` size 3 → Metric: Min `timestamp` → Metric: Max `timestamp` → Split rows: Date Histogram `timestamp` 간격 1d |
| Q4 | 체인 단계 전이 — 분 단위 (공격 IP · node 셸 · juiceshop발 SSH · neobank 유출) | 분 단위 단계 전이: 경로 대입 → SQLi → 로그인 → node 셸 → SSH → 유출. | Split rows: Date Histogram `timestamp` 간격 1m → Split rows: Terms `decoder.name` size 4 |
| Q5 | juiceshop(10.20.40.81)에서 나간 SSH — 서버별 성공 시각(초) | 서버 3대 SSH 성공 시각 간격이 수 초 — 사람의 타이핑 속도가 아니다. | Split rows: Terms `agent.name` size 5 · 정렬 t asc → Metric: Min `timestamp` |
| Q6 | 공격 IP 92.10.220.142 관련 경보 레벨 분포 — 레벨 10 이상이 있었나 | 그 IP 의 경보 레벨 — 레벨 10+ 가 있었나? 있었다면 누가 언제 봤나. | Split rows: Terms `rule.level` size 5 |

**모니터:** 한 IP 가 1분에 200건 이상 요청 (기계 속도) — 트리거 `ctx.results[0].aggregations.m.buckets.stream().anyMatch(b -> b.ip.buckets.size() > 0 && b.ip.buckets[0].doc_count >= 200)`

![스크린샷: r13 핵심 집계 시각화](images/r13-viz.png)

## 5. 규칙 팩 (`rules/r13/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9613001 | PURPLE R13 automation client UA (python-httpx/aiohttp/Go) |
| Suricata | 9613002 | PURPLE R13 machine-speed requests - 100 in 20s from one source |
| Suricata | 9613003 | PURPLE R13 rapid server-to-server SSH - 3 targets in 60s |
| ModSecurity | 91302 | PURPLE R13 rate limit - %{ip.r13_req} req/10s |
| ModSecurity | 91303 | PURPLE R13 automation UA (observe) |
| Wazuh | 191301 (L12) | PURPLE R13: 30초에 4xx 100회 $(srcip) — 사람이 낼 수 없는 속도의 경로 대입 [빈도 100/30s] |
| Wazuh | 191302 (L14) | PURPLE R13: 고속 대입 직후 5분 안에 같은 IP 의 SQLi 통과 $(srcip) — 자율 공격 체인 [순서 300s] |
| Wazuh | 191303 (L6) | PURPLE R13: 서버존발 SSH 로그인 $(srcip) → $(hostname) |
| Wazuh | 191304 (L14) | PURPLE R13: 60초에 같은 서버에서 3대로 SSH 성공 $(srcip) — 기계 속도 내부 확산 [빈도 3/60s] |
| Sigma | 단건 | PURPLE R13 Automation Client Request |
| Sigma | 상관 | PURPLE R13 Machine Speed - 100 requests in 30s |
| osquery | purple_r13_node_shell | R13: node(웹앱)가 띄운 셸 — 짧은 interval 로 기계 속도를 따라간다 |
| osquery | purple_r13_ssh_keys_read | R13: SSH 키·known_hosts 를 여는 프로세스 |
| Sysmon | ProcessCreate | rules/r13/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

기계 속도 공격은 사람이 경보를 읽기 전에 끝난다 → 191301 에 firewall-drop(15분) 자동 차단이 의미 있는 유일한 라운드. 191304(고속 확산) → deploy 키 즉시 폐기.

![스크린샷: r13 대응 기록](images/r13-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
