# 퍼플 집계 R10 — 영향 — 공격인가 장애인가

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

몇 분 사이 수천 건의 파일 변경, 두 달 내내 같은 포트 — 그리고 '공격이 아닌' 장애를 판별한다

## 2. 시나리오 (로그로만 재현)

```
R10 영향(AI 데이터센터) — 몇 분 사이 수천 건의 파일 변경, 두 달 내내 같은 포트, 그리고 '공격이 아닌' 장애.

Red(로그로만 재현)
  1) 크립토마이닝: GPU 존(10.20.50.60) → 풀 서버 3333/tcp(stratum), D-60 부터 낮에는 쉬고 밤에만(시간대 프로파일)
  2) 웹 변조: D-1 08:57 mediforum 첫 화면 교체 → 이후 '/' 응답 크기 급감
  3) 랜섬 준비: D-2 03:00 govportal 공유폴더 1,200개 파일 암호화(.kt66lock 추가·원본 삭제) + 안내문 30개
  (정상) 장애 주입: D-3 14:00~14:25 neobank 백엔드 장애 → 503 급증 (공격 아님)
Blue: FIM 폭주 구간 → 패턴별 파일 → vhost 별 5xx 폭주 → '/' 평균 크기 → GPU 존 포트 → 서버별 FIM·5xx 판별표
```

## 3. 데이터

- 총 2,440,763건 · 공격 3,023건 · 정상(배경 포함) 99.876%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | FIM 이벤트 10분 버킷 — 200건 이상만, 호스트별 | FIM 은 평소 시간당 몇 건 — 10분에 200건+ 이면 대량 변경이다. | Split rows: Date Histogram `timestamp` 간격 10m → Split rows: Terms `agent.name` size 2 → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q2 | govportal FIM — 패턴별 건수 | 패턴별로 보면 '.kt66lock 추가 + 원본 삭제 + 안내문' 세 줄이 같은 수로 맞는다. | Split rows: Filters (1_locked_added / 2_note_added / 3_deleted / 4_modified) |
| Q3 | vhost 별 5xx — 1시간에 30건 이상인 구간 | 5xx 폭주는 공격일 수도, 장애일 수도 — 혼자서는 판별하지 못한다. | Split rows: Terms `data.vhost` size 8 → Split rows: Date Histogram `timestamp` 간격 1h → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q4 | mediforum 첫 화면('/') 평균 응답 크기 — 일별 마지막 5일 | 첫 화면 크기가 하루 만에 1/10 이 됐다 — 내용이 바뀌었다. | Split rows: Date Histogram `timestamp` 간격 1d → Metric: Average `data.bytes` |
| Q5 | GPU 존(10.20.50.x) 외부 연결 — 포트별 건수·연결 지속시간 합(초)·활동 일수 | GPU 존 → 3333 포트, 밤에만, 연결이 길다 — stratum 마이닝. | Split rows: Terms `data.dest_port` size 4 → Metric: Sum `data.flow.age` → Split rows: Date Histogram `timestamp` 간격 1d |
| Q6 | 판별표 — 서버별 FIM 건수 vs 5xx 건수 | 판별표: FIM 폭주 + 5xx 없음 = 랜섬, 5xx 폭주 + FIM 없음 = 장애. | Split rows: Terms `agent.name` size 6 → (하위 필터: decoder.name:syscheck*) → (하위 필터: data.id:5*) |

**모니터:** 10분에 FIM 200건 이상 (대량 변경) — 트리거 `ctx.results[0].aggregations.t.buckets.size() > 0`

![스크린샷: r10 핵심 집계 시각화](images/r10-viz.png)

## 5. 규칙 팩 (`rules/r10/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9610001 | PURPLE R10 GPU zone to stratum mining port |
| Suricata | 9610002 | PURPLE R10 mining pool domain lookup |
| Suricata | 9610003 | PURPLE R10 5xx surge from one vhost - 20 in 10 min (availability - attack or outage?) |
| Wazuh | 191001 (L7) | PURPLE R10: 암호화 확장자 파일 생성 $(file) |
| Wazuh | 191002 (L15) | PURPLE R10: 2분에 암호화 확장자 파일 50개 이상 — 랜섬웨어 암호화 진행 중 [빈도 50/120s] |
| Wazuh | 191003 (L12) | PURPLE R10: 랜섬 안내문 생성 $(file) |
| Wazuh | 191004 (L12) | PURPLE R10: 2분에 파일 삭제 100건 이상 — 대량 삭제 [빈도 100/120s] |
| Wazuh | 191005 (L12) | PURPLE R10: 첫 화면 파일 변경 $(file) — 웹 변조 의심 |
| Wazuh | 191006 (L8) | PURPLE R10: 10분에 5xx 20건 이상 — 가용성 이상 (공격·장애 판별은 집계로) [빈도 20/600s] |
| Wazuh | 191007 (L10) | PURPLE R10: 내부 $(src_ip) → 마이닝 풀 포트 $(dest_ip):$(dest_port) |
| Wazuh | 191008 (L10) | PURPLE R10: 마이닝 풀 도메인 질의 $(query) from $(srcip) |
| Sigma | 단건 | PURPLE R10 Encrypted Extension File Added |
| Sigma | 상관 | PURPLE R10 Ransomware Burst - 50 files in 2 min |
| osquery | purple_r10_lock_count | R10: 공유폴더 암호화 파일 수 (폴더별) |
| osquery | purple_r10_miner_proc | R10: 마이너 프로세스 |
| osquery | purple_r10_pool_sockets | R10: 마이닝 풀 포트 연결 |
| Sysmon | FileCreate | rules/r10/sysmon.xml |
| Sysmon | NetworkConnect | rules/r10/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

191002 → govportal 공유폴더 즉시 읽기 전용·호스트 격리·스냅숏 복구 준비. 191005 → mediforum 첫 화면 원복. 191006(5xx)은 자동 대응하지 않는다(장애일 수 있다). 마이닝 풀은 egress 차단.

![스크린샷: r10 대응 기록](images/r10-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
