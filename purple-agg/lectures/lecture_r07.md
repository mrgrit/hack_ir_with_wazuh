# 퍼플 집계 R07 — 내부 이동 — 계정 하나, 서버 여러 대

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

계정 하나가 10분 안에 서버 여러 대로 — 계정×시간 버킷×서로 다른 호스트 수

## 2. 시나리오 (로그로만 재현)

```
R07 내부 이동 — 관리자 계정 하나가 10분 안에 서버 여러 대로 퍼진다.

Red(로그로만 재현) — 탈취한 관리자 계정 kim.minjun
  1) D-45~D-4: 새벽에 해외 IP 로 bastion 로그인 후 서버 1대씩 '둘러보기'(실제 로그 재방문 패턴)
  2) D-3 01:20: bastion → 서버존 포트 스캔 → 8분 안에 서버 6대 SSH, dvwa 실패
  3) neobank → KT66-WIN-01 네트워크 로그온(유형 3) → 서비스 실행 → 계정 생성·관리자 그룹 추가
Blue: 계정×10분×호스트 수 → bastion 해외 로그인 → 동서 스캔 → 로그온 유형 → 그룹 변경 → 타임라인
```

## 3. 데이터

- 총 2,444,140건 · 공격 135건 · 정상(배경 포함) 99.994%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | bastion 경유 서버 로그인 — 계정 × 10분 × 서로 다른 서버 수 (4대 이상만) | 관리자도 하루에 여러 서버에 들어간다. 다른 것은 속도 — 10분에 4대 이상. | Split rows: Terms `data.srcuser` size 20 → Split rows: Date Histogram `timestamp` 간격 10m → Metric: Unique Count `agent.name` → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |
| Q2 | bastion 로그인 성공 — 외부 출발지 국가별 계정 | bastion 에 외부 IP 가 직접 붙었다 — VPN 없이 들어온 관리자 계정. | Split rows: Terms `GeoLocation.country_name` size 4 → Split rows: Terms `data.srcuser` size 3 |
| Q3 | 서버존(10.20.40.x)으로 들어온 동서 연결 — 출발지별 포트·목적지 수 | 서버존으로 들어온 동서 연결 — 출발지 하나가 포트 15개 × 서버 7대. | Split rows: Terms `data.src_ip` size 5 · 정렬 ports desc → Metric: Unique Count `data.dest_port` → Metric: Unique Count `data.dest_ip` |
| Q4 | KT66-WIN-01 로그온 성공(4624) — 유형 × 출발 IP | PC 에 '네트워크 로그온(유형 3)'이 서버에서 왔다 — 방향이 거꾸로다. | Split rows: Terms `data.win.eventdata.logonType` size 4 → Split rows: Terms `data.win.eventdata.ipAddress` size 2 |
| Q5 | KT66-WIN-01 레벨 8 이상 경보 | 그 PC 의 레벨 8+ 경보 — 계정 생성·관리자 그룹 변경. | Split rows: Terms `rule.description` size 4 → Split rows: Terms `data.win.eventdata.targetUserName` size 1 |
| Q6 | kim.minjun·svc_backup·neobank발 로그온 — 10분 버킷 중 4건 이상만, 호스트별 | 관련 계정·호스트만 10분 버킷으로 — 확산의 순서가 보인다. | Split rows: Date Histogram `timestamp` 간격 10m → Split rows: Terms `agent.name` size 8 → 조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로 |

**모니터:** 한 계정이 10분 안에 서버 4대 이상 로그인 — 트리거 `ctx.results[0].aggregations.u.buckets.stream().anyMatch(b -> b.t.buckets.size() > 0)`

![스크린샷: r07 핵심 집계 시각화](images/r07-viz.png)

## 5. 규칙 팩 (`rules/r07/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9607001 | PURPLE R07 east-west port sweep from bastion |
| Suricata | 9607002 | PURPLE R07 server zone to user PC SMB - lateral movement |
| Suricata | 9607003 | PURPLE R07 bastion SSH fan-out - 5 servers in 10 min |
| Wazuh | 190701 (L3) | PURPLE R07: bastion 경유 SSH 로그인 $(dstuser) |
| Wazuh | 190702 (L12) | PURPLE R07: 한 계정 $(dstuser) 이 10분 안에 bastion 경유로 서버 4대 이상 로그인 — 내부 확산 [빈도 4/600s] |
| Wazuh | 190703 (L12) | PURPLE R07: 외부 IP $(srcip) 에서 bastion 직접 로그인 $(dstuser) |
| Wazuh | 190704 (L10) | PURPLE R07: 서버존에서 사용자 PC 로 네트워크 로그온(유형 3) $(win.eventdata.targetUserName) |
| Wazuh | 190705 (L13) | PURPLE R07: 원격 서비스 실행(PsExec 계열) $(win.eventdata.newProcessName) |
| Wazuh | 190706 (L15) | PURPLE R07: 서버발 네트워크 로그온 15분 안에 관리자 그룹 변경 — 내부 이동 후 지속성 [순서 900s] |
| Sigma | 단건 | PURPLE R07 SSH Login via Bastion |
| Sigma | 상관 | PURPLE R07 One Account Fans Out (4 logins in 10 min) |
| osquery | purple_r07_ssh_sources | R07: bastion 이 아닌 곳에서 들어온 SSH 로그인(서버→서버) |
| osquery | purple_r07_outbound_ssh | R07: 서버에서 다른 서버로 나가는 SSH |
| Sysmon | ProcessCreate | rules/r07/sysmon.xml |
| Sysmon | NetworkConnect | rules/r07/sysmon.xml |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

190702·190706 → kim.minjun 세션 강제 종료·비밀번호 재설정, svc_backup 비활성·관리자 그룹 원복. 190703 → bastion 에서 외부 IP 1시간 차단(firewall-drop local).

![스크린샷: r07 대응 기록](images/r07-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
