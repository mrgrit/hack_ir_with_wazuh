# 퍼플 집계 R12 — AI 서비스 — 챗봇 로그의 이상치

> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.

## 1. 이 라운드의 질문

챗봇 로그에서 '평범한 사용자는 쓰지 않는 것' — 도구·프롬프트 길이·주입 표지·디버그 경로

## 2. 시나리오 (로그로만 재현)

```
R12 AI 서비스 공격·방어 — 챗봇 로그에서 '평범한 사용자는 쓰지 않는 것'을 집계로 찾는다.

Red(로그로만 재현) — 가입 사용자 u7731042, 표적 aicompanion(10.20.40.87)
  1) D-45~D-4: 프롬프트 인젝션 시도(긴 프롬프트·주입 패턴 표지) — 실제 로그 재방문 패턴
  2) 도구 남용: 일반 사용자에게 없는 http_fetch·file_read·shell 호출 → http_fetch 로 내부 관리콘솔 SSRF
  3) /api/debug/* 로 시스템 프롬프트·설정 노출 시도(404 → 200), RAG 문서 업로드로 오염
Blue: 도구 분포 → 관리 도구 사용자 → 사용자별 프롬프트 길이 → 표지×차단 → 디버그·업로드 경로 → 동서 연결
```

## 3. 데이터

- 총 2,445,975건 · 공격 236건 · 정상(배경 포함) 99.990%
- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.
- 엔드포인트(가상 IP): juice.kt66.lab=198.51.100.81, dvwa.kt66.lab=198.51.100.82, neobank.kt66.lab=198.51.100.83, govportal.kt66.lab=198.51.100.84, mediforum.kt66.lab=198.51.100.85, admin.kt66.lab=198.51.100.86, ai.kt66.lab=198.51.100.87, webmail.kt66.lab=198.51.100.26, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10

## 4. 집계 문항

| 문항 | 질문 | 왜 | Visualize |
|---|---|---|---|
| Q1 | 챗봇 도구 호출 분포 | 도구 호출의 대부분은 none·search — http_fetch·shell 은 일반 사용자에게 없다. | Split rows: Terms `data.ai.tool` size 8 |
| Q2 | 관리용 도구(http_fetch·file_read·shell)를 쓴 사용자 | 관리 도구를 쓴 사용자 — 한 명이 튄다. | Split rows: Terms `data.ai.user` size 5 → Split rows: Terms `data.ai.tool` size 3 |
| Q3 | 사용자별 최대·평균 프롬프트 길이 (최대 순 상위 5) | 프롬프트 길이 최대값 — 정상 사용자는 수백 자, 주입 시도는 수천 자. | Split rows: Terms `data.ai.user` size 5 · 정렬 mx desc → Metric: Max `data.ai.prompt_len` → Metric: Average `data.ai.prompt_len` |
| Q4 | 주입 패턴 표지 × 차단 여부 | 주입 표지가 붙었는데 차단되지 않은 요청 — 방어가 놓친 것. | Split rows: Terms `data.ai.blocked` size 2 → Metric: Unique Count `data.ai.user` |
| Q5 | ai.kt66.lab — 디버그·문서 업로드 경로 호출 IP | /api/debug·/api/docs/upload 를 부른 IP — 404 → 200 순서가 '찾았다'는 뜻. | Split rows: Terms `data.srcip` size 5 → Split rows: Terms `data.id` size 4 |
| Q6 | 관리콘솔(10.20.40.86)로 들어온 동서 연결 — 출발지별 | AI 서버가 관리콘솔에 연결 — 도구(http_fetch) SSRF 의 네트워크 흔적. | Split rows: Terms `data.src_ip` size 4 → Split rows: Terms `data.dest_port` size 2 |

**모니터:** 주입 패턴 표지 20회 이상인 사용자 — 트리거 `ctx.results[0].aggregations.u.buckets.size() > 0`

![스크린샷: r12 핵심 집계 시각화](images/r12-viz.png)

## 5. 규칙 팩 (`rules/r12/`)

| 도구 | ID | 내용 |
|---|---|---|
| Suricata | 9612001 | PURPLE R12 AI debug endpoint access |
| Suricata | 9612002 | PURPLE R12 prompt injection phrase in chat body |
| Suricata | 9612003 | PURPLE R12 AI server to admin console (tool SSRF) |
| ModSecurity | 91201 | PURPLE R12 debug endpoint hidden |
| ModSecurity | 91202 | PURPLE R12 prompt injection phrase |
| ModSecurity | 91203 | PURPLE R12 oversized prompt |
| ModSecurity | 91204 | PURPLE R12 injection phrase inside RAG upload |
| Wazuh | 191201 (L8) | PURPLE R12: 일반 사용자에게 없는 도구 호출 $(ai.tool) by $(srcuser) |
| Wazuh | 191202 (L5) | PURPLE R12: 프롬프트 주입 표지 $(srcuser) (blocked=$(ai.blocked)) |
| Wazuh | 191203 (L12) | PURPLE R12: 한 사용자 $(srcuser) 가 1시간에 주입 표지 10회 이상 — 반복 시도 [빈도 10/3600s] |
| Wazuh | 191204 (L12) | PURPLE R12: 디버그 엔드포인트 200 응답 $(url) to $(srcip) — 설정·시스템 프롬프트 노출 |
| Wazuh | 191205 (L10) | PURPLE R12: AI 서버 → 관리콘솔 연결 — 도구 SSRF 의심 |
| Sigma | 단건 | PURPLE R12 Privileged Tool Call by AI User |
| Sigma | 상관 | PURPLE R12 Tool Abuse - 5 privileged calls per user per hour |
| osquery | purple_r12_ai_children | R12: AI 서비스 프로세스가 띄운 셸·다운로더 (도구 남용) |
| osquery | purple_r12_ai_egress | R12: AI 서비스의 동서 연결 |

검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).

## 6. 대응

191203 → 사용자 정지·세션 폐기, 191204 → /api/debug 외부 차단(ModSec 91201), 191205 → AI 서버 egress 를 허용 목록으로 제한. 오염된 RAG 문서는 삭제·재색인.

![스크린샷: r12 대응 기록](images/r12-response.png)

## 7. 생각해 볼 것

- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?
- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)
- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?
