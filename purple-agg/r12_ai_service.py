#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R12 AI 서비스 공격·방어 — 챗봇 로그에서 '평범한 사용자는 쓰지 않는 것'을 집계로 찾는다.

Red(로그로만 재현) — 가입 사용자 u7731042, 표적 aicompanion(10.20.40.87)
  1) D-45~D-4: 프롬프트 인젝션 시도(긴 프롬프트·주입 패턴 표지) — 실제 로그 재방문 패턴
  2) 도구 남용: 일반 사용자에게 없는 http_fetch·file_read·shell 호출 → http_fetch 로 내부 관리콘솔 SSRF
  3) /api/debug/* 로 시스템 프롬프트·설정 노출 시도(404 → 200), RAG 문서 업로드로 오염
Blue: 도구 분포 → 관리 도구 사용자 → 사용자별 프롬프트 길이 → 표지×차단 → 디버그·업로드 경로 → 동서 연결
"""
import purplelab as P

ROUND, TITLE, SEED = "r12", "AI 서비스 — 챗봇 로그의 이상치", 1212
U = "u7731042"


def attack(S):
    ip = S.ext_ip("Singapore")
    S.ips["ip"] = ip
    ua = P.UA_LIST[0]
    ai_ip = P.IP_OF["aicompanion"]
    for t0 in S.visits(min(45, P.DAYS - 1), 4, cls="returning", revisit_scale=0.4):
        for t in S.session_times(t0, S.rnd.randint(6, 16)):
            inj = S.rnd.random() < 0.85
            tool = S.rnd.choices(["none", "http_fetch", "file_read", "shell"], weights=[60, 25, 10, 5])[0]
            blocked = inj and S.rnd.random() < 0.65
            S.add(P.web(t, "aicompanion", ip, "POST", "/api/chat", 200, S.rnd.randint(1500, 4000), S.rnd.randint(800, 4000), ua))
            S.add(P.ai(t + 0.02, U, ip, S.rnd.randint(1800, 6500), S.rnd.randint(5000, 8000) if (not blocked and S.rnd.random() < 0.08) else S.rnd.randint(150, 900),
                       tool if not blocked else "none", ["injection_pattern"] if inj else None, blocked))
            if tool == "http_fetch" and not blocked:
                S.add(P.flow(t + 0.5, ai_ip, P.IP_OF["adminconsole"], 80, 420, S.rnd.randint(2000, 60000), "http", 1))
    t = S.at(6, 23, 10, 0)
    for path, st in [("/api/debug", 404), ("/api/debug/", 404), ("/api/debug/config", 200), ("/api/debug/prompt", 200),
                     ("/api/debug/env", 403), ("/api/debug/config", 200), ("/api/debug/prompt", 200)]:
        t += S.rnd.uniform(5, 30)
        S.add(P.web(t, "aicompanion", ip, "GET", path, st, 3800 if st == 200 else 210, 40, ua))
    t = S.at(5, 1, 20, 0)
    for i in range(5):
        t += S.rnd.uniform(60, 300)
        S.add(P.web(t, "aicompanion", ip, "POST", "/api/docs/upload", 201, 380, 900, ua))


S0 = P.Scenario(0, SEED)
attack(S0)
IP = S0.ips["ip"]
AI = {"exists": {"field": "data.ai.tool"}}

QUERIES = [
    P.Q("Q1", "챗봇 도구 호출 분포",
        {"size": 0, "query": AI, "aggs": {"tool": {"terms": {"field": "data.ai.tool", "size": 8}}}},
        path=["tool"], cols=["key", "doc_count"]),
    P.Q("Q2", "관리용 도구(http_fetch·file_read·shell)를 쓴 사용자",
        {"size": 0, "query": {"terms": {"data.ai.tool": ["http_fetch", "file_read", "shell"]}},
         "aggs": {"u": {"terms": {"field": "data.ai.user", "size": 5},
                        "aggs": {"t": {"terms": {"field": "data.ai.tool", "size": 3}}}}}},
        path=["u", "t"], cols=["^key", "key", "doc_count"]),
    P.Q("Q3", "사용자별 최대·평균 프롬프트 길이 (최대 순 상위 5)",
        {"size": 0, "query": AI,
         "aggs": {"u": {"terms": {"field": "data.ai.user", "size": 5, "order": {"mx": "desc"}},
                        "aggs": {"mx": {"max": {"field": "data.ai.prompt_len"}}, "av": {"avg": {"field": "data.ai.prompt_len"}}}}}},
        path=["u"], cols=["key", "doc_count", "mx.value", "av.value|floor"]),
    P.Q("Q4", "주입 패턴 표지 × 차단 여부",
        {"size": 0, "query": {"term": {"data.ai.flags": "injection_pattern"}},
         "aggs": {"b": {"terms": {"field": "data.ai.blocked", "size": 2},
                        "aggs": {"u": {"cardinality": {"field": "data.ai.user"}}}}}},
        path=["b"], cols=["key", "doc_count", "u.value"]),
    P.Q("Q5", "ai.kt66.lab — 디버그·문서 업로드 경로 호출 IP",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.vhost": "ai.kt66.lab"}}],
                                       "should": [{"prefix": {"data.url": "/api/debug"}}, {"prefix": {"data.url": "/api/docs"}}],
                                       "minimum_should_match": 1}},
         "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 5},
                         "aggs": {"st": {"terms": {"field": "data.id", "size": 4}}}}}},
        path=["ip", "st"], cols=["^key", "key", "doc_count"]),
    P.Q("Q6", "관리콘솔(10.20.40.86)로 들어온 동서 연결 — 출발지별",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.event_type": "flow"}}, {"term": {"data.dest_ip": "10.20.40.86"}}]}},
         "aggs": {"src": {"terms": {"field": "data.src_ip", "size": 4},
                          "aggs": {"port": {"terms": {"field": "data.dest_port", "size": 2}}}}}},
        path=["src", "port"], cols=["^key", "key", "doc_count"]),
]

MON = P.Q("MON", "주입 패턴 표지 20회 이상인 사용자",
          {"size": 0, "query": {"term": {"data.ai.flags": "injection_pattern"}},
           "aggs": {"u": {"terms": {"field": "data.ai.user", "size": 50},
                          "aggs": {"hit": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 20"}}}}}},
          path=["u"], cols=["key", "doc_count"], trigger="ctx.results[0].aggregations.u.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
