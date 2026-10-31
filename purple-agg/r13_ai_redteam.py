#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R13 AI 레드팀 — 사람이 며칠 걸리는 체인을 3분에. 기계 속도는 '분 단위 집계'에서 튄다.

Red(로그로만 재현) — 자율 에이전트(UA python-httpx), 표적 juiceshop → neobank·govportal·mediforum
  · D-30·D-16: 같은 인프라의 '예행 연습' 짧은 폭주 2회 (각 1분, 경로 대입만)
  · D-2 04:11~04:14 본 체인: 경로 대입 420건(52초) → SQLi 120건(차단 40·우회 80, 덤프 4)
    → 탈취 계정 로그인 → node 프로세스가 셸 12회(40초) → juiceshop 에서 서버 3대로 SSH(30초) → neobank 유출
Blue: juice 분당 요청 폭주 → UA 분포 → IP 의 처음·마지막(초) → 분 단위 단계 전이 → SSH 전파 속도 → 경보 레벨
"""
import purplelab as P

ROUND, TITLE, SEED = "r13", "AI 레드팀 — 기계 속도의 체인", 1313
UA = "python-httpx/0.27.0"


def attack(S):
    S.opts["audit"] = True
    X = S.ext_ip("United States")
    out = S.ext_ip("United States")
    S.ips.update(X=X, out=out)
    words = ["admin", "api", "backup", "rest", "ftp", "metrics", "profile", "graphql", "debug", "console", "config", "upload"]

    def scan(t, n, step):
        for i in range(n):
            t += step + S.rnd.uniform(0, 0.004)
            p = "/" + words[i % len(words)] + "/" + ("%03d" % i)
            S.add(P.web(t, "juiceshop", X, "GET", p, 404 if i % 37 else 200, 214, 3, UA))
        return t
    for d in (30, 16):
        if d < P.DAYS:
            scan(S.at(d, 4, 2, 0), 60, 0.9)
    t = scan(S.at(2, 4, 11, 0), 420, 0.124)
    for i in range(120):
        t += 0.25
        if i < 40:
            u = "/rest/products/search?q=%27))+UNION+SELECT+*+FROM+Users--"
            S.add(P.waf(t, "juiceshop", X, u, "942100", "SQL Injection Attack Detected via libinjection"))
            S.add(P.web(t + 0.002, "juiceshop", X, "GET", u, 403, 199, 2, UA))
        else:
            u = "/rest/products/search?q=x%27))/**/uNiOn/**/sElEcT/**/id,email,password,4,5,6,7,8,9/**/FrOm/**/Users--"
            big = i >= 116
            S.add(P.web(t, "juiceshop", X, "GET", u, 200, 1_800_000 if big else S.rnd.randint(4000, 9000), 40 if not big else 900, UA))
    t += 3
    S.add(P.web(t, "juiceshop", X, "POST", "/rest/user/login", 200, 820, 90, UA))
    S.add(P.appauth(t + 0.01, "juiceshop", X, "admin@juice-sh.op", True))
    for c in ["id", "uname -a", "cat /etc/passwd", "env", "ls -la /app", "cat /app/config/default.yml", "ps aux",
              "ip addr", "cat ~/.ssh/known_hosts", "ls ~/.ssh", "cat ~/.ssh/id_rsa", "ssh -V"]:
        t += S.rnd.uniform(2.5, 4)
        S.add(P.audit(t, "juiceshop", "node", "/bin/sh", "sh -c " + c, "/usr/local/bin/node"))
    src = P.IP_OF["juiceshop"]
    for tgt in ("neobank", "govportal", "mediforum"):
        t += S.rnd.uniform(4, 9)
        S.add(P.ssh(t, tgt, src, "deploy", "5716"))
        S.add(P.ssh(t + 1.2, tgt, src, "deploy", "5715"))
    t += 30
    S.add(P.flow(t, P.IP_OF["neobank"], out, 443, 220_000_000, 30_000, "tls", 95))


S0 = P.Scenario(0, SEED)
attack(S0)
X = S0.ips["X"]
JUICE = {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}}, {"term": {"data.vhost": "juice.kt66.lab"}}]}}

QUERIES = [
    P.Q("Q1", "juice.kt66.lab 분당 요청 — 250건 이상인 분",
        {"size": 0, "query": JUICE,
         "aggs": {"m": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m", "time_zone": "+09:00", "format": "MM-dd HH:mm", "min_doc_count": 250}}}},
        path=["m"], cols=["key_as_string", "doc_count"]),
    P.Q("Q2", "juice.kt66.lab 의 User-Agent 상위 8",
        {"size": 0, "query": JUICE, "aggs": {"ua": {"terms": {"field": "data.user_agent", "size": 8}}}},
        path=["ua"], cols=["key", "doc_count"]),
    P.Q("Q3", "python-httpx 출발지 — 건수·처음·마지막(초)·활동 일수",
        {"size": 0, "query": {"term": {"data.user_agent": UA}},
         "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 3},
                         "aggs": {"first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                                  "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}}}}}},
        path=["ip"], cols=["key", "doc_count", "first.value|tss", "last.value|tss", "days.buckets|len"]),
    P.Q("Q4", "체인 단계 전이 — 분 단위 (공격 IP · node 셸 · juiceshop발 SSH · neobank 유출)",
        {"size": 0, "query": {"bool": {"should": [{"term": {"data.srcip": X}}, {"term": {"data.audit.parent": "/usr/local/bin/node"}},
                                                  {"term": {"data.srcip": "10.20.40.81"}},
                                                  {"bool": {"filter": [{"term": {"data.src_ip": "10.20.40.83"}}, {"range": {"data.flow.bytes_toserver": {"gte": 100000000}}}]}}],
                                       "minimum_should_match": 1}},
         "aggs": {"m": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m", "time_zone": "+09:00", "format": "MM-dd HH:mm", "min_doc_count": 1},
                        "aggs": {"k": {"terms": {"field": "decoder.name", "size": 4}}}}}},
        path=["m", "k"], cols=["^key_as_string", "key", "doc_count"], head=16),
    P.Q("Q5", "juiceshop(10.20.40.81)에서 나간 SSH — 서버별 성공 시각(초)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"rule.id": "5715"}}, {"term": {"data.srcip": "10.20.40.81"}}]}},
         "aggs": {"ag": {"terms": {"field": "agent.name", "size": 5, "order": {"t": "asc"}},
                         "aggs": {"t": {"min": {"field": "timestamp"}}}}}},
        path=["ag"], cols=["key", "t.value|tss"]),
    P.Q("Q6", f"공격 IP {X} 관련 경보 레벨 분포 — 레벨 10 이상이 있었나",
        {"size": 0, "query": {"term": {"data.srcip": X}},
         "aggs": {"lv": {"terms": {"field": "rule.level", "size": 5, "missing": 0}}}},
        path=["lv"], cols=["key", "doc_count"]),
]

MON = P.Q("MON", "한 IP 가 1분에 200건 이상 요청 (기계 속도)",
          {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}}]}},
           "aggs": {"m": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m", "time_zone": "+09:00", "format": "MM-dd HH:mm", "min_doc_count": 200},
                          "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 1}},
                                   "hot": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 200"}}}}}},
          path=["m", "ip"], cols=["^key_as_string", "key", "doc_count"],
          trigger="ctx.results[0].aggregations.m.buckets.stream().anyMatch(b -> b.ip.buckets.size() > 0 && b.ip.buckets[0].doc_count >= 200)")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
