#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R02 정찰·탐색 — 많이 온 IP 가 아니라 '이상하게 넓게 훑은' IP 를 찾는다.

Red(로그로만 재현)
  A: 외부 포트 스캔 — 공개 VIP 8개 × 상위 100포트 (FW DROP + IDS)
  B: 웹 콘텐츠 탐색 — govportal·mediforum 에 경로 사전 대입(평범한 브라우저 UA 로 위장)
  C: 분산 저속 정찰 — 300개 IP 가 neobank API 의 숨은 경로 2개를 1~2번씩
Blue: 요청량 상위(정상 대량 이용자) → 404 상위 → IP별 고유 URL → 경로별 고유 IP → 포트 다양성
"""
import purplelab as P

ROUND, TITLE, SEED = "r02", "정찰·탐색 — 넓게 훑는 IP 찾기", 202
PORTS100 = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 636, 873, 993, 995,
            1025, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4443, 4848, 5000,
            5432, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 7070, 7443, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888,
            9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 10250, 11211, 15672, 27017, 50000, 50070,
            389, 1099, 1900, 2000, 2222, 2323, 3001, 4000, 4444, 5555, 5800, 6000, 6667, 7000, 7777, 8001, 8082,
            8083, 8181, 8282, 8800, 9443, 9800, 12345, 31337]
DIRS = ["admin", "backup", "old", "test", "dev", "api", "config", "db", "upload", "files", "private", "tmp", "logs",
        "staff", "manager", "console", "phpinfo.php", "server-status", ".svn", "wp-admin", "install", "setup",
        "cgi-bin", "include", "inc", "lib", "data", "export", "download", "sql", "dump", "archive", "web.config",
        "WEB-INF", "debug", "status", "monitor", "jenkins", "swagger", "graphql", "actuator", "beta", "stage"]
EXT = ["", "/", ".php", ".bak", ".zip", ".old", ".txt"]
HIDDEN = ["/api/v1/admin/users", "/api/v1/accounts/export?format=csv"]


def attack(S):
    A = S.ext_ip("Russia")
    B = S.ext_ip("United States")
    bot = [S.ext_ip(S.rnd.choice(["Vietnam", "Brazil", "India", "China"])) for _ in range(300)]
    S.ips.update(A=A, B=B)
    vips = ["198.51.100.81", "198.51.100.83", "198.51.100.84", "198.51.100.85", "198.51.100.87",
            "198.51.100.26", "198.51.100.25", "198.51.100.201"]
    # A ① 저속 포트 스캔: D-80~D-21, 실제 로그 재방문 패턴으로 하루 1~3포트씩
    for t in S.visits(min(80, P.DAYS - 1), 21, cls="persistent"):
        for tt in S.session_times(t, S.rnd.randint(1, 3)):
            S.add(P.fw(tt, A, S.rnd.choice(vips), S.rnd.choice(PORTS100)))
    # A ② 본 스캔: D-20 02:10 — VIP 8개 × 상위 100포트
    t = S.at(20, 2, 10, 3.0)
    for v in vips:
        for port in PORTS100:
            t += S.rnd.uniform(0.15, 0.4)
            if port in (80, 443, 25, 22):
                continue
            S.add(P.fw(t, A, v, port))
    for k in range(12):
        S.add(P.ids(S.at(20, 2, 11 + k // 4), A, S.rnd.choice(vips), 3389, "ET SCAN NMAP -sS window 1024", 2009582, 2, "Attempted Information Leak"))
    # B: 웹 경로 대입 — D-60~D-5 사이 재방문(세션당 경로 10~40개), 마지막 D-4 21시 대량
    ua = P.UA_LIST[0]
    seen = set()

    def probe(t, ep, n):
        for _ in range(n):
            for _try in range(50):
                path = "/" + S.rnd.choice(DIRS) + S.rnd.choice(EXT)
                if (ep, path) not in seen:
                    seen.add((ep, path))
                    break
            t += S.rnd.uniform(1.0, 6.0)
            st = 200 if path in ("/admin/", "/swagger", "/status") else (403 if path in ("/server-status", "/.svn/", "/WEB-INF/") else 404)
            S.add(P.web(t, ep, B, "GET", path, st, 196 if st == 404 else S.rnd.randint(800, 4000), S.rnd.randint(3, 20), ua))
    for t in S.visits(min(60, P.DAYS - 1), 5, revisit_scale=1.5):
        probe(t, S.rnd.choice(["govportal", "mediforum"]), S.rnd.randint(10, 40))
    probe(S.at(4, 21, 5, 0), "govportal", 120)
    probe(S.at(4, 21, 50, 0), "mediforum", 120)
    # C: 분산 저속 정찰 — 300 IP 가 D-60~D-1 에 걸쳐 1~2번씩
    for ip in bot:
        for path in (HIDDEN if S.rnd.random() < 0.5 else [S.rnd.choice(HIDDEN)]):
            day = S.rnd.randint(1, min(60, P.DAYS - 1))
            S.add(P.web(S.at(day, S.hour_pick()), "neobank", ip, "GET", path, 404, 214,
                        S.rnd.randint(4, 15), S.rnd.choice(P.UA_LIST)))


def ips():
    S = P.Scenario(0, SEED)
    attack(S)
    return S.ips


IPS = ips()
A, B = IPS["A"], IPS["B"]
WEB = {"term": {"decoder.name": "web-accesslog"}}

QUERIES = [
    P.Q("Q1", "웹 요청 수 상위 10 IP — 많이 온 IP 는 누구인가",
        {"size": 0, "query": WEB, "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 10},
                                                     "aggs": {"ua": {"terms": {"field": "data.user_agent", "size": 1}}}}}},
        path=["by_ip", "ua"], cols=["^key", "key", "doc_count"]),
    P.Q("Q2", "404 응답을 가장 많이 받은 IP 상위 5",
        {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.id": "404"}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5}}}},
        path=["by_ip"], cols=["key", "doc_count"]),
    P.Q("Q3", "404 IP 별 서로 다른 URL 수·vhost 수 (고유 URL 순)",
        {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.id": "404"}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5, "order": {"urls": "desc"}},
                            "aggs": {"urls": {"cardinality": {"field": "data.url"}},
                                     "hosts": {"cardinality": {"field": "data.vhost"}}}}}},
        path=["by_ip"], cols=["key", "doc_count", "urls.value", "hosts.value"]),
    P.Q("Q4", "neobank API(/api/) 404 — 경로별 서로 다른 IP 수",
        {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.vhost": "neobank.kt66.lab"}},
                                                   {"term": {"data.id": "404"}}, {"prefix": {"data.url": "/api/"}}]}},
         "aggs": {"by_url": {"terms": {"field": "data.url", "size": 5, "order": {"ips": "desc"}},
                             "aggs": {"ips": {"cardinality": {"field": "data.srcip"}}}}}},
        path=["by_url"], cols=["key", "doc_count", "ips.value"]),
    P.Q("Q5", "숨은 API 경로를 두드린 IP 들의 국가 분포",
        {"size": 0, "query": {"terms": {"data.url": ["/api/v1/admin/users", "/api/v1/accounts/export?format=csv"]}},
         "aggs": {"by_cc": {"terms": {"field": "GeoLocation.country_name", "size": 6},
                            "aggs": {"ips": {"cardinality": {"field": "data.srcip"}}}}}},
        path=["by_cc"], cols=["key", "doc_count", "ips.value"]),
    P.Q("Q6", "방화벽 차단(DROP) — IP 별 서로 다른 포트·목적지 수·활동 일수",
        {"size": 0, "query": {"term": {"decoder.name": "kt66-nft"}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5, "order": {"ports": "desc"}},
                            "aggs": {"ports": {"cardinality": {"field": "data.dstport"}},
                                     "dsts": {"cardinality": {"field": "data.dstip"}},
                                     "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}}}}}},
        path=["by_ip"], cols=["key", "doc_count", "ports.value", "dsts.value", "days.buckets|len"]),
    P.Q("Q7", f"두 정찰 IP({A}, {B})의 일별 활동 (일 단위, 많은 날 순)",
        {"size": 0, "query": {"bool": {"should": [{"term": {"data.srcip": A}}, {"term": {"data.srcip": B}}, {"term": {"data.src_ip": A}}]}},
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00",
                                           "format": "yyyy-MM-dd", "min_doc_count": 1, "order": {"_count": "desc"}},
                        "aggs": {"who": {"terms": {"field": "decoder.name", "size": 2}}}}}},
        path=["t", "who"], cols=["^key", "key", "doc_count"], head=8),
]
QUERIES.append(P.Q("Q8", "404 고유 URL 상위 IP 의 활동 일수·처음·마지막 (장기 정찰 판별)",
    {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.id": "404"}}]}},
     "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5, "order": {"urls": "desc"}},
                        "aggs": {"urls": {"cardinality": {"field": "data.url"}},
                                 "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}},
                                 "first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}}}}}},
    path=["by_ip"], cols=["key", "urls.value", "days.buckets|len", "first.value|day", "last.value|day"]))
# 날짜 버킷 키를 사람이 읽게: ^key 는 epoch 이므로 key_as_string 을 쓰도록 보정
QUERIES[6].cols = ["^key_as_string", "key", "doc_count"]

MON = P.Q("MON", "404 를 받은 서로 다른 URL 이 100개 이상인 IP",
          {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.id": "404"}}]}},
           "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 50, "order": {"urls": "desc"}},
                              "aggs": {"urls": {"cardinality": {"field": "data.url"}},
                                       "hit": {"bucket_selector": {"buckets_path": {"u": "urls"}, "script": "params.u >= 100"}}}}}},
          path=["by_ip"], cols=["key", "doc_count", "urls.value"],
          trigger="ctx.results[0].aggregations.by_ip.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
