#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R01 운영체제 수립 + 가시성 베이스라인 — 정상의 모양을 집계로 재고, 그 위에서 튀는 것을 본다.

Red(로그로만 재현): juiceshop 서버(10.20.40.81)에 심긴 Caldera sandcat 이 C2 로 30~60초마다 POST /beat.
                   Discovery 명령(whoami·pwd·ls·ifconfig·which)은 로그가 남지 않는다(가시성 0).
Blue: 엔드포인트별 정상 분포 → 서버발 외부 목적지 집계 → 시간 규칙성 → 모니터.
"""
import purplelab as P

ROUND, TITLE, SEED = "r01", "가시성 베이스라인 — 정상의 모양과 서버발 비콘", 101
C2 = {}


def attack(S):
    c2 = S.ext_ip("Netherlands")
    C2["ip"] = c2
    web = P.IP_OF["juiceshop"]
    # ① 장기 잠복: D-75 부터 1시간(±30%) 간격 비콘 — 밤낮·주말 구분 없음
    t = S.at(min(75, P.DAYS - 1), 3, 12, 7.3)
    S.add(P.http(t, web, c2, 8888, "POST", "/file/download", c2 + ":8888", "curl/7.81.0", 200, 412, 9_843_712))
    end_sleep = S.at(2, 10, 0, 0)
    t += 4.2
    while t < end_sleep:
        S.add(P.http(t, web, c2, 8888, "POST", "/beat", c2 + ":8888", "Go-http-client/1.1", 200,
                     S.rnd.randint(980, 1250), S.rnd.randint(180, 420)))
        t += 3600 * S.rnd.uniform(0.7, 1.3)
    # ② 운영자 접속: D-2 10:00~16:00 대화형 모드(30~60초)
    end = S.at(2, 16, 0, 0)
    while t < end:
        S.add(P.http(t, web, c2, 8888, "POST", "/beat", c2 + ":8888", "Go-http-client/1.1", 200,
                     S.rnd.randint(980, 1250), S.rnd.randint(180, 9000)))
        t += S.rnd.uniform(30, 60)
    # ③ 그 뒤 다시 잠복
    while t < S.anchor:
        S.add(P.http(t, web, c2, 8888, "POST", "/beat", c2 + ":8888", "Go-http-client/1.1", 200,
                     S.rnd.randint(980, 1250), S.rnd.randint(180, 420)))
        t += 3600 * S.rnd.uniform(0.7, 1.3)


def _q():
    c2 = C2.get("ip") or _c2()
    return [
        P.Q("Q1", "이벤트 출처(에이전트)별 분포 — 정상의 모양 ①",
            {"size": 0, "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 15}}}},
            path=["by_agent"], cols=["key", "doc_count"]),
        P.Q("Q2", "웹 엔드포인트별 요청 수와 서로 다른 방문 IP 수 — 정상의 모양 ②",
            {"size": 0, "query": {"term": {"decoder.name": "web-accesslog"}},
             "aggs": {"by_vhost": {"terms": {"field": "data.vhost", "size": 10},
                                   "aggs": {"ips": {"cardinality": {"field": "data.srcip", "precision_threshold": 40000}}}}}},
            path=["by_vhost"], cols=["key", "doc_count", "ips.value"]),
        P.Q("Q3", "주별 이벤트 추이 (7일 버킷, KST) — 기간 전체의 모양",
            {"size": 0, "aggs": {"per_week": {"date_histogram": {"field": "timestamp", "fixed_interval": "7d",
                                                                  "time_zone": "+09:00", "format": "yyyy-MM-dd", "min_doc_count": 1}}}},
            path=["per_week"], cols=["key_as_string", "doc_count"]),
        P.Q("Q4", "서버존(10.20.40.x)에서 밖으로 나간 연결 — 목적지 상위",
            {"size": 0, "query": {"prefix": {"data.src_ip": "10.20.40."}},
             "aggs": {"by_dst": {"terms": {"field": "data.dest_ip", "size": 8},
                                 "aggs": {"srcs": {"cardinality": {"field": "data.src_ip"}},
                                          "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d",
                                                                      "time_zone": "+09:00", "min_doc_count": 1}}}}}},
            path=["by_dst"], cols=["key", "doc_count", "srcs.value", "days.buckets|len"]),
        P.Q("Q5", f"출발지 1곳뿐인 목적지({c2}) — 일별 요청 수 (가장 많은 날 순)",
            {"size": 0, "query": {"term": {"data.dest_ip": c2}},
             "aggs": {"per_day": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00",
                                                     "format": "yyyy-MM-dd", "min_doc_count": 1, "order": {"_count": "desc"}}}}},
            path=["per_day"], cols=["key_as_string", "doc_count"], head=6),
        P.Q("Q6", f"같은 목적지 요청의 경로·메서드·UA 조합",
            {"size": 0, "query": {"term": {"data.dest_ip": c2}},
             "aggs": {"by_url": {"terms": {"field": "data.http.url", "size": 5},
                                 "aggs": {"m": {"terms": {"field": "data.http.http_user_agent", "size": 3}}}}}},
            path=["by_url", "m"], cols=["^key", "key", "doc_count"]),
        P.Q("Q7", "지금 경보(rule.level ≥ 7)는 무엇을 보고 있나 — 상위 5",
            {"size": 0, "query": {"range": {"rule.level": {"gte": 7}}},
             "aggs": {"by_rule": {"terms": {"field": "rule.description", "size": 5}}}},
            path=["by_rule"], cols=["key", "doc_count"]),
    ]


def _c2():
    S = P.Scenario(0, SEED)
    attack(S)
    return C2["ip"]


MON = P.Q("MON", "서버존발 외부 목적지 중 출발지가 1곳이고 500회 이상인 곳 (비콘 후보)",
          {"size": 0, "query": {"prefix": {"data.src_ip": "10.20.40."}},
           "aggs": {"by_dst": {"terms": {"field": "data.dest_ip", "size": 50},
                               "aggs": {"srcs": {"cardinality": {"field": "data.src_ip"}},
                                        "hit": {"bucket_selector": {"buckets_path": {"c": "_count", "s": "srcs"},
                                                                     "script": "params.c >= 500 && params.s == 1"}}}}}},
          path=["by_dst"], cols=["key", "doc_count", "srcs.value"],
          trigger="ctx.results[0].aggregations.by_dst.buckets.size() > 0")

QUERIES = _q()

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
