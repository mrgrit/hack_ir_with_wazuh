#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R08 C2·유출 — 석 달 내내 한 시간마다 같은 곳, 이름이 긴 DNS 질의 수백 개, 새벽의 대용량 업로드.

Red(로그로만 재현) — 감염 PC KT66-WIN-01(10.20.70.10)
  1) HTTPS 비콘: D-80 부터 1시간(±25%) 간격 — 사용자가 없는 밤·주말에도
  2) 비표준 포트 백업 채널 8443: 실제 로그 재방문 패턴으로 드문드문
  3) DNS 터널: 서브도메인에 데이터를 실은 TXT 질의 — 세 번의 새벽(실제 로그 시간대 분포)
  4) 유출: D-1 새벽 파일 공유 서비스로 300~800MB 업로드 6회
Blue: 내부 출발지별 흐름 → 감염 PC 목적지 → 일별·시간대 규칙성 → 도메인별 서브도메인 수 → 업로드 합계 → 포트 분포
"""
import purplelab as P

ROUND, TITLE, SEED = "r08", "C2·유출 — 규칙성과 볼륨", 808
DOM = "cdn-sync-analytics.com"


def attack(S):
    c2 = S.ext_ip("United States")
    share = S.ext_ip("United States")
    S.ips.update(c2=c2, share=share)
    pc = "10.20.70.10"
    t = S.at(min(80, P.DAYS - 1), 14, 3, 0)
    while t < S.anchor:
        S.add(P.flow(t, pc, c2, 443, S.rnd.randint(900, 1600), S.rnd.randint(1200, 4000), "tls", S.rnd.randint(1, 3)))
        t += 3600 * S.rnd.uniform(0.75, 1.25)
    for t0 in S.visits(min(70, P.DAYS - 1), 1, cls="persistent"):
        for tt in S.session_times(t0):
            S.add(P.flow(tt, pc, c2, 8443, S.rnd.randint(500, 2500), S.rnd.randint(500, 9000), "failed", 1))
    for d in (21, 9, 2):
        t = S.at(d, 2, 0, 0)
        for i in range(300):
            t += S.rnd.uniform(1, 9)
            sub = "%040x" % S.rnd.getrandbits(160) + ("%08x" % i)
            S.add(P.dns(t, pc, f"{sub}.{DOM}", "TXT"))
    t = S.at(1, 3, 12, 0)
    for i in range(6):
        t += S.rnd.uniform(200, 400)
        S.add(P.flow(t, pc, share, 443, S.rnd.randint(300_000_000, 800_000_000), S.rnd.randint(40_000, 90_000), "tls", S.rnd.randint(60, 240)))


S0 = P.Scenario(0, SEED)
attack(S0)
C2 = S0.ips["c2"]
FLOW = {"term": {"data.event_type": "flow"}}

QUERIES = [
    P.Q("Q1", "사용자존(10.20.70.x) 출발지별 외부 연결 수 (상위 5)",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"prefix": {"data.src_ip": "10.20.70."}}]}},
         "aggs": {"src": {"terms": {"field": "data.src_ip", "size": 5}}}},
        path=["src"], cols=["key", "doc_count"]),
    P.Q("Q2", "KT66-WIN-01(10.20.70.10)의 목적지 상위 — 포트·활동 일수",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"term": {"data.src_ip": "10.20.70.10"}}]}},
         "aggs": {"dst": {"terms": {"field": "data.dest_ip", "size": 5},
                          "aggs": {"port": {"terms": {"field": "data.dest_port", "size": 1}},
                                   "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}}}}}},
        path=["dst"], cols=["key", "doc_count", "days.buckets|len"]),
    P.Q("Q3", f"1위 목적지({C2}) — 6시간 버킷: 밤·주말에도 일정한가 (앞 8개)",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"term": {"data.dest_ip": C2}}, {"term": {"data.dest_port": "443"}}]}},
         "aggs": {"h": {"date_histogram": {"field": "timestamp", "fixed_interval": "6h", "time_zone": "+09:00",
                                           "format": "MM-dd HH:mm", "min_doc_count": 1}}}},
        path=["h"], cols=["key_as_string", "doc_count"], head=8),
    P.Q("Q4", "DNS — 등록 도메인별 서로 다른 질의 이름 수 · 평균 질의 길이 (상위 5)",
        {"size": 0, "query": {"term": {"decoder.name": "kt66-dns"}},
         "aggs": {"dom": {"terms": {"field": "data.domain", "size": 5, "order": {"names": "desc"}},
                          "aggs": {"names": {"cardinality": {"field": "data.query"}}, "len": {"avg": {"field": "data.query_len"}}}}}},
        path=["dom"], cols=["key", "doc_count", "names.value", "len.value|floor"]),
    P.Q("Q5", "내부 → 외부 업로드 합계(bytes_toserver, MB) 상위 목적지",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"prefix": {"data.src_ip": "10.20."}}]}},
         "aggs": {"dst": {"terms": {"field": "data.dest_ip", "size": 5, "order": {"up": "desc"}},
                          "aggs": {"up": {"sum": {"field": "data.flow.bytes_toserver"}}, "srcs": {"cardinality": {"field": "data.src_ip"}}}}}},
        path=["dst"], cols=["key", "doc_count", "up.value|mb", "srcs.value"]),
    P.Q("Q6", "사용자존 외부 연결 — 목적지 포트 분포",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"prefix": {"data.src_ip": "10.20.70."}}]}},
         "aggs": {"port": {"terms": {"field": "data.dest_port", "size": 5},
                           "aggs": {"srcs": {"cardinality": {"field": "data.src_ip"}}}}}},
        path=["port"], cols=["key", "doc_count", "srcs.value"]),
]

MON = P.Q("MON", "서로 다른 서브도메인 200개 이상을 질의한 도메인 (DNS 터널 후보)",
          {"size": 0, "query": {"term": {"decoder.name": "kt66-dns"}},
           "aggs": {"dom": {"terms": {"field": "data.domain", "size": 50, "order": {"names": "desc"}},
                            "aggs": {"names": {"cardinality": {"field": "data.query"}},
                                     "hit": {"bucket_selector": {"buckets_path": {"n": "names"}, "script": "params.n >= 200"}}}}}},
          path=["dom"], cols=["key", "doc_count", "names.value"],
          trigger="ctx.results[0].aggregations.dom.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
