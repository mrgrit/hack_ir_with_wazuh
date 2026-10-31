#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R10 영향(AI 데이터센터) — 몇 분 사이 수천 건의 파일 변경, 두 달 내내 같은 포트, 그리고 '공격이 아닌' 장애.

Red(로그로만 재현)
  1) 크립토마이닝: GPU 존(10.20.50.60) → 풀 서버 3333/tcp(stratum), D-60 부터 낮에는 쉬고 밤에만(시간대 프로파일)
  2) 웹 변조: D-1 08:57 mediforum 첫 화면 교체 → 이후 '/' 응답 크기 급감
  3) 랜섬 준비: D-2 03:00 govportal 공유폴더 1,200개 파일 암호화(.kt66lock 추가·원본 삭제) + 안내문 30개
  (정상) 장애 주입: D-3 14:00~14:25 neobank 백엔드 장애 → 503 급증 (공격 아님)
Blue: FIM 폭주 구간 → 패턴별 파일 → vhost 별 5xx 폭주 → '/' 평균 크기 → GPU 존 포트 → 서버별 FIM·5xx 판별표
"""
import purplelab as P

ROUND, TITLE, SEED = "r10", "영향 — 공격인가 장애인가", 1010


def attack(S):
    pool = S.ext_ip("Germany")
    S.ips["pool"] = pool
    t_out0 = S.at(3, 14, 0, 0)
    S.opts["outage"] = ("neobank", t_out0, t_out0 + 1500, 503, 0.85)
    S.opts["deface"] = ("mediforum", "/", S.at(1, 8, 57, 30), 1200)
    gpu = "10.20.50.60"
    for d in range(min(60, P.DAYS - 1), 0, -1):
        for h in range(24):
            if 7 <= h < 20 or S.rnd.random() < 0.15:
                continue
            S.add(P.flow(S.at(d, h, S.rnd.randint(0, 5)), gpu, pool, 3333, S.rnd.randint(8000, 30000), S.rnd.randint(4000, 12000), "failed", 3500))
        if S.rnd.random() < 0.5:
            S.add(P.dns(S.at(d, 0, 30), gpu, "eu1.minexmr-kt.net"))
    S.add(P.fim(S.at(1, 8, 57, 30), "mediforum", "/var/www/mediforum/templates/index.html", "modified", "www-data"))
    t = S.at(2, 3, 0, 5)
    for i in range(1200):
        t += S.rnd.uniform(0.3, 0.9)
        f = f"/srv/share/minwon/{2020 + i % 6}/doc_{i:05d}.hwp"
        S.add(P.fim(t, "govportal", f + ".kt66lock", "added", "www-data"))
        S.add(P.fim(t + 0.05, "govportal", f, "deleted", "www-data"))
        if i % 40 == 0:
            S.add(P.fim(t + 0.1, "govportal", f"/srv/share/minwon/{2020 + i % 6}/README_RESTORE.txt", "added", "www-data"))


S0 = P.Scenario(0, SEED)
attack(S0)
FIM = {"prefix": {"decoder.name": "syscheck"}}
WEB = {"term": {"decoder.name": "web-accesslog"}}

QUERIES = [
    P.Q("Q1", "FIM 이벤트 10분 버킷 — 200건 이상만, 호스트별",
        {"size": 0, "query": FIM,
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "10m", "time_zone": "+09:00", "format": "MM-dd HH:mm", "min_doc_count": 1},
                        "aggs": {"ag": {"terms": {"field": "agent.name", "size": 2}},
                                 "burst": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 200"}}}}}},
        path=["t", "ag"], cols=["^key_as_string", "key", "doc_count"]),
    P.Q("Q2", "govportal FIM — 패턴별 건수",
        {"size": 0, "query": {"bool": {"filter": [FIM, {"term": {"agent.name": "govportal"}}]}},
         "aggs": {"p": {"filters": {"filters": {"1_locked_added": {"wildcard": {"syscheck.path": "*.kt66lock"}},
                                                "2_note_added": {"wildcard": {"syscheck.path": "*README_RESTORE.txt"}},
                                                "3_deleted": {"term": {"syscheck.event": "deleted"}},
                                                "4_modified": {"term": {"syscheck.event": "modified"}}}}}}},
        path=["p"], cols=["key", "doc_count"]),
    P.Q("Q3", "vhost 별 5xx — 1시간에 30건 이상인 구간",
        {"size": 0, "query": {"bool": {"filter": [WEB, {"prefix": {"data.id": "5"}}]}},
         "aggs": {"vh": {"terms": {"field": "data.vhost", "size": 8},
                         "aggs": {"h": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "+09:00", "format": "MM-dd HH:mm", "min_doc_count": 1},
                                        "aggs": {"spike": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 30"}}}}}}}},
        path=["vh", "h"], cols=["^key", "key_as_string", "doc_count"]),
    P.Q("Q4", "mediforum 첫 화면('/') 평균 응답 크기 — 일별 마지막 5일",
        {"size": 0, "query": {"bool": {"filter": [WEB, {"term": {"data.vhost": "mediforum.kt66.lab"}}, {"term": {"data.url": "/"}}, {"term": {"data.id": "200"}}]}},
         "aggs": {"d": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "format": "yyyy-MM-dd", "min_doc_count": 1,
                                           "order": {"_key": "desc"}},
                        "aggs": {"avg": {"avg": {"field": "data.bytes"}}}}}},
        path=["d"], cols=["key_as_string", "doc_count", "avg.value|floor"], head=5),
    P.Q("Q5", "GPU 존(10.20.50.x) 외부 연결 — 포트별 건수·연결 지속시간 합(초)·활동 일수",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.event_type": "flow"}}, {"prefix": {"data.src_ip": "10.20.50."}}]}},
         "aggs": {"port": {"terms": {"field": "data.dest_port", "size": 4},
                           "aggs": {"age": {"sum": {"field": "data.flow.age"}},
                                    "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}}}}}},
        path=["port"], cols=["key", "doc_count", "age.value", "days.buckets|len"]),
    P.Q("Q6", "판별표 — 서버별 FIM 건수 vs 5xx 건수",
        {"size": 0, "query": {"bool": {"should": [FIM, {"bool": {"filter": [WEB, {"prefix": {"data.id": "5"}}]}}], "minimum_should_match": 1}},
         "aggs": {"ag": {"terms": {"field": "agent.name", "size": 6},
                         "aggs": {"fim": {"filter": FIM}, "err": {"filter": {"prefix": {"data.id": "5"}}}}}}},
        path=["ag"], cols=["key", "fim.doc_count", "err.doc_count"]),
]

MON = P.Q("MON", "10분에 FIM 200건 이상 (대량 변경)", QUERIES[0].body, path=["t", "ag"],
          cols=["^key_as_string", "key", "doc_count"], trigger="ctx.results[0].aggregations.t.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
