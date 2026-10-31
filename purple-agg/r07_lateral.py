#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R07 내부 이동 — 관리자 계정 하나가 10분 안에 서버 여러 대로 퍼진다.

Red(로그로만 재현) — 탈취한 관리자 계정 kim.minjun
  1) D-45~D-4: 새벽에 해외 IP 로 bastion 로그인 후 서버 1대씩 '둘러보기'(실제 로그 재방문 패턴)
  2) D-3 01:20: bastion → 서버존 포트 스캔 → 8분 안에 서버 6대 SSH, dvwa 실패
  3) neobank → KT66-WIN-01 네트워크 로그온(유형 3) → 서비스 실행 → 계정 생성·관리자 그룹 추가
Blue: 계정×10분×호스트 수 → bastion 해외 로그인 → 동서 스캔 → 로그온 유형 → 그룹 변경 → 타임라인
"""
import purplelab as P

ROUND, TITLE, SEED = "r07", "내부 이동 — 계정 하나, 서버 여러 대", 707
APPS = ["juiceshop", "neobank", "govportal", "mediforum", "aicompanion", "adminconsole"]


def attack(S):
    ru = S.ext_ip("Russia")
    S.ips["ru"] = ru
    U = "kim.minjun"
    bast = P.IP_OF["bastion"]
    for t0 in S.visits(min(45, P.DAYS - 1), 4):
        S.add(P.ssh(t0, "bastion", ru, U, "5715"))
        S.add(P.ssh(t0 + S.rnd.uniform(60, 600), S.rnd.choice(APPS), bast, U, "5715"))
    t = S.at(3, 1, 20, 4)
    S.add(P.ssh(t, "bastion", ru, U, "5715"))
    t += 240
    for app in APPS + ["dvwa"]:
        for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017, 5601, 8443, 2375, 11211, 9000, 3000]:
            t += S.rnd.uniform(0.05, 0.3)
            S.add(P.flow(t, bast, P.IP_OF[app], port, 60, 0 if port not in (22, 80, 443) else 300, "failed" if port not in (22, 80, 443) else "tls", 0))
    t += 60
    for app in APPS:
        t += S.rnd.uniform(40, 90)
        S.add(P.ssh(t, app, bast, U, "5715"))
        S.add(P.sudo(t + 20, app, U, "/bin/bash"))
    for _ in range(3):
        t += 5
        S.add(P.ssh(t, "dvwa", bast, U, "5716"))
    nb = P.IP_OF["neobank"]
    t += 300
    S.add(P.flow(t, nb, "10.20.70.10", 445, 18_000, 9_000, "smb", 3))
    S.add(P.win(t + 1, 4624, "park.jiwoo", 3, nb, extra={"authenticationPackageName": "NTLM"}))
    S.add(P.win(t + 4, 4688, "SYSTEM", proc="C:\\Windows\\PSEXESVC.exe", cmd="PSEXESVC.exe", parent="C:\\Windows\\System32\\services.exe"))
    S.add(P.win(t + 9, 4688, "SYSTEM", proc="C:\\Windows\\System32\\cmd.exe", cmd="cmd.exe /c net user svc_backup P@ss2026! /add", parent="C:\\Windows\\PSEXESVC.exe"))
    S.add(P.win(t + 10, 4720, "svc_backup"))
    S.add(P.win(t + 14, 4732, "svc_backup", extra={"targetSid": "S-1-5-32-544", "memberName": "svc_backup"}))
    for t0 in S.visits(2, 1):
        S.add(P.win(t0, 4624, "svc_backup", 3, nb, extra={"authenticationPackageName": "NTLM"}))


S0 = P.Scenario(0, SEED)
attack(S0)
RU = S0.ips["ru"]
SRV_SSH = {"bool": {"filter": [{"term": {"rule.id": "5715"}}, {"term": {"data.srcip": "10.20.30.201"}}]}}

QUERIES = [
    P.Q("Q1", "bastion 경유 서버 로그인 — 계정 × 10분 × 서로 다른 서버 수 (4대 이상만)",
        {"size": 0, "query": SRV_SSH,
         "aggs": {"u": {"terms": {"field": "data.srcuser", "size": 20},
                        "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "10m", "time_zone": "+09:00",
                                                          "format": "MM-dd HH:mm", "min_doc_count": 1},
                                       "aggs": {"hosts": {"cardinality": {"field": "agent.name"}},
                                                "many": {"bucket_selector": {"buckets_path": {"h": "hosts"}, "script": "params.h >= 4"}}}}}}}},
        path=["u", "t"], cols=["^key", "key_as_string", "hosts.value"]),
    P.Q("Q2", "bastion 로그인 성공 — 외부 출발지 국가별 계정",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "bastion"}}, {"term": {"rule.id": "5715"}},
                                                  {"exists": {"field": "GeoLocation.country_name"}}]}},
         "aggs": {"cc": {"terms": {"field": "GeoLocation.country_name", "size": 4},
                         "aggs": {"u": {"terms": {"field": "data.srcuser", "size": 3}}}}}},
        path=["cc", "u"], cols=["^key", "key", "doc_count"]),
    P.Q("Q3", "서버존(10.20.40.x)으로 들어온 동서 연결 — 출발지별 포트·목적지 수",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.event_type": "flow"}}, {"prefix": {"data.dest_ip": "10.20.40."}}]}},
         "aggs": {"src": {"terms": {"field": "data.src_ip", "size": 5, "order": {"ports": "desc"}},
                          "aggs": {"ports": {"cardinality": {"field": "data.dest_port"}}, "dsts": {"cardinality": {"field": "data.dest_ip"}}}}}},
        path=["src"], cols=["key", "doc_count", "ports.value", "dsts.value"]),
    P.Q("Q4", "KT66-WIN-01 로그온 성공(4624) — 유형 × 출발 IP",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "KT66-WIN-01"}}, {"term": {"data.win.system.eventID": "4624"}}]}},
         "aggs": {"lt": {"terms": {"field": "data.win.eventdata.logonType", "size": 4},
                         "aggs": {"ip": {"terms": {"field": "data.win.eventdata.ipAddress", "size": 2, "missing": "-"}}}}}},
        path=["lt", "ip"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "KT66-WIN-01 레벨 8 이상 경보",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "KT66-WIN-01"}}, {"range": {"rule.level": {"gte": 8}}}]}},
         "aggs": {"r": {"terms": {"field": "rule.description", "size": 4},
                        "aggs": {"u": {"terms": {"field": "data.win.eventdata.targetUserName", "size": 1}}}}}},
        path=["r", "u"], cols=["^key", "key", "doc_count"]),
    P.Q("Q6", "kim.minjun·svc_backup·neobank발 로그온 — 10분 버킷 중 4건 이상만, 호스트별",
        {"size": 0, "query": {"bool": {"should": [{"term": {"data.srcuser": "kim.minjun"}},
                                                  {"term": {"data.win.eventdata.ipAddress": "10.20.40.83"}},
                                                  {"term": {"data.win.eventdata.targetUserName": "svc_backup"}}],
                                       "minimum_should_match": 1}},
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "10m", "time_zone": "+09:00",
                                           "format": "MM-dd HH:mm", "min_doc_count": 1},
                        "aggs": {"ag": {"terms": {"field": "agent.name", "size": 8}},
                                 "busy": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 4"}}}}}},
        path=["t", "ag"], cols=["^key_as_string", "key", "doc_count"]),
]

MON = P.Q("MON", "한 계정이 10분 안에 서버 4대 이상 로그인", QUERIES[0].body, path=["u", "t"],
          cols=["^key", "key_as_string", "hosts.value"],
          trigger="ctx.results[0].aggregations.u.buckets.stream().anyMatch(b -> b.t.buckets.size() > 0)")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
