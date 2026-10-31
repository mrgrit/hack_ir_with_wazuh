#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R09 중간 종합 — 석 달에 걸친 사람 속도의 전체 체인 (R02~R08 기법 결합, 무예고)

Red(로그로만 재현) — 표적 govportal(10.20.40.84) → neobank·mediforum
  ① D-85~D-40 정찰(재방문 패턴)  ② D-35 SQLi: 차단→우회→덤프  ③ D-34 밤 웹셸 업로드·명령
  ④ D-33 권한상승(sudo 오용)·계정 생성·cron  ⑤ D-20 shadow 열람 → govportal 에서 neobank·mediforum 으로 SSH
  ⑥ D-5 neobank → 외부 대용량 전송  ⑦ D-4 로그 삭제
Blue: R03·R04·R05·R07·R08 의 집계를 한 인덱스에서 다시 쓰고, 날짜순으로 이어 붙여 체인을 복원한다.
"""
import purplelab as P

ROUND, TITLE, SEED = "r09", "중간 종합 — 석 달짜리 체인", 909


def attack(S):
    S.opts["audit"] = True
    I1 = S.ext_ip("China")
    I2 = S.ext_ip("China")
    I3 = S.ext_ip("United States")
    S.ips.update(I1=I1, I2=I2, I3=I3)
    ua = P.UA_LIST[3]
    gov = "govportal"
    for t0 in S.visits(min(85, P.DAYS - 1), 40, revisit_scale=0.8):
        for tt in S.session_times(t0, S.rnd.randint(5, 25), gap_scale=0.2):
            S.add(P.web(tt, gov, I1, "GET", "/" + S.rnd.choice(["admin", "backup", "old", "api", "search", "files", "manager"]) + S.rnd.choice(["", "/", ".php", ".bak"]),
                        404, 196, S.rnd.randint(3, 20), ua))
    t = S.at(35, 10, 2, 0)
    for i in range(300):
        t += S.rnd.uniform(2, 6)
        url = "/search?q=" + S.rnd.choice(["1%27+OR+%271%27%3D%271", "x%27+UNION+SELECT+NULL--", "1%27+AND+SLEEP(5)--"])
        S.add(P.waf(t, gov, I1, url, "942100", "SQL Injection Attack Detected via libinjection"))
        S.add(P.web(t + 0.002, gov, I1, "GET", url, 403, 199, 3, ua))
    for i in range(180):
        t += S.rnd.uniform(5, 12)
        S.add(P.web(t, gov, I1, "GET", "/search?q=x%2527/**/uNiOn/**/sElEcT/**/1,2,3--", 200, S.rnd.randint(7000, 9000), S.rnd.randint(50, 900), ua))
    for i in range(12):
        t += S.rnd.uniform(30, 90)
        S.add(P.web(t, gov, I1, "GET", f"/search?q=x%2527/**/uNiOn/**/sElEcT/**/name,rrn,phone/**/FROM/**/citizens/**/LIMIT/**/{i * 10000},10000",
                    200, S.rnd.randint(2_000_000, 4_500_000), S.rnd.randint(3000, 9000), ua))
    t = S.at(34, 22, 30, 0)
    shell = "/var/www/govportal/files/m_8812.php"
    S.add(P.web(t, gov, I2, "POST", "/minwon/apply", 200, 820, 260, ua))
    S.add(P.fim(t + 0.5, gov, shell, "added", "www-data"))
    for c in ["id", "uname -a", "cat /etc/passwd", "sudo -l", "ls /var/www/govportal", "cat /var/www/govportal/config.yml",
              "ps aux", "netstat -tnlp", "find / -perm -4000 2>/dev/null", "crontab -l", "whoami", "hostname"]:
        t += S.rnd.uniform(40, 200)
        S.add(P.web(t, gov, I2, "GET", "/files/m_8812.php?c=" + c.replace(" ", "+").replace("/", "%2F"), 200, S.rnd.randint(80, 3000), 120, ua))
        S.add(P.audit(t + 0.05, gov, "www-data", "/bin/sh", "sh -c " + c, "/usr/sbin/apache2"))
    t = S.at(33, 2, 10, 0)
    for i in range(4):
        t += 20
        S.add(P.sudo(t, gov, "www-data", "list", ok=False))
    S.add(P.sudo(t + 40, gov, "www-data", "/usr/bin/find . -exec /bin/sh ; -quit"))
    S.add(P.useradd(t + 120, gov, "backupsvc"))
    S.add(P.fim(t + 121, gov, "/etc/passwd", "modified"))
    S.add(P.fim(t + 180, gov, "/etc/cron.d/backupsvc", "added"))
    t = S.at(20, 3, 0, 0)
    S.add(P.audit(t, gov, "root", "/usr/bin/cat", "cat /etc/shadow", "/bin/sh"))
    src = P.IP_OF[gov]
    for tgt in ("neobank", "mediforum"):
        for _ in range(3):
            t += 6
            S.add(P.ssh(t, tgt, src, "deploy", "5716"))
        t += 30
        S.add(P.ssh(t, tgt, src, "deploy", "5715"))
    t = S.at(5, 2, 30, 0)
    for i in range(4):
        t += S.rnd.uniform(300, 600)
        S.add(P.flow(t, P.IP_OF["neobank"], I3, 443, S.rnd.randint(300_000_000, 420_000_000), 50_000, "tls", 200))
    t = S.at(4, 4, 0, 0)
    for pth in ["/var/log/apache2/govportal_access.log", "/root/.bash_history", shell]:
        t += 10
        S.add(P.fim(t, gov, pth, "deleted"))


S0 = P.Scenario(0, SEED)
attack(S0)
IP = S0.ips
WEB = {"term": {"decoder.name": "web-accesslog"}}
ACT = {"bool": {"should": [{"terms": {"data.srcip": [IP["I1"], IP["I2"]]}}, {"term": {"data.audit.parent": "/usr/sbin/apache2"}},
                           {"term": {"data.srcuser": "www-data"}}, {"term": {"rule.id": "5902"}},
                           {"bool": {"filter": [{"term": {"rule.id": "5715"}}, {"prefix": {"data.srcip": "10.20.40."}}]}},
                           {"bool": {"filter": [{"term": {"data.event_type": "flow"}}, {"term": {"data.dest_ip": IP["I3"]}}]}},
                           {"bool": {"filter": [{"term": {"syscheck.event": "deleted"}}, {"term": {"agent.name": "govportal"}}],
                                     "must_not": [{"wildcard": {"syscheck.path": "*.gz"}}]}}],
                "minimum_should_match": 1}}

QUERIES = [
    P.Q("Q1", "차단 20회+ · 통과 20회+ 를 함께 가진 외부 IP (R03 기법)",
        {"size": 0, "query": {"bool": {"filter": [WEB], "must_not": [{"prefix": {"data.srcip": "10."}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 100, "order": {"blocked": "desc"}},
                            "aggs": {"blocked": {"filter": {"term": {"data.id": "403"}}}, "ok": {"filter": {"term": {"data.id": "200"}}},
                                     "mx": {"max": {"field": "data.bytes"}},
                                     "hit": {"bucket_selector": {"buckets_path": {"b": "blocked>_count", "o": "ok>_count"}, "script": "params.b >= 20 && params.o >= 20"}}}}}},
        path=["by_ip"], cols=["key", "blocked.doc_count", "ok.doc_count", "mx.value"]),
    P.Q("Q2", "웹서버 프로세스(apache2)가 실행한 셸 — 호스트별 (R04 기법)",
        {"size": 0, "query": {"term": {"data.audit.parent": "/usr/sbin/apache2"}},
         "aggs": {"ag": {"terms": {"field": "agent.name", "size": 5}}}},
        path=["ag"], cols=["key", "doc_count"]),
    P.Q("Q3", "관리자가 아닌 sudo 사용자 (R05 기법)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "sudo"}}], "must_not": [{"terms": {"data.srcuser": P.ADMINS}}]}},
         "aggs": {"u": {"terms": {"field": "data.srcuser", "size": 5}, "aggs": {"ag": {"terms": {"field": "agent.name", "size": 2}}}}}},
        path=["u", "ag"], cols=["^key", "key", "doc_count"]),
    P.Q("Q4", "서버존 출발 SSH (bastion 이 아닌 곳에서 들어온 로그인) (R07 기법)",
        {"size": 0, "query": {"bool": {"filter": [{"terms": {"rule.id": ["5715", "5716"]}}, {"prefix": {"data.srcip": "10.20.40."}}]}},
         "aggs": {"tgt": {"terms": {"field": "agent.name", "size": 5}, "aggs": {"r": {"terms": {"field": "rule.id", "size": 2}}}}}},
        path=["tgt", "r"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "서버존 → 외부 업로드 합계 MB 상위 (R08 기법)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.event_type": "flow"}}, {"prefix": {"data.src_ip": "10.20.40."}}]}},
         "aggs": {"dst": {"terms": {"field": "data.dest_ip", "size": 3, "order": {"up": "desc"}},
                          "aggs": {"up": {"sum": {"field": "data.flow.bytes_toserver"}}, "srcs": {"cardinality": {"field": "data.src_ip"}}}}}},
        path=["dst"], cols=["key", "doc_count", "up.value|mb", "srcs.value"]),
    P.Q("Q6", "체인 복원 — 공격 관련 이벤트의 날짜별·종류별 건수",
        {"size": 0, "query": ACT,
         "aggs": {"d": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "format": "yyyy-MM-dd", "min_doc_count": 1},
                        "aggs": {"k": {"terms": {"field": "decoder.name", "size": 4}}}}}},
        path=["d", "k"], cols=["^key_as_string", "key", "doc_count"]),
]

MON = P.Q("MON", "서버존 IP 에서 들어온 SSH 로그인 성공", 
          {"size": 0, "query": {"bool": {"filter": [{"term": {"rule.id": "5715"}}, {"prefix": {"data.srcip": "10.20.40."}}]}},
           "aggs": {"tgt": {"terms": {"field": "agent.name", "size": 10},
                            "aggs": {"hit": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 1"}}}}}},
          path=["tgt"], cols=["key", "doc_count"],
          trigger="ctx.results[0].aggregations.tgt.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
