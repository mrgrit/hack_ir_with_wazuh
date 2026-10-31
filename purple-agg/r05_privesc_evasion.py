#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R05 권한상승·방어회피 — sudo 를 쓰지 않던 계정, /dev/shm 의 [kworker], 그리고 '로그가 끊긴 2시간'.

Red(로그로만 재현) — mediforum(10.20.40.85), www-data 셸에서
  1) sudo -l 실패 반복 → find -exec 로 root 셸   2) /dev/shm 에 커널 스레드 이름으로 위장한 프로세스
  3) auth.log 비우기·history 삭제·wazuh-agent 중지 → 약 2시간 로그 공백   4) 재시작 후 FIM 이 삭제를 보고
Blue: sudo 사용자 분포 → www-data 명령 → 10분 단위 0건 구간 → 수상 경로 실행 → 삭제 파일 → 타임라인
"""
import purplelab as P

ROUND, TITLE, SEED = "r05", "권한상승·방어회피 — 끊긴 로그도 신호다", 505


def attack(S):
    S.opts["audit"] = True
    ag = "mediforum"
    t = S.at(2, 0, 40, 5)
    for i in range(6):
        t += S.rnd.uniform(4, 15)
        S.add(P.sudo(t, ag, "www-data", "list", ok=False))
        S.add(P.audit(t + 0.01, ag, "www-data", "/usr/bin/sudo", "sudo -l", "/bin/sh"))
    t += 40
    S.add(P.sudo(t, ag, "www-data", "/usr/bin/find . -exec /bin/sh ; -quit"))
    S.add(P.audit(t + 0.02, ag, "root", "/usr/bin/find", "find . -exec /bin/sh ; -quit", "/usr/bin/sudo"))
    S.add(P.audit(t + 0.05, ag, "root", "/bin/sh", "/bin/sh", "/usr/bin/find"))
    steps = [("/usr/bin/cp", "cp /tmp/.x/update.sh /dev/shm/.k", "/bin/sh"),
             ("/dev/shm/[kworker/u8:2]", "[kworker/u8:2]", "/bin/sh"),
             ("/usr/bin/truncate", "truncate -s 0 /var/log/auth.log", "/bin/sh"),
             ("/usr/bin/rm", "rm -f /root/.bash_history /home/www-data/.bash_history", "/bin/sh"),
             ("/usr/bin/sed", "sed -i /10.20/d /var/log/apache2/mediforum_access.log", "/bin/sh"),
             ("/usr/bin/systemctl", "systemctl stop wazuh-agent", "/bin/sh")]
    for exe, cmd, par in steps:
        t += S.rnd.uniform(30, 120)
        S.add(P.audit(t, ag, "root", exe, cmd, par))
    gap0 = t + 1
    gap1 = S.at(2, 3, 5, 12)
    S.drops.append((ag, gap0, gap1))
    S.ips["gap"] = (gap0, gap1)
    # 앞서 한 달 동안 '연습': 새벽에 에이전트를 70~110분씩 세 번 멈췄다 (실제 공격자의 반복 접근 시간대)
    for d in (29, 18, 9):
        if d < P.DAYS:
            g0 = S.at(d, S.rnd.choice([1, 2, 3]), S.rnd.randint(0, 5))
            S.add(P.audit(g0 - 1, ag, "root", "/usr/bin/systemctl", "systemctl stop wazuh-agent", "/bin/sh"))
            S.drops.append((ag, g0, g0 + S.rnd.randint(70, 110) * 60))
    t = gap1 + 30
    S.add(P.audit(t, ag, "root", "/usr/bin/systemctl", "systemctl start wazuh-agent", "/usr/sbin/cron"))
    for i, pth in enumerate(["/root/.bash_history", "/home/www-data/.bash_history", "/var/log/apache2/mediforum_access.log.1"]):
        S.add(P.fim(t + 60 + i, ag, pth, "deleted"))
    S.add(P.fim(t + 70, ag, "/var/log/auth.log", "modified"))
    # 위장 프로세스는 계속 돈다(재시작 이후에도 auditd 가 본다): 30분마다 자기 재실행
    k = t + 300
    while k < S.anchor:   # D-2 이후
        S.add(P.audit(k, ag, "root", "/dev/shm/[kworker/u8:2]", "[kworker/u8:2]", "/usr/sbin/cron"))
        k += 1800


S0 = P.Scenario(0, SEED)
attack(S0)

QUERIES = [
    P.Q("Q1", "sudo 사용자 × 결과(rule.id)",
        {"size": 0, "query": {"term": {"decoder.name": "sudo"}},
         "aggs": {"u": {"terms": {"field": "data.srcuser", "size": 20, "order": {"_key": "asc"}},
                        "aggs": {"r": {"terms": {"field": "rule.id", "size": 2}}}}}},
        path=["u", "r"], cols=["^key", "key", "doc_count"]),
    P.Q("Q2", "www-data 가 sudo 로 실행하려 한 명령",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "sudo"}}, {"term": {"data.srcuser": "www-data"}}]}},
         "aggs": {"c": {"terms": {"field": "data.command", "size": 5}}}},
        path=["c"], cols=["key", "doc_count"]),
    P.Q("Q3", "mediforum 이벤트 1시간 단위 — 0건 구간만",
        {"size": 0, "query": {"term": {"agent.name": "mediforum"}},
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "+09:00",
                                           "format": "MM-dd HH:mm", "min_doc_count": 0},
                        "aggs": {"zero": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c == 0"}}}}}},
        path=["t"], cols=["key_as_string", "doc_count"]),
    P.Q("Q4", "실행 파일 경로 — /tmp · /dev/shm 에서 실행된 것",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "auditd"}}],
                                       "should": [{"prefix": {"data.audit.exe": "/tmp/"}}, {"prefix": {"data.audit.exe": "/dev/shm/"}}],
                                       "minimum_should_match": 1}},
         "aggs": {"exe": {"terms": {"field": "data.audit.exe", "size": 5},
                          "aggs": {"u": {"terms": {"field": "data.audit.auid", "size": 1}}}}}},
        path=["exe", "u"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "파일 삭제(FIM 553) 경로",
        {"size": 0, "query": {"term": {"rule.id": "553"}},
         "aggs": {"p": {"terms": {"field": "syscheck.path", "size": 8}}}},
        path=["p"], cols=["key", "doc_count"]),
    P.Q("Q6", "mediforum 의 root·www-data 명령 (auditd) — 시간순 첫 10줄",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "mediforum"}}, {"term": {"decoder.name": "auditd"}},
                                                  {"terms": {"data.audit.auid": ["root", "www-data"]}}],
                                       "must_not": [{"term": {"data.audit.exe": "/usr/bin/php"}}]}},
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m", "time_zone": "+09:00",
                                           "format": "MM-dd HH:mm", "min_doc_count": 1},
                        "aggs": {"c": {"terms": {"field": "data.audit.command", "size": 3}}}}}},
        path=["t", "c"], cols=["^key_as_string", "key"], head=12),
]

MON = P.Q("MON", "대량 로그 서버 4대 중 1시간 동안 이벤트 0건이 된 구간",
          {"size": 0, "query": {"terms": {"agent.name": ["juiceshop", "neobank", "govportal", "mediforum"]}},
           "aggs": {"ag": {"terms": {"field": "agent.name", "size": 4},
                           "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "+09:00",
                                                             "format": "MM-dd HH:mm", "min_doc_count": 0},
                                          "aggs": {"zero": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c == 0"}}}}}}}},
          path=["ag", "t"], cols=["^key", "key_as_string", "doc_count"],
          trigger="ctx.results[0].aggregations.ag.buckets.stream().anyMatch(b -> b.t.buckets.size() > 0)")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
