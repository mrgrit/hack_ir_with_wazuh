#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R15 최종 — 사람의 느린 체인 + AI 의 빠른 체인 + 허가된 점검·정상 백업이라는 '미끼'.

Red(로그로만 재현)
  사람(두 달): D-60 피싱 → park.jiwoo PC(WINWORD → powershell) → 30분±6분 HTTPS 비콘
              → D-21 그 PC 에서 관리자 계정으로 관리콘솔 SSH → D-9·D-3 DNS 터널
  AI(3분): D-1 03:00 챗봇 프롬프트 인젝션 → http_fetch 로 관리콘솔 내부 API(사용자 내보내기) SSRF → 외부 전송
  미끼: ① 허가된 외부 점검업체(D-14, govportal 경로 대입) ② neobank 매일 01시 백업 업로드(정상)
Blue: 지금까지의 집계 기법을 골라 쓰고, 미끼(허용 목록)를 근거와 함께 제외한다.
"""
import purplelab as P

ROUND, TITLE, SEED = "r15", "최종 — 혼합 체인과 미끼", 1515
VENDOR_NOTE = "허가된 점검: 2026 정기 취약점 점검(점검업체 IP 는 lab 문서의 허용 목록에 기재)"


def attack(S):
    S.opts["audit"] = True
    mta = S.ext_ip("Netherlands")
    c2 = S.ext_ip("United States")
    ai_user_ip = S.ext_ip("Singapore")
    out = S.ext_ip("United States")
    vendor = S.ext_ip("Republic of Korea")
    backup = S.ext_ip("United States")
    S.ips.update(mta=mta, c2=c2, ai=ai_user_ip, out=out, vendor=vendor, backup=backup)
    pc = "10.20.70.10"
    span = min(60, P.DAYS - 1)
    # 미끼 ②: 매일 01시 neobank 백업 업로드 (정상)
    for d in range(P.DAYS - 1, 0, -1):
        S.add(P.flow(S.at(d, 1, 0, S.rnd.uniform(0, 50)), P.IP_OF["neobank"], backup, 443, S.rnd.randint(1_800_000_000, 2_200_000_000), 90_000, "tls", 900))
    # 사람: 피싱 → 실행 → 비콘
    t = S.at(span, 9, 41, 0)
    for v in S.rnd.sample(P.EMPLOYEES, 11) + [P.WIN_USER]:
        t += S.rnd.uniform(3, 9)
        S.add(P.mail(t, "in", mta, "hr-notice@kt66-hr.support", v + "@kt66.lab", 48_000, "sent"))
    t = S.at(span, 10, 30, 0)
    S.add(P.win(t, 4688, P.WIN_USER, proc="C:\\Program Files\\Microsoft Office\\WINWORD.EXE", cmd="WINWORD.EXE /n 급여명세_정정.docm",
                parent="C:\\Windows\\explorer.exe"))
    S.add(P.win(t + 6, 4688, P.WIN_USER, proc="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...", parent="C:\\Program Files\\Microsoft Office\\WINWORD.EXE"))
    t += 30
    while t < S.anchor:
        S.add(P.flow(t, pc, c2, 443, S.rnd.randint(900, 1500), S.rnd.randint(1200, 3000), "tls", 1))
        t += S.rnd.uniform(1440, 2160)
    t = S.at(21, 22, 14, 0)
    S.add(P.ssh(t, "adminconsole", pc, "kim.minjun", "5715"))
    S.add(P.sudo(t + 30, "adminconsole", "kim.minjun", "/bin/cat /opt/admin/db.env"))
    for d in (9, 3):
        t = S.at(d, 2, 5, 0)
        for i in range(250):
            t += S.rnd.uniform(1, 7)
            S.add(P.dns(t, pc, "%040x%04x.telemetry-kt66.net" % (S.rnd.getrandbits(160), i), "TXT"))
    # 미끼 ①: 허가된 점검업체 경로 대입 (D-14 14시)
    t = S.at(14, 14, 0, 0)
    for i in range(350):
        t += S.rnd.uniform(0.5, 2)
        S.add(P.web(t, "govportal", vendor, "GET", f"/{['admin', 'backup', 'test', 'old', 'api', 'dev'][i % 6]}/{i:04d}", 404, 196, 4,
                    "Mozilla/5.0 (KT66-Authorized-Scanner)"))
    # AI: 3분 체인
    t = S.at(1, 3, 0, 0)
    for i in range(40):
        t += S.rnd.uniform(1.5, 3.5)
        S.add(P.web(t, "aicompanion", ai_user_ip, "POST", "/api/chat", 200, 2200, 1500, "python-httpx/0.27.0"))
        S.add(P.ai(t + 0.02, "u5520193", ai_user_ip, S.rnd.randint(2500, 6000), S.rnd.randint(300, 6000), "http_fetch" if i % 2 else "none",
                   ["injection_pattern"], False))
        if i % 2:
            S.add(P.web(t + 0.4, "adminconsole", P.IP_OF["aicompanion"], "GET", "/api/users/export?format=json&page=%d" % (i // 2),
                        200, S.rnd.randint(400_000, 900_000), 300, "aicompanion-tools/1.2"))
    S.add(P.flow(t + 20, P.IP_OF["aicompanion"], out, 443, 14_000_000, 20_000, "tls", 25))


S0 = P.Scenario(0, SEED)
attack(S0)
IP = S0.ips
FLOW = {"term": {"data.event_type": "flow"}}

QUERIES = [
    P.Q("Q1", "KT66-WIN-01 프로세스 생성 — 부모 × 자식 (드문 쌍)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"agent.name": "KT66-WIN-01"}}, {"term": {"data.win.system.eventID": "4688"}}]}},
         "aggs": {"p": {"terms": {"field": "data.win.eventdata.parentProcessName", "size": 4, "order": {"_count": "asc"}},
                        "aggs": {"c": {"terms": {"field": "data.win.eventdata.newProcessName", "size": 2}}}}}},
        path=["p", "c"], cols=["^key", "key", "doc_count"]),
    P.Q("Q2", "KT66-WIN-01 외부 목적지 — 건수·활동 일수·업로드 MB",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"term": {"data.src_ip": "10.20.70.10"}}]}},
         "aggs": {"d": {"terms": {"field": "data.dest_ip", "size": 3},
                        "aggs": {"days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}},
                                 "up": {"sum": {"field": "data.flow.bytes_toserver"}}}}}},
        path=["d"], cols=["key", "doc_count", "days.buckets|len", "up.value|mb"]),
    P.Q("Q3", "서버 SSH 로그인 — bastion(10.20.30.201)이 아닌 출발지",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"rule.id": "5715"}}, {"prefix": {"data.srcip": "10."}}],
                                       "must_not": [{"term": {"data.srcip": "10.20.30.201"}}, {"term": {"agent.name": "bastion"}}]}},
         "aggs": {"src": {"terms": {"field": "data.srcip", "size": 5},
                          "aggs": {"t": {"terms": {"field": "agent.name", "size": 2}}, "u": {"terms": {"field": "data.srcuser", "size": 1}}}}}},
        path=["src", "t"], cols=["^key", "key", "doc_count"]),
    P.Q("Q4", "DNS — 서로 다른 질의 이름 200개 이상인 도메인",
        {"size": 0, "query": {"term": {"decoder.name": "kt66-dns"}},
         "aggs": {"dom": {"terms": {"field": "data.domain", "size": 20, "order": {"n": "desc"}},
                          "aggs": {"n": {"cardinality": {"field": "data.query"}},
                                   "src": {"terms": {"field": "data.srcip", "size": 1}},
                                   "hit": {"bucket_selector": {"buckets_path": {"x": "n"}, "script": "params.x >= 200"}}}}}},
        path=["dom", "src"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "관리콘솔 웹 — 출발지별 요청·응답 합계 MB (내부 출발지 포함)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}}, {"term": {"data.vhost": "admin.kt66.lab"}}]}},
         "aggs": {"src": {"terms": {"field": "data.srcip", "size": 4, "order": {"b": "desc"}},
                          "aggs": {"b": {"sum": {"field": "data.bytes"}}}}}},
        path=["src"], cols=["key", "doc_count", "b.value|mb"]),
    P.Q("Q6", "서버존 → 외부 업로드 — 목적지별 MB·활동 일수 (매일 반복 = 정상 백업 후보)",
        {"size": 0, "query": {"bool": {"filter": [FLOW, {"prefix": {"data.src_ip": "10.20.40."}}, {"range": {"data.flow.bytes_toserver": {"gte": 10000000}}}]}},
         "aggs": {"d": {"terms": {"field": "data.dest_ip", "size": 4, "order": {"up": "desc"}},
                        "aggs": {"up": {"sum": {"field": "data.flow.bytes_toserver"}}, "src": {"terms": {"field": "data.src_ip", "size": 1}},
                                 "days": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "time_zone": "+09:00", "min_doc_count": 1}}}}}},
        path=["d"], cols=["key", "doc_count", "up.value|mb", "days.buckets|len"]),
    P.Q("Q7", "404 고유 URL 100개 이상 IP (허용 목록 대조용)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"decoder.name": "web-accesslog"}}, {"term": {"data.id": "404"}}]}},
         "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 20, "order": {"u": "desc"}},
                         "aggs": {"u": {"cardinality": {"field": "data.url"}}, "ua": {"terms": {"field": "data.user_agent", "size": 1}},
                                  "hit": {"bucket_selector": {"buckets_path": {"x": "u"}, "script": "params.x >= 100"}}}}}},
        path=["ip", "ua"], cols=["^key", "key", "doc_count"]),
]

MON = P.Q("MON", "bastion 이 아닌 내부 출발지의 서버 SSH 로그인", QUERIES[2].body, path=["src", "t"], cols=["^key", "key", "doc_count"],
          trigger="ctx.results[0].aggregations.src.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
