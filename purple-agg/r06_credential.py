#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R06 자격증명 접근 — IP 당 1~2번뿐인 분산 대입, 낯선 발신 도메인, 두 번째 나라에서의 로그인.

Red(로그로만 재현)
  1) 웹메일 비밀번호 분산 대입(spray): 1,200개 IP(대부분 국내)가 D-60~D-1 에 걸쳐 1~2번씩 — 3개 계정 성공 → 몇 주에 걸쳐 다른 출구 IP 로 재로그인
  2) 피싱: 유사 도메인에서 직원 40명에게 3분 안에 발송 → 1명(lee.yuna) 계정이 해외에서 로그인·메일함 열람
Blue: IP 별 실패(소용없음) → 계정별 실패 IP 수 → 계정별 외부 성공 IP 수 → 해외 성공 → 희귀 발신 도메인 → 메일함 열람량
"""
import purplelab as P

ROUND, TITLE, SEED = "r06", "자격증명 접근 — 분산 대입과 피싱", 606
PHISH_DOMAIN = "kt66-lab.help"


def attack(S):
    spray = [S.ext_ip("Republic of Korea" if S.rnd.random() < 0.7 else None) for _ in range(1200)]
    mta = S.ext_ip("Netherlands")
    nl = S.ext_ip("Netherlands")
    S.ips.update(mta=mta, nl=nl)
    won = ["choi.jiho", "kang.seoah", "jung.dohyun"]
    S.ips["won"] = won
    span = min(60, P.DAYS - 1)
    ua = P.UA_LIST[0]
    for i, ip in enumerate(spray):
        for _ in range(1 if S.rnd.random() < 0.7 else 2):
            t = S.at(S.rnd.randint(1, span), S.hour_pick())
            u = S.rnd.choice(P.EMPLOYEES)
            ok = False
            if i < 3:
                u, ok = won[i], True
            S.add(P.web(t, "webmail", ip, "POST", "/?_task=login", 302 if ok else 401, 600, S.rnd.randint(80, 200), ua))
            S.add(P.appauth(t + 0.01, "webmail", ip, u, ok, "" if ok else "bad_password"))
    # 피싱 → 해외 로그인
    t = S.at(12, 10, 12, 0)
    victims = S.rnd.sample(P.EMPLOYEES, 40)
    if "lee.yuna" not in victims:
        victims[0] = "lee.yuna"
    for v in victims:
        t += S.rnd.uniform(2, 6)
        S.add(P.mail(t, "in", mta, f"it-support@{PHISH_DOMAIN}", v + "@kt66.lab", S.rnd.randint(14000, 16000), "sent"))
    t = S.at(11, 3, 10, 0)
    S.add(P.web(t, "webmail", nl, "POST", "/?_task=login", 302, 610, 140, P.UA_LIST[4]))
    S.add(P.appauth(t + 0.01, "webmail", nl, "lee.yuna", True))
    for k in range(320):
        t += S.rnd.uniform(1.5, 6)
        S.add(P.web(t, "webmail", nl, "GET", f"/?_task=mail&_action=show&_uid={9000 - k}", 200, S.rnd.randint(6000, 40000),
                    S.rnd.randint(40, 150), P.UA_LIST[4]))
    # 이후 몇 주 동안 가끔 재접속 (실제 로그 재방문 패턴) — VPN 출구를 바꿔 가며
    nl2 = S.ext_ip("Netherlands")
    vpn = [S.ext_ip(None) for _ in range(5)]
    S.ips.update(nl2=nl2, vpn=vpn)
    for k, t0 in enumerate(S.visits(9, 1, revisit_scale=1.2)):
        ip = nl if k % 2 == 0 else nl2
        S.add(P.web(t0, "webmail", ip, "POST", "/?_task=login", 302, 610, 140, P.UA_LIST[4]))
        S.add(P.appauth(t0 + 0.01, "webmail", ip, "lee.yuna", True))
    # 대입으로 맞힌 3개 계정: 성공 뒤 며칠~몇 주에 걸쳐 다른 출구 IP 로 다시 로그인(계정 확인·메일 열람)
    for j, u in enumerate(won):
        for k, t0 in enumerate(S.visits(min(55, P.DAYS - 1), 1, revisit_scale=1.0)[:4]):
            ip = vpn[(j + k) % len(vpn)]
            S.add(P.web(t0, "webmail", ip, "POST", "/?_task=login", 302, 610, 150, ua))
            S.add(P.appauth(t0 + 0.01, "webmail", ip, u, True))
            for m in range(S.rnd.randint(3, 12)):
                S.add(P.web(t0 + 5 + m * S.rnd.uniform(3, 20), "webmail", ip, "GET", f"/?_task=mail&_action=show&_uid={S.rnd.randint(1000, 9000)}",
                            200, S.rnd.randint(6000, 40000), S.rnd.randint(40, 150), ua))


S0 = P.Scenario(0, SEED)
attack(S0)
AUTH = {"term": {"data.app": "webmail"}}

QUERIES = [
    P.Q("Q1", "웹메일 로그인 실패 — IP 별 상위 5 (IP 당 횟수)",
        {"size": 0, "query": {"bool": {"filter": [AUTH, {"term": {"data.result": "fail"}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5}}}},
        path=["by_ip"], cols=["key", "doc_count"]),
    P.Q("Q2", "웹메일 로그인 실패 — 계정별 서로 다른 출발 IP 수 (상위 5)",
        {"size": 0, "query": {"bool": {"filter": [AUTH, {"term": {"data.result": "fail"}}]}},
         "aggs": {"by_user": {"terms": {"field": "data.srcuser", "size": 5, "order": {"ips": "desc"}},
                              "aggs": {"ips": {"cardinality": {"field": "data.srcip"}}}}}},
        path=["by_user"], cols=["key", "doc_count", "ips.value"]),
    P.Q("Q3", "웹메일 로그인 성공 — 계정별 서로 다른 '외부' IP 수 (2 이상)",
        {"size": 0, "query": {"bool": {"filter": [AUTH, {"term": {"data.result": "success"}}],
                                       "must_not": [{"prefix": {"data.srcip": "10."}}]}},
         "aggs": {"by_user": {"terms": {"field": "data.srcuser", "size": 300, "order": {"ips": "desc"}},
                              "aggs": {"ips": {"cardinality": {"field": "data.srcip"}},
                                       "two": {"bucket_selector": {"buckets_path": {"n": "ips"}, "script": "params.n >= 2"}}}}}},
        path=["by_user"], cols=["key", "doc_count", "ips.value"]),
    P.Q("Q4", "웹메일 로그인 성공 — 국외 출발지",
        {"size": 0, "query": {"bool": {"filter": [AUTH, {"term": {"data.result": "success"}}, {"exists": {"field": "GeoLocation.country_name"}}],
                                       "must_not": [{"term": {"GeoLocation.country_name": "Republic of Korea"}}]}},
         "aggs": {"by_user": {"terms": {"field": "data.srcuser", "size": 5},
                              "aggs": {"cc": {"terms": {"field": "GeoLocation.country_name", "size": 2}}}}}},
        path=["by_user", "cc"], cols=["^key", "key", "doc_count"]),
    P.Q("Q5", "수신 메일(전달됨) — 발신 도메인 중 드문 것 (적은 순 3) · 수신자 수",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.direction": "in"}}, {"term": {"data.status": "sent"}}]}},
         "aggs": {"dom": {"terms": {"field": "data.from_domain", "size": 3, "order": {"_count": "asc"}},
                          "aggs": {"rcpt": {"cardinality": {"field": "data.to"}}}}}},
        path=["dom"], cols=["key", "doc_count", "rcpt.value"]),
    P.Q("Q6", "웹메일 — 서로 다른 메일을 가장 많이 연 IP (상위 5)",
        {"size": 0, "query": {"bool": {"filter": [{"term": {"data.vhost": "webmail.kt66.lab"}}, {"term": {"decoder.name": "web-accesslog"}}]}},
         "aggs": {"by_ip": {"terms": {"field": "data.srcip", "size": 5, "order": {"urls": "desc"}},
                            "aggs": {"urls": {"cardinality": {"field": "data.url"}}}}}},
        path=["by_ip"], cols=["key", "doc_count", "urls.value"]),
]

MON = P.Q("MON", "외부 IP 2곳 이상에서 로그인에 성공한 웹메일 계정",
          QUERIES[2].body, path=["by_user"], cols=["key", "doc_count", "ips.value"],
          trigger="ctx.results[0].aggregations.by_user.buckets.size() > 0")

if __name__ == "__main__":
    P.main(ROUND, TITLE, attack, QUERIES, SEED, monitor=MON)
