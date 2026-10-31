#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
purple_http_replay.py — rNN_http.jsonl 을 ModSecurity 스텁 vhost(purple-test.kt66.lab)로 재생해 룰을 검증한다.

  · 요청은 Host: purple-test.kt66.lab 으로만 보낸다 — 스텁은 "ok" 만 돌려주고 어떤 앱에도 닿지 않는다.
  · 원래 출발지 IP 는 X-Purple-Client, 원래 상태코드는 X-Purple-Status 헤더로 보낸다
    (스텁의 mod_remoteip·stub.cgi 가 받아서 IP 별 카운터·응답 단계 카운터가 실제처럼 돈다).
  · 시간: 원래 간격을 --speed 배 빠르게, 간격이 --max-gap 초보다 길면 잘라서 재생.
  · 결과: 403/404/429/400/413 로 바뀐 요청 = ModSec 이 막은 요청. 룰 id 는 스텁 error 로그에서 집계.

사용
  python3 purple_http_replay.py r02_http.jsonl --host 127.0.0.1
  python3 purple_http_replay.py r13_http.jsonl --host 10.20.32.80 --speed 1 --max-gap 2
  sudo grep -o 'id "9[0-9]\\{4\\}"' /var/log/apache2/purple_test_error.log | sort | uniq -c
"""
import argparse
import collections
import json
import sys
import time
import urllib.error
import urllib.request
import uuid


def send(base, rec, timeout):
    url = base + rec["url"]
    hdr = {"Host": "purple-test.kt66.lab", "User-Agent": rec.get("ua", "-"),
           "X-Purple-Client": rec["src"], "X-Purple-Status": str(rec.get("status", 200))}
    data = None
    if "json" in rec:
        data = json.dumps(rec["json"], ensure_ascii=False).encode()
        hdr["Content-Type"] = "application/json"
    elif "file" in rec:
        b = uuid.uuid4().hex
        name, content = rec["file"]
        data = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n{content}\r\n--{b}--\r\n").encode()
        hdr["Content-Type"] = f"multipart/form-data; boundary={b}"
    elif "body" in rec:
        data = rec["body"].encode()
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=hdr, method=rec["method"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--host", default="127.0.0.1", help="스텁 vhost 가 있는 웹 서버 (kt66-web)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--speed", type=float, default=0, help="0 = 기다리지 않음, 1 = 원래 속도")
    ap.add_argument("--max-gap", type=float, default=1.0)
    ap.add_argument("--src", help="이 출발지만 재생")
    ap.add_argument("--timeout", type=float, default=5)
    a = ap.parse_args()
    base = f"http://{a.host}:{a.port}"
    recs = [json.loads(x) for x in open(a.file, encoding="utf-8") if x.strip()]
    if a.src:
        recs = [r for r in recs if r["src"] == a.src]
    tally = collections.Counter()
    changed = collections.Counter()
    prev = None
    for i, r in enumerate(recs):
        if a.speed and prev is not None:
            time.sleep(min(a.max_gap, max(0.0, (r["t"] - prev) / a.speed)))
        prev = r["t"]
        got = send(base, r, a.timeout)
        want = r.get("status", 200) if r.get("status") in (401, 403, 404, 429, 500, 503) else 200
        tally[got] += 1
        if got != want:
            changed[(r["src"], got)] += 1
        if (i + 1) % 500 == 0:
            print(f"  … {i + 1:,}/{len(recs):,}", file=sys.stderr)
    print(f"재생 {len(recs):,}건 → 응답 코드 분포: " + ", ".join(f"{k}:{v}" for k, v in sorted(tally.items())))
    print("ModSec 이 응답을 바꾼 출발지 상위 (출발지, 받은 코드, 건수):")
    for (src, code), n in changed.most_common(10):
        print(f"  {src:<16} {code}  {n}")


if __name__ == "__main__":
    main()
