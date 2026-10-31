#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
purple_log_replay.py — rNN_replay.jsonl 을 Wazuh manager 의 재생 파일로 '시간 간격을 지켜' 흘려 넣는다.

왜 간격이 필요한가: Wazuh 상관 규칙(frequency·timeframe·if_matched_sid)은 로그 안의 날짜가 아니라
manager 에 '도착한 시각'으로 센다. 3,000줄을 한 번에 붙여 넣으면 석 달이 1초에 들어가 규칙이 과하게 울린다.

  · 간격 = 원래 간격 / --speed, 단 --max-gap 초보다 길면 잘라 낸다(긴 공백 압축)
      --speed 1  --max-gap 2    : 초·분 단위 규칙(R13 기계 속도, R02 스캔) 을 실제 속도로 검증
      --speed 60 --max-gap 0.05 : 기본값. 전체를 몇 분에 재생 (일 단위 창 규칙은 압축 때문에 더 잘 울린다)
  · 쓰는 곳: <dir>/replay_syslog.log, <dir>/replay_json.log  (rules/common/wazuh_localfile.xml 이 읽는 파일)
  · manager 에서 실행 (kt66-siem 컨테이너 안이면 docker exec -it kt66-siem python3 …)

사용
  sudo python3 purple_log_replay.py r06_replay.jsonl
  sudo python3 purple_log_replay.py r13_replay.jsonl --speed 1 --max-gap 2 --from-hour 4 --to-hour 5
"""
import argparse
import json
import os
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--dir", default="/var/ossec/logs/purple")
    ap.add_argument("--speed", type=float, default=60)
    ap.add_argument("--max-gap", type=float, default=0.05)
    ap.add_argument("--from-hour", type=int, help="KST 시(0~23) 이후만")
    ap.add_argument("--to-hour", type=int, help="KST 시(0~23) 이전만")
    ap.add_argument("--dry", action="store_true", help="쓰지 않고 줄 수·예상 소요만 출력")
    a = ap.parse_args()
    recs = [json.loads(x) for x in open(a.file, encoding="utf-8") if x.strip()]
    if a.from_hour is not None or a.to_hour is not None:
        lo, hi = a.from_hour or 0, a.to_hour if a.to_hour is not None else 24
        recs = [r for r in recs if lo <= time.gmtime(r["t"] + 32400).tm_hour < hi]
    est = sum(min(a.max_gap, max(0.0, (b["t"] - p["t"]) / a.speed)) for p, b in zip(recs, recs[1:]))
    print(f"{len(recs):,}줄 · 예상 {est / 60:.1f}분 (speed {a.speed:g}, max-gap {a.max_gap:g}s)")
    if a.dry:
        return
    os.makedirs(a.dir, exist_ok=True)
    out = {k: open(os.path.join(a.dir, f"replay_{k}.log"), "a", encoding="utf-8") for k in ("syslog", "json")}
    prev = None
    for i, r in enumerate(recs):
        if prev is not None:
            time.sleep(min(a.max_gap, max(0.0, (r["t"] - prev) / a.speed)))
        prev = r["t"]
        f = out[r["f"]]
        f.write(r["line"] + "\n")
        f.flush()
        if (i + 1) % 1000 == 0:
            print(f"  … {i + 1:,}/{len(recs):,}")
    for f in out.values():
        f.close()
    print("완료 — 경보 확인: grep -c PURPLE /var/ossec/logs/alerts/alerts.log  또는 Discover 에서 rule.groups:purple")


if __name__ == "__main__":
    main()
