#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
profile_from_labeling.py — 실제 장기 집계표(labeling_YYYY-MM-DD.xlsx)에서 공격자 접근 패턴 프로파일 추출

입력: IP 별 장기 집계 시트 (열: ip, log_len, day_cnt, dip_cnt, hour_dist, dotw_cnt, nwt_ratio, hd_ratio,
      log_start, log_end, mean_tg, stdev_tg, log_type_content, methods …)
출력: 생성기(purplelab.py)가 쓰는 JSON — 접근 유형(1회성·재방문·상주)별 분위수(0,5,…,100%)

사용
  pip install openpyxl
  python3 profile_from_labeling.py labeling_2019-03-02.xlsx [다른 파일 …] -o profile_2019.json
  python3 r02_recon.py gen --profile profile_2019.json     # 생성기에 적용

같은 IP 가 여러 파일에 있으면 마지막(가장 최근 누적) 행을 쓴다. 이 스크립트는 통계만 뽑고 IP 는 내보내지 않는다.
"""
import argparse
import datetime as dt
import json
import sys


def q21(v):
    v = sorted(x for x in v if x is not None)
    if not v:
        return None
    return [round(v[min(len(v) - 1, int(p / 100 * (len(v) - 1)))], 4) for p in range(0, 101, 5)]


def to_dt(x):
    if isinstance(x, dt.datetime):
        return x
    try:
        return dt.datetime.fromisoformat(str(x))
    except ValueError:
        return None


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("-o", "--out", default="profile.json")
    a = ap.parse_args()
    try:
        import openpyxl
    except ImportError:
        sys.exit("openpyxl 필요: pip install openpyxl")
    by_ip = {}
    for fn in a.files:
        ws = openpyxl.load_workbook(fn, read_only=True).active
        it = ws.iter_rows(values_only=True)
        hdr = next(it)
        H = {h: i for i, h in enumerate(hdr) if h}
        for r in it:
            ip = r[H["ip"]]
            if ip:
                by_ip[ip] = {k: r[i] for k, i in H.items()}
    rows = list(by_ip.values())
    cls = {"oneshot": [], "returning": [], "persistent": []}
    start_h = [0] * 24
    for r in rows:
        d = num(r.get("day_cnt")) or 1
        c = "oneshot" if d <= 1 else ("returning" if d < 15 else "persistent")
        cls[c].append(r)
        s = to_dt(r.get("log_start"))
        if s:
            start_h[s.hour] += 1
    out = {"source": f"labeling 집계 {len(a.files)}개 파일 · 출발지 {len(rows):,}개", "start_hour_weights": start_h,
           "classes": {}}
    for c, rs in cls.items():
        if not rs:
            continue
        span = []
        epd = []
        for r in rs:
            s, e = to_dt(r.get("log_start")), to_dt(r.get("log_end"))
            if s and e:
                span.append((e - s).total_seconds() / 86400)
            ll, dc = num(r.get("log_len")), num(r.get("day_cnt")) or 1
            if ll:
                epd.append(ll / dc)
        out["classes"][c] = {
            "share": round(len(rs) / len(rows), 4),
            "day_cnt_q": q21(num(r.get("day_cnt")) for r in rs),
            "span_days_q": q21(span),
            "events_per_day_q": q21(epd),
            "hour_cov_q": q21(num(r.get("hour_dist")) for r in rs),
            "nwt_ratio_q": q21(num(r.get("nwt_ratio")) for r in rs),
            "hd_ratio_q": q21(num(r.get("hd_ratio")) for r in rs),
            "mean_tg_q": q21(num(r.get("mean_tg")) for r in rs),
            "stdev_tg_q": q21(num(r.get("stdev_tg")) for r in rs),
            "dip_cnt_q": q21(num(r.get("dip_cnt")) for r in rs),
        }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"[저장] {a.out} — " + ", ".join(f"{c} {len(v):,}" for c, v in cls.items()))


if __name__ == "__main__":
    main()
