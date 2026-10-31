#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sigma_corr2wazuh.py — kt66 sigma2wazuh 확장: Sigma '상관(correlation)' 룰 → Wazuh 상관 룰

kt66 의 sigma2wazuh.py 는 단건 룰(full_log 정규식)만 변환하고 count/timeframe 상관은 지원하지 않는다.
이 도구는 sigma2wazuh 가 만든 sigma_rules.xml 에서 '기반 룰 → Wazuh id' 를 찾아,
Sigma correlation 문서(type: event_count | value_count | temporal)를 Wazuh 룰로 바꾼다.

  event_count  : group-by 같고 timespan 안에 condition 건 이상   → frequency + timeframe + same_*
  value_count  : group-by 같고 field 의 서로 다른 값이 N 개 이상  → frequency + timeframe + different_*
  temporal     : rules 가 순서대로 timespan 안에 (같은 group-by) → if_sid(뒤) + if_matched_sid(앞) + same_*

또 하나: kt66 변환기는 단건 룰을 if_sid 없는 '최상위' 룰로 만든다. Wazuh 는 최상위 룰 중 처음 맞는 것
(예: 웹 로그 31100, Suricata 86600, sshd 5700)으로 들어가 그 자식만 보므로, 뒤에 붙은 최상위 Sigma 룰은
그런 로그에서 평가되지 않는다. --fix-parents 는 logsource(group)에 맞는 부모 if_sid 를 끼워 넣어 이 문제를 고친다.

사용
  python3 sigma2wazuh.py rules/ > sigma_rules.xml                               # kt66 기존 단계
  python3 sigma_corr2wazuh.py --fix-parents sigma_rules.xml > sigma_rules.fixed.xml  # 부모 연결
  python3 sigma_corr2wazuh.py rules/ sigma_rules.fixed.xml > sigma_corr_rules.xml    # 상관 룰 추가 (id 210001+)
"""
import glob
import os
import re
import sys

import yaml

LEVEL = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 13}
SAME = {"srcip": "<same_srcip />", "src_ip": "<same_srcip />", "dstip": "<same_dstip />", "srcuser": "<same_srcuser />",
        "user": "<same_user />", "url": "<same_url />", "location": "<same_location />"}
DIFF = {"srcip": "<different_srcip />", "src_ip": "<different_srcip />", "url": "<different_url />"}


def tsec(s):
    m = re.fullmatch(r"(\d+)([smhd])", str(s).strip())
    if not m:
        raise ValueError(f"timespan 형식: {s}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


PARENTS = [  # (group 표지, 부모) — 처음 맞는 것 하나
    ("webserver,", "<if_sid>31100,31101,31103,31104,31105,31106,31108,31120</if_sid>"),
    ("apache,", "<if_sid>31100,31101,31103,31104,31105,31106,31108,31120</if_sid>"),
    ("sshd,", "<if_sid>5700,5710,5715,5716</if_sid>"),
    ("sudo,", "<if_sid>5400,5401,5402</if_sid>"),
    ("syscheck,", "<if_sid>550,553,554</if_sid>"),
    ("suricata,", "<if_sid>86600,86601</if_sid>"),
    ("windows,", "<if_group>windows</if_group>"),
]


def fix_parents(xml):
    out, buf = [], []
    for line in open(xml, encoding="utf-8"):
        if "<rule id=" in line or buf:
            buf.append(line)
            if "</rule>" in line:
                block = "".join(buf)
                buf = []
                if "<if_sid>" not in block and "<if_group>" not in block:
                    g = re.search(r"<group>([^<]*)</group>", block)
                    par = next((p for k, p in PARENTS if g and k in g.group(1)), None)
                    if par:
                        block = re.sub(r"(<rule id=\"\d+\"[^>]*>\n)", lambda m: m.group(1) + "    " + par + "\n", block, count=1)
                out.append(block)
            continue
        out.append(line)
    sys.stdout.write("".join(out))


def main():
    if sys.argv[1] == "--fix-parents":
        return fix_parents(sys.argv[2])
    src, xml = sys.argv[1], sys.argv[2]
    title2id = {}
    cur = None
    for line in open(xml, encoding="utf-8"):
        m = re.search(r"<!-- (.+?) \(sigma level=", line)
        if m:
            cur = m.group(1)
        m = re.search(r'<rule id="(\d+)"', line)
        if m and cur:
            title2id[cur] = m.group(1)
            cur = None
    ref = {}
    corr = []
    for f in sorted(glob.glob(os.path.join(src, "**", "*.yml"), recursive=True)):
        for doc in yaml.safe_load_all(open(f, encoding="utf-8")):
            if not doc:
                continue
            if "correlation" in doc:
                corr.append(doc)
            elif "detection" in doc:
                for k in (doc.get("name"), doc.get("id"), doc.get("title")):
                    if k:
                        ref[k] = title2id.get(doc.get("title"))
    print("<!-- Sigma correlation → Wazuh (sigma_corr2wazuh.py 자동생성) -->")
    print('<group name="sigma,sigma_correlation,kt66,">')
    rid = 210000
    for doc in corr:
        c = doc["correlation"]
        base = [ref.get(r) for r in c["rules"]]
        if None in base:
            sys.stderr.write(f"WARN: 기반 룰을 찾지 못함 {c['rules']} — sigma2wazuh 먼저 실행\n")
            continue
        rid += 1
        lvl = LEVEL.get(str(doc.get("level", "high")), 10)
        ts = tsec(c["timespan"])
        gb = c.get("group-by", [])
        same = "".join(SAME.get(g, f"<same_field>{g}</same_field>") for g in gb)
        cond = c.get("condition", {})
        n = int(cond.get("gte", cond.get("gt", 1)))
        t = c["type"]
        print(f"  <!-- {doc.get('title')} (sigma correlation {t}) -->")
        if t == "event_count":
            print(f'  <rule id="{rid}" level="{lvl}" frequency="{n}" timeframe="{ts}">')
            print(f"    <if_matched_sid>{base[0]}</if_matched_sid>{same}")
        elif t == "value_count":
            fld = cond["field"]
            diff = DIFF.get(fld, f"<different_field>{fld}</different_field>")
            print(f'  <rule id="{rid}" level="{lvl}" frequency="{n}" timeframe="{ts}">')
            print(f"    <if_matched_sid>{base[0]}</if_matched_sid>{same}{diff}")
        elif t == "temporal":
            print(f'  <rule id="{rid}" level="{lvl}" timeframe="{ts}">')
            print(f"    <if_sid>{base[-1]}</if_sid><if_matched_sid>{base[0]}</if_matched_sid>{same}")
        else:
            sys.stderr.write(f"WARN: 미지원 type {t}\n")
            continue
        print(f"    <description>[Sigma 상관] {doc.get('title')}</description>")
        tags = [x.split(".", 1)[1].upper() for x in doc.get("tags", []) if re.match(r"attack\.t\d", x)]
        if tags:
            print("    <mitre>" + "".join(f"<id>{x}</id>" for x in tags) + "</mitre>")
        print("    <group>sigma_correlation,</group>")
        print("  </rule>")
    print("</group>")


if __name__ == "__main__":
    main()
