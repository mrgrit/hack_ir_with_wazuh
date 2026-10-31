#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_labs.py — 라운드 스크립트(QUERIES·MON) + 정답 키(answers/) + 규칙 팩(rules/) + 검증 결과(validation/)
              → labs/lab_rNN.yaml (미션 8개, 프로젝트 lab 형식) 와 lectures/lecture_rNN.md

  python3 make_labs.py            # 13개 라운드 전부
  python3 make_labs.py r02 r06    # 일부만
"""
import glob
import importlib
import json
import os
import re
import sys

import yaml

import labs_config as C
import purplelab as P

IDX = "https://10.20.32.110:9200"
CURL = "curl -sk -u admin:SecretPassword -H 'Content-Type: application/json'"
ANCHOR = "2026-11-01"
OUT_LAB, OUT_LEC = "labs", "lectures"


# ── 정답 키 읽기 ──
def read_answers(mod):
    fn = f"answers/{mod}.txt"
    if not os.path.exists(fn):
        return {}, ""
    cur, out, head = None, {}, ""
    for line in open(fn, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("총 "):
            head = line
        m = re.match(r"# (Q\d+|MON) ", line)
        if m:
            cur = m.group(1)
            out[cur] = []
            continue
        if cur and line.startswith("  "):
            out[cur].append(line.strip())
        elif cur and line.startswith("("):
            cur = None
    return out, head


def read_val(rnd, kind):
    fn = f"validation/{rnd}_{kind}.txt"
    return open(fn, encoding="utf-8").read().rstrip() if os.path.exists(fn) else ""


# ── DSL → Dashboard(Visualize) 설명·KQL ──
def kql(q):
    if not q:
        return ""
    if "term" in q:
        (f, v), = q["term"].items()
        return f'{f}:"{v}"'
    if "terms" in q:
        (f, v), = q["terms"].items()
        return f"{f}:(" + " or ".join(f'"{x}"' for x in v) + ")"
    if "prefix" in q:
        (f, v), = q["prefix"].items()
        return f"{f}:{v}*"
    if "wildcard" in q:
        (f, v), = q["wildcard"].items()
        v = v["value"] if isinstance(v, dict) else v
        return f"{f}:{v}"
    if "exists" in q:
        return f'{q["exists"]["field"]}:*'
    if "range" in q:
        (f, r), = q["range"].items()
        ops = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}
        return " and ".join(f"{f} {ops[k]} {v}" for k, v in r.items() if k in ops)
    if "bool" in q:
        b = q["bool"]
        parts = [kql(x) for x in b.get("filter", []) + b.get("must", [])]
        if b.get("should"):
            parts.append("(" + " or ".join(kql(x) for x in b["should"]) + ")")
        parts += ["not " + kql(x) for x in b.get("must_not", [])]
        return " and ".join(p for p in parts if p)
    return "(DSL 필터 — Add filter → Edit as Query DSL)"


def viz(aggs, depth=0):
    out = []
    for name, spec in aggs.items():
        kind = next(k for k in spec if k not in ("aggs",))
        s = spec[kind]
        if kind == "terms":
            o = s.get("order", {})
            od = (" · 정렬 " + ",".join(f"{k} {v}" for k, v in o.items())) if o else ""
            out.append(f"Split rows: Terms `{s['field']}` size {s.get('size', 10)}{od}")
        elif kind == "date_histogram":
            out.append(f"Split rows: Date Histogram `{s['field']}` 간격 {s.get('fixed_interval', s.get('calendar_interval'))}")
        elif kind == "filters":
            out.append("Split rows: Filters (" + " / ".join(s["filters"].keys()) + ")")
        elif kind == "cardinality":
            out.append(f"Metric: Unique Count `{s['field']}`")
        elif kind in ("min", "max", "avg", "sum"):
            out.append(f"Metric: {dict(min='Min', max='Max', avg='Average', sum='Sum')[kind]} `{s['field']}`")
        elif kind == "filter":
            out.append(f"(하위 필터: {kql(s)})")
        elif kind == "bucket_selector":
            out.append("조건 거르기(bucket_selector) — Visualize 에는 없음 → DSL·모니터로")
        elif kind == "top_hits":
            out.append("Top Hit — Discover 에서 해당 필터로 정렬")
        if "aggs" in spec:
            out += viz(spec["aggs"], depth + 1)
    return out


def block(text, n):
    pad = " " * n
    return "\n".join((pad + l) if l.strip() else "" for l in text.rstrip("\n").split("\n"))


def q_cmds(mod, rnd, q, k):
    body = json.dumps(q.body, ensure_ascii=False, separators=(",", ":"))
    jq = q.jq()
    head = f" | head -{q.head}" if q.head else ""
    return (f"# {k}) {q.id} 질의 본문(DSL)을 먼저 읽는다 — 어떤 필터·버킷·지표인가\n"
            f"python3 {mod}.py dsl {q.id}\n\n"
            f"# {k + 1}) 인덱서에 직접 질의 — jq 로 '키 | 값' 표만 뽑는다\n"
            f"{CURL} {IDX}/purple-{rnd}/_search -d @- <<'EOF' | jq -r '{jq}'{head}\n{body}\nEOF\n\n"
            f"# {k + 2}) 같은 질의를 생성기로 (표 출력, 정답 키와 같은 형식)\n"
            f"python3 {mod}.py ask {q.id}\n"), \
        f"python3 {mod}.py ask {q.id}"


def expected(ans, qid, n=10):
    rows = ans.get(qid, [])
    return "\n".join(rows[:n]) + ("\n…" if len(rows) > n else "") if rows else "(answers/ 를 먼저 생성: python3 MOD.py answers --anchor 2026-11-01)"


def first_key(ans, qid, default):
    rows = ans.get(qid) or []
    if not rows or "|" not in rows[0]:
        return default
    return rows[0].split("|")[0].strip()[:40] or default


# ── 규칙 팩 요약 (강의·카드용) ──
def pack_summary(rnd):
    d = f"rules/{rnd}"
    rows = []
    for line in open(f"{d}/suricata.rules", encoding="utf-8") if os.path.exists(f"{d}/suricata.rules") else []:
        m = re.search(r'msg:"([^"]+)".*sid:(\d+)', line)
        if m and not line.startswith("#"):
            rows.append(("Suricata", m.group(2), m.group(1)))
    if os.path.exists(f"{d}/modsec.conf"):
        for m in re.finditer(r"id:(\d+),[^\"]*?msg:'([^']+)'", open(f"{d}/modsec.conf", encoding="utf-8").read()):
            rows.append(("ModSecurity", m.group(1), m.group(2)))
    if os.path.exists(f"{d}/wazuh_rules.xml"):
        s = open(f"{d}/wazuh_rules.xml", encoding="utf-8").read()
        for m in re.finditer(r'<rule id="(\d+)" level="(\d+)"([^>]*)>([\s\S]*?)</rule>', s):
            desc = re.search(r"<description>([^<]+)", m.group(4)).group(1)
            fr = re.search(r'frequency="(\d+)" timeframe="(\d+)"', m.group(3))
            tf = re.search(r'timeframe="(\d+)"', m.group(3))
            tag = f" [빈도 {fr.group(1)}/{fr.group(2)}s]" if fr else (f" [순서 {tf.group(1)}s]" if tf else "")
            rows.append(("Wazuh", f"{m.group(1)} (L{m.group(2)})", desc + tag))
    for f in sorted(glob.glob(f"{d}/sigma/*.yml")):
        for doc in yaml.safe_load_all(open(f, encoding="utf-8")):
            if doc:
                rows.append(("Sigma", "상관" if "correlation" in doc else "단건", doc["title"]))
    if os.path.exists(f"{d}/osquery.conf"):
        for k, v in json.load(open(f"{d}/osquery.conf", encoding="utf-8"))["queries"].items():
            rows.append(("osquery", k, v.get("description", "")))
    if os.path.exists(f"{d}/sysmon.xml"):
        for m in re.finditer(r'<(ProcessCreate|NetworkConnect|DnsQuery|FileCreate) onmatch', open(f"{d}/sysmon.xml", encoding="utf-8").read()):
            rows.append(("Sysmon", m.group(1), "rules/%s/sysmon.xml" % rnd))
    return rows


def ar_ids(rnd):
    f = f"rules/{rnd}/wazuh_ar.xml"
    if not os.path.exists(f):
        return []
    return sorted({x for m in re.findall(r"<rules_id>([^<]+)", open(f).read()) for x in m.split(",")})


# ── 미션 ──
def mission(order, title, concept, where, cmds, notes, expect, hint, cat, pts, answer, detail, out, intent, crit, tvm):
    ins = (f"## 🎯 목표 — {title}\n## 📖 개념 한 줄\n{concept}\n## 💻 실행 명령 (한 줄씩 따라 실행)\n\n"
           f"**실습 위치:** {where}\n\n```bash\n{cmds.rstrip()}\n```\n{notes}\n\n"
           f"## ✅ 합격 기준\n`{expect}` 출력 시 통과.")
    return (f"  - order: {order}\n    instruction: |2\n{block(ins, 6)}\n"
            f"    hint: {json.dumps(hint, ensure_ascii=False)}\n    category: {cat}\n    points: {pts}\n"
            f"    answer: |2\n{block(answer, 6)}\n"
            f"    answer_detail: {json.dumps(detail, ensure_ascii=False)}\n"
            f"    expected_output: |2\n{block(out, 6)}\n"
            f"    verify:\n      type: output_contains\n      expect: {json.dumps(expect, ensure_ascii=False)}\n      field: stdout\n"
            f"      semantic:\n        intent: {json.dumps(intent, ensure_ascii=False)}\n"
            f"        success_criteria: {json.dumps(crit, ensure_ascii=False)}\n"
            f"        acceptable_methods: [\"**[OSS] OpenSearch 집계 DSL + Dashboard (권장)**\"]\n"
            f"    target_vm: {tvm}\n")


HOST = "`kt66 호스트` — `ssh ccc@{{TARGET_IP}}` 접속 후 `cd ~/purple-agg` (생성기·인덱서 https://10.20.32.110:9200)"


def build(rnd):
    cfg = C.R[rnd]
    mod = cfg["mod"]
    M = importlib.import_module(mod)
    ans, head = read_answers(mod)
    qs = list(M.QUERIES)
    NN = rnd[1:]
    ms = []
    # 1) 생성·적재 + Q0 + Q1
    q1 = qs[0]
    c1, a1 = q_cmds(mod, rnd, q1, 6)
    cmds = (f"# 1) 인덱서 연결 확인 — 클러스터 이름·버전, 이미 있는 purple-* 인덱스\npython3 {mod}.py check\n\n"
            f"# 2) 로그 생성·적재 — 90일, 엔드포인트 10곳 정상 99.9% + 공격 (실제 공격 없음, 수 분)\n"
            f"python3 {mod}.py gen --anchor {ANCHOR}\n\n"
            f"# 3) 적재 건수 확인 — 총 이벤트 수 | 서로 다른 외부 IP 수 (Q0)\npython3 {mod}.py ask Q0\n\n"
            f"# 4) Dashboard: Stack Management → Index Patterns → purple-* (시간 필드 timestamp) — 있으면 건너뜀\n"
            f"# 5) Discover 에서 purple-{rnd} · 기간 2026-08-01 ~ 2026-11-01 로 맞춘다\n\n" + c1)
    ms.append(mission(
        1, f"데이터 적재와 정상의 모양 — {q1.title}",
        "정상의 크기를 먼저 잰다. " + cfg["concept"].get(q1.id, ""), HOST, cmds,
        f"- 2) 기준일 `{ANCHOR}` 로 고정해야 정답 키와 숫자가 같다(다른 날짜면 분포는 같고 시각만 밀린다).\n"
        f"- 시각화: " + " → ".join(viz(q1.body.get("aggs", {}))) + (f" · 필터 `{kql(q1.body.get('query'))}`" if q1.body.get("query") else ""),
        first_key(ans, q1.id, "|"), f"gen → ask Q0 → {q1.id}", "survey", 10,
        f"# 1) 생성·적재 (기준일 고정)\npython3 {mod}.py gen --anchor {ANCHOR} >/dev/null && python3 {mod}.py ask Q0\n# 2) 정상의 모양\n{a1}",
        f"{head} — 정상이 99.9% 인 데이터에서 '정상의 모양'을 먼저 기록한다. {cfg['concept'].get(q1.id, '')}",
        "# Q0\n" + expected(ans, "Q0") + f"\n# {q1.id}\n" + expected(ans, q1.id),
        "적재 + 정상 기준선", ["인덱스 purple-" + rnd, "Q0 건수", q1.id + " 분포"], "host"))
    # 2~4) 탐지 집계
    rest = qs[1:]
    n = len(rest)
    sizes = [n // 3 + (1 if i < n % 3 else 0) for i in range(3)]
    i0 = 0
    for k, sz in enumerate(sizes):
        grp = rest[i0:i0 + sz]
        i0 += sz
        if not grp:
            continue
        cmds, answers, outs, notes, conc = "", [], [], [], []
        step = 1
        for q in grp:
            c, a = q_cmds(mod, rnd, q, step)
            step += 3
            cmds += f"# ── {q.id} {q.title} ──\n" + c + "\n"
            answers.append(f"# {q.id} {q.title}\n{a}")
            outs.append(f"# {q.id}\n" + expected(ans, q.id))
            conc.append(f"**{q.id}** {cfg['concept'].get(q.id, '')}")
            notes.append(f"- {q.id} 시각화: " + " → ".join(viz(q.body.get("aggs", {})))
                         + (f" · 필터 `{kql(q.body.get('query'))}`" if q.body.get("query") else ""))
        last = next((q for q in reversed(grp) if ans.get(q.id)), grp[-1])
        ms.append(mission(
            k + 2, " · ".join(q.title.split(" — ")[0] for q in grp), "\n".join(conc), HOST, cmds,
            "\n".join(notes), first_key(ans, last.id, "|"), " / ".join(q.id for q in grp), "analysis", 13,
            "\n".join(answers), " ".join(f"{q.id}: {cfg['concept'].get(q.id, '')}" for q in grp), "\n".join(outs),
            "탐지 집계", [q.id for q in grp], "host"))
    # 5) 모니터
    mon = M.MON
    mb = json.dumps(P.monitor_body(rnd, mon), ensure_ascii=False, separators=(",", ":"))
    cmds = (f"# 1) 모니터가 쓸 집계(+bucket_selector 조건)를 읽는다\npython3 {mod}.py dsl MON\n\n"
            f"# 2) 같은 집계를 지금 데이터에 — 조건을 넘는 버킷만 남는다\npython3 {mod}.py ask MON\n\n"
            f"# 3) Alerting 모니터 드라이런(_execute) — 등록하지 않고 트리거 판정만\n"
            f"{CURL} {IDX}/_plugins/_alerting/monitors/_execute -d @- <<'EOF' | jq '.trigger_results | to_entries[] | {{name: .value.name, triggered: .value.triggered}}'\n{mb}\nEOF\n\n"
            f"# 4) 등록(비활성) — Dashboard → Alerting → Monitors 에서 보고, 10분 주기로 켜 본다\n"
            f"{CURL} -X POST {IDX}/_plugins/_alerting/monitors -d @- <<'EOF' | jq -r '._id'\n{json.dumps(P.monitor_body(rnd, mon)['monitor'], ensure_ascii=False, separators=(',', ':'))}\nEOF\n")
    ms.append(mission(
        5, f"지속 탐지 — 모니터: {mon.title}",
        "한 번 찾은 집계는 모니터로 만든다. bucket_selector 로 '조건을 넘는 버킷'만 남기고, 버킷이 하나라도 있으면 트리거한다. "
        "Wazuh 상관 규칙은 분·시간 창의 기억이지만 모니터는 인덱스 전체(최대 1년)를 다시 센다 — 긴 창은 모니터의 몫이다.",
        HOST, cmds, f"- 트리거 조건: `{mon.trigger}`\n- 4) 실제 운영에서는 질의에 `range timestamp gte now-1h` 를 더해 최근 구간만 본다(실습 데이터는 과거라 생략).",
        "triggered", "dsl MON → ask MON → _execute", "detection", 12,
        f"python3 {mod}.py ask MON\n{CURL} {IDX}/_plugins/_alerting/monitors/_execute -d '{mb}' | jq -c '.trigger_results | to_entries[] | {{name: .value.name, triggered: .value.triggered}}'",
        f"모니터 = 집계 + 조건 + 주기. {mon.title}. 결과 버킷이 정답 키와 같으면 트리거 true.",
        "# MON\n" + expected(ans, "MON") + f'\n{{"name":"{mon.title[:60]}","triggered":true}}',
        "Alerting 모니터", ["bucket_selector", "triggered true"], "host"))
    # 6) 시그니처·호스트 규칙
    d = f"rules/{rnd}"
    cmds, notes, outs, answers = "", [], [], []
    k = 1
    if os.path.exists(f"{d}/suricata.rules"):
        cmds += (f"# ── Suricata (kt66-ips) — 로그를 패킷으로 재구성해 오프라인 검사, 망에는 보내지 않는다 ──\n"
                 f"# {k}) 규칙 읽기 — msg·threshold·sid 96{NN}0xx\ncat rules/{rnd}/suricata.rules\n\n"
                 f"# {k + 1}) pcap 재구성 (공격 + 같은 시간대 정상 표본)\npython3 {mod}.py pcap\n\n"
                 f"# {k + 2}) ips 컨테이너로 복사\ndocker cp {rnd}.pcap kt66-ips:/tmp/{rnd}.pcap\ndocker cp rules/{rnd}/suricata.rules kt66-ips:/tmp/{rnd}.rules\n\n"
                 f"# {k + 3}) 오프라인 검사 — -S 로 이 규칙만 (운영 룰셋과 섞지 않음)\ndocker exec kt66-ips mkdir -p /tmp/{rnd}-out\n"
                 f"docker exec kt66-ips suricata -r /tmp/{rnd}.pcap -S /tmp/{rnd}.rules -k none -l /tmp/{rnd}-out\n\n"
                 f"# {k + 4}) 규칙별 경보 수\ndocker exec kt66-ips sh -c \"grep -o '\\[1:[0-9]*:1\\] [^[]*' /tmp/{rnd}-out/fast.log | sort | uniq -c\"\n\n")
        k += 5
        answers.append(f"python3 {mod}.py pcap >/dev/null && docker cp {rnd}.pcap kt66-ips:/tmp/ && docker cp rules/{rnd}/suricata.rules kt66-ips:/tmp/{rnd}.rules && docker exec kt66-ips sh -c 'mkdir -p /tmp/{rnd}-out; suricata -r /tmp/{rnd}.pcap -S /tmp/{rnd}.rules -k none -l /tmp/{rnd}-out >/dev/null 2>&1; grep -o \"\\[1:[0-9]*:1\\] [^[]*\" /tmp/{rnd}-out/fast.log | sort | uniq -c'")
        outs.append(read_val(rnd, "suricata") or "(validation/ 없음)")
        notes.append("- Suricata: threshold 는 '서명 한 줄'의 집계다. 분산·장기 패턴은 서명으로 안 잡히는 것이 정상 — 미션 2~5 의 집계와 비교한다.")
    if os.path.exists(f"{d}/modsec.conf"):
        cmds += (f"# ── ModSecurity (kt66-web) — 스텁 vhost purple-test.kt66.lab 에서만, 응답은 항상 \"ok\" ──\n"
                 f"# {k}) 스텁 vhost 설치(최초 1회: R02 에서 했으면 건너뜀) — README §3\n"
                 f"# {k + 1}) 규칙 읽기 — id 9{NN}xx, phase·카운터(고정 창)\ncat rules/{rnd}/modsec.conf\n\n"
                 f"# {k + 2}) 규칙 올리기 + 문법 검사 + 무중단 재적용\ndocker cp rules/{rnd}/modsec.conf kt66-web:/etc/modsecurity/purple/{rnd}.conf\n"
                 f"docker exec kt66-web apache2ctl -t\ndocker exec kt66-web apache2ctl -k graceful\n\n"
                 f"# {k + 3}) HTTP 재생 파일 만들기 (원래 출발지·상태코드·무해한 본문)\npython3 {mod}.py http\n\n"
                 f"# {k + 4}) 스텁으로 재생 — X-Purple-Client 가 REMOTE_ADDR 로 바뀌어 IP 별 카운터가 실제처럼 돈다\n"
                 f"python3 rules/common/purple_http_replay.py {rnd}_http.jsonl --host 10.20.32.80\n\n"
                 f"# {k + 5}) 룰 id 별 차단 수\ndocker exec kt66-web sh -c \"grep -o 'id \\\"9[0-9]\\{{4\\}}\\\"' /var/log/apache2/purple_test_error.log | sort | uniq -c\"\n\n")
        k += 6
        answers.append(f"docker cp rules/{rnd}/modsec.conf kt66-web:/etc/modsecurity/purple/{rnd}.conf && docker exec kt66-web apache2ctl -k graceful && python3 {mod}.py http >/dev/null && python3 rules/common/purple_http_replay.py {rnd}_http.jsonl --host 10.20.32.80 && docker exec kt66-web sh -c 'grep -o \"id \\\"9[0-9]*\\\"\" /var/log/apache2/purple_test_error.log | sort | uniq -c'")
        outs.append(read_val(rnd, "modsec") or "(validation/ 없음)")
        notes.append("- ModSecurity: 재생은 석 달을 몇 초로 압축한다 → 하루·주 단위 카운터는 부풀려진다. 임계값은 집계(미션 2~4)의 분포로 정한다.")
    osq = f"{d}/osquery.conf"
    if os.path.exists(osq):
        qd = json.load(open(osq, encoding="utf-8"))["queries"]
        name, qq = next(iter(qd.items()))
        cmds += (f"# ── osquery (호스트) — 예약 쿼리 팩. 실제 공격이 없으니 결과 [] 가 정상 ──\n"
                 f"# {k}) 쿼리 팩 읽기\ncat rules/{rnd}/osquery.conf\n\n"
                 f"# {k + 1}) 대표 쿼리를 즉석 실행 (kt66-web) — {qq['description']}\n"
                 f"docker exec kt66-web osqueryi --json \"{qq['query']}\"\n\n")
        k += 2
        if not answers:
            answers.append(f"docker exec kt66-web osqueryi --json \"{qq['query']}\"")
        notes.append(f"- osquery: 운영 배포는 `/etc/osquery/osquery.conf` 의 packs 에 추가 → 결과는 osquery 결과 로그 → Wazuh(osquery 모듈)로 들어온다.")
    if os.path.exists(f"{d}/sysmon.xml"):
        notes.append(f"- Sysmon: `rules/{rnd}/sysmon.xml` 의 RuleGroup 을 Sysmon 설정(Windows `sysmon64 -c`, Linux `sysmon -c`)에 합친다 — kt66 에 Sysmon 이 없으면 추가 설치 제안(README §6).")
    if cfg.get("m6_note"):
        notes.append("- 검증 해석: " + cfg["m6_note"])
    if not cmds:
        cmds = "# 이 라운드는 시그니처 규칙 없음"
    ms.append(mission(
        6, "시그니처·호스트 규칙 — 네트워크·웹·호스트 층에서 같은 것을 잡을 수 있나",
        "집계로 찾은 것을 각 센서의 규칙으로 옮긴다. 서명은 '한 줄·한 요청'에 강하고 분산·장기 패턴에 약하다. "
        "검증은 실제 공격이 아니라 로그에서 재구성한 pcap·HTTP 재생·무해한 표식으로 한다.",
        "`kt66 호스트` (`cd ~/purple-agg`) — `docker cp`/`docker exec` 로 kt66-ips·kt66-web 에 적용",
        cmds, "\n".join(notes), "PURPLE " + rnd.upper() if os.path.exists(f"{d}/suricata.rules") else "[]",
        "pcap → suricata -r / http 재생 → ModSec 로그", "detection", 12,
        "\n".join(answers) or f"cat rules/{rnd}/osquery.conf", "규칙별 경보 수가 아래와 같으면 통과. 0 인 규칙은 이유(표본에 없음·body 없음·창 크기)를 적는다.",
        "\n".join(outs) or "[]", "시그니처 규칙 검증", ["Suricata 오프라인", "ModSec 스텁", "osquery 즉석"], "host"))
    # 7) Wazuh 상관 + Sigma
    wz = [r for r in pack_summary(rnd) if r[0] == "Wazuh"]
    rid_pat = f"19{NN}"
    deps = {"r09": "r03 r04 r05 r07 r08 ", "r15": "r02 r08 r12 r13 "}.get(rnd, "")
    cp_rules = "".join(f"docker cp rules/{x}/wazuh_rules.xml kt66-siem:/var/ossec/etc/rules/purple_{x}.xml\n" for x in (deps + rnd).split())
    lists = ("docker exec kt66-siem mkdir -p /var/ossec/etc/lists\n"
             "docker cp rules/r15/lists/purple-allow-scanner kt66-siem:/var/ossec/etc/lists/purple-allow-scanner\n"
             "docker cp rules/r15/lists/purple-allow-backup kt66-siem:/var/ossec/etc/lists/purple-allow-backup\n"
             "# ossec.conf <ruleset> 에 <list>etc/lists/purple-allow-scanner</list> 한 줄 추가 (README §4)\n") if rnd == "r15" else ""
    cmds = (f"# 1) 규칙 읽기 — 단건(level 3~6) 위에 빈도(frequency·timeframe)·순서(if_matched_sid) 상관\ncat rules/{rnd}/wazuh_rules.xml\n\n"
            f"# 2) 공통 디코더·재생 입력(최초 1회: R01 에서 했으면 건너뜀) — README §4\n"
            f"# 3) 규칙 올리기{' (앞 라운드 규칙 포함)' if deps else ''}\n{cp_rules}{lists}\n"
            f"# 4) 문법 검사 — 오류가 없어야 재시작한다\ndocker exec kt66-siem /var/ossec/bin/wazuh-analysisd -t\n\n"
            f"# 5) 재시작\ndocker exec kt66-siem /var/ossec/bin/wazuh-control restart\n\n"
            f"# 6) 재생 파일 만들기 (공격 + 같은 시간대 정상 표본, 원래 시각 포함)\npython3 {mod}.py replay\n\n"
            f"# 7) manager 로 복사 → 시간 간격을 지켜 흘려 넣기 (상관 규칙은 '도착 시각'으로 센다)\n"
            f"docker cp {rnd}_replay.jsonl kt66-siem:/tmp/\ndocker cp rules/common/purple_log_replay.py kt66-siem:/tmp/\n"
            f"docker exec kt66-siem /var/ossec/framework/python/bin/python3 /tmp/purple_log_replay.py /tmp/{rnd}_replay.jsonl --dry\n"
            f"docker exec kt66-siem /var/ossec/framework/python/bin/python3 /tmp/purple_log_replay.py /tmp/{rnd}_replay.jsonl\n\n"
            f"# 8) 규칙별 경보 수 — 단건과 상관 규칙이 각각 몇 번 울렸나\n"
            f"docker exec kt66-siem sh -c \"grep -oE 'Rule: {rid_pat}[0-9]+ \\(level [0-9]+\\)' /var/ossec/logs/alerts/alerts.log | sort | uniq -c\"\n\n"
            f"# 9) Sigma — kt66 변환기(단건) → 부모 연결(--fix-parents) → 상관 변환\n"
            f"cp rules/{rnd}/sigma/*.yml ~/kt66/sigma/rules/\n"
            f"python3 ~/kt66/sigma/sigma2wazuh.py ~/kt66/sigma/rules > /tmp/sigma_rules.xml\n"
            f"python3 sigma_corr2wazuh.py --fix-parents /tmp/sigma_rules.xml > /tmp/sigma_rules.fixed.xml\n"
            f"python3 sigma_corr2wazuh.py ~/kt66/sigma/rules /tmp/sigma_rules.fixed.xml > /tmp/sigma_corr_rules.xml\n"
            f"grep -c '<rule ' /tmp/sigma_rules.fixed.xml /tmp/sigma_corr_rules.xml\n"
            f"docker cp /tmp/sigma_rules.fixed.xml kt66-siem:/var/ossec/etc/rules/sigma_rules.xml\n"
            f"docker cp /tmp/sigma_corr_rules.xml kt66-siem:/var/ossec/etc/rules/sigma_corr_rules.xml\n")
    exp_lines = "\n".join(f"      N Rule: {r[1].split()[0]} (level {r[1].split('L')[1].rstrip(')')})" for r in wz if not r[1].endswith("(L0)"))
    ms.append(mission(
        7, "Wazuh 복합 이벤트 — 빈도·순서 상관과 Sigma",
        "단건 경보(낮은 레벨)를 쌓아 빈도 규칙(같은 IP·같은 계정·서로 다른 IP)과 순서 규칙(A 뒤 B, 같은 출발지)으로 올린다. "
        "Wazuh 의 창은 분·시간·일 — 그보다 긴 체인은 미션 5 의 모니터가 맡는다. Sigma 로 같은 규칙을 도구 중립으로 남긴다.",
        "`kt66 호스트` (`cd ~/purple-agg`) — `docker exec kt66-siem`", cmds,
        "- 8) N 은 재생 속도·표본에 따라 달라진다 — 단건 규칙이 먼저 울리고, 그 위에 상관 규칙이 '몇 번' 울렸는지를 적는다.\n"
        "- 순서 규칙이 0 이면 `wazuh-logtest` 에 재생 파일의 해당 줄을 붙여 넣어 어느 규칙이 먼저 잡는지(31106·31151 등) 확인하고 if_sid 를 고친다.\n"
        "- Sigma: kt66 변환기는 단건을 최상위 규칙으로 만든다 → 웹·sshd·Suricata 로그에서는 평가되지 않으므로 `--fix-parents` 로 부모를 연결한다.",
        f"Rule: {rid_pat}", "rules → analysisd -t → restart → replay → alerts.log", "detection", 15,
        f"{cp_rules.strip()} && docker exec kt66-siem /var/ossec/bin/wazuh-control restart >/dev/null && python3 {mod}.py replay >/dev/null && docker cp {rnd}_replay.jsonl kt66-siem:/tmp/ && docker cp rules/common/purple_log_replay.py kt66-siem:/tmp/ && docker exec kt66-siem /var/ossec/framework/python/bin/python3 /tmp/purple_log_replay.py /tmp/{rnd}_replay.jsonl >/dev/null && docker exec kt66-siem sh -c \"grep -oE 'Rule: {rid_pat}[0-9]+ \\(level [0-9]+\\)' /var/ossec/logs/alerts/alerts.log | sort | uniq -c\"",
        "Wazuh 규칙: " + "; ".join(f"{r[1]} {r[2]}" for r in wz),
        "(형식 — N 은 실행마다 다름)\n" + "\n".join(l.strip() for l in exp_lines.split("\n")),
        "Wazuh 상관 규칙 검증", [r[1].split()[0] for r in wz], "siem"))
    # 8) 대응 + 카드
    ids = ar_ids(rnd)
    blk = cfg.get("block")
    ipb = M.S0.ips.get(blk) if blk and hasattr(M, "S0") and hasattr(M.S0, "ips") else None
    if rnd == "r01" and hasattr(M, "C2"):
        ipb = M.C2.get("ip") or M._c2()
    card_rows = []
    for q in qs:
        r = ans.get(q.id, [])
        if r:
            card_rows.append(f"- {q.id} {q.title.split(' — ')[0]}: {r[0]}")
    card = (f"# PURPLE-AGG {rnd.upper()} 라운드 카드 — {M.TITLE}\n## 1. 질문: {cfg['goal']}\n## 2. 데이터: {head}\n## 3. 집계 결과(첫 줄)\n"
            + "\n".join(card_rows[:8]) + f"\n## 4. 규칙: Suricata 96{NN}0xx · ModSec 9{NN}xx · Wazuh 19{NN}0x · Sigma purple-{rnd}-*\n"
            f"## 5. 대응: {cfg['response']}\n## 6. 놓친 것·다음 라운드: (직접 적는다)\n")
    nft = (f"# 4) (선택) 수동 차단 — kt66-fw 의 egress 블록리스트에 목적지 추가 (가상 IP 라 실제 영향 없음)\n"
           f"docker exec kt66-fw nft add table inet purple\n"
           f"docker exec kt66-fw nft add set inet purple block4 '{{ type ipv4_addr; flags timeout; }}'\n"
           f"docker exec kt66-fw nft add element inet purple block4 '{{ {ipb} timeout 1d }}'\n"
           f"docker exec kt66-fw nft list set inet purple block4\n\n") if ipb else ""
    cmds = (f"# 1) 이 라운드의 액티브 리스폰스 — 어떤 규칙에 무엇을 거나\ncat rules/{rnd}/wazuh_ar.xml\n\n"
            f"# 2) ossec.conf 에 추가 (purple-ar 명령·스크립트는 최초 1회 — README §4)\n"
            f"docker cp rules/{rnd}/wazuh_ar.xml kt66-siem:/tmp/{rnd}_ar.xml\n"
            f"docker exec kt66-siem sh -c \"{{ echo '<ossec_config>'; cat /tmp/{rnd}_ar.xml; echo '</ossec_config>'; }} >> /var/ossec/etc/ossec.conf\"\n"
            f"docker exec kt66-siem /var/ossec/bin/wazuh-control restart\n\n"
            f"# 3) 재생을 한 번 더 → 대응 기록 확인 (purple-ar 은 '무엇을 했어야 하는지'만 적는다)\n"
            f"docker exec kt66-siem /var/ossec/framework/python/bin/python3 /tmp/purple_log_replay.py /tmp/{rnd}_replay.jsonl\n"
            f"docker exec kt66-siem tail -5 /var/ossec/logs/purple-ar.log\n\n" + nft +
            f"# 5) 라운드 카드 — 집계 숫자는 미션 1~5 의 출력에서 옮긴다\ncat > ~/purple-agg/{rnd}_card.md <<'EOF'\n{card}EOF\n\n"
            f"# 6) 카드 확인\ncat ~/purple-agg/{rnd}_card.md\n")
    ms.append(mission(
        8, "대응과 라운드 카드",
        cfg["response"], "`kt66 호스트` (`cd ~/purple-agg`)", cmds,
        f"- 대응 대상 규칙: {', '.join(ids) or '-'}\n- 재생 IP 는 가상(198.51.100.x·무작위 공인 대역)이다 — 위협 인텔로 공유하지 않는다.\n"
        f"- Dashboard: 미션 2~5 의 시각화를 하나의 Dashboard 로 묶어 스크린샷을 카드에 붙인다. ![스크린샷: {rnd} 대시보드](images/{rnd}-dashboard.png)",
        "라운드 카드", "wazuh_ar.xml → purple-ar.log → 카드", "report", 12,
        f"docker exec kt66-siem tail -3 /var/ossec/logs/purple-ar.log\ncat > ~/purple-agg/{rnd}_card.md <<'EOF'\n{card}EOF\ncat ~/purple-agg/{rnd}_card.md",
        "대응은 규칙→행동의 연결이다. 자동은 기록·알림까지, 계정·호스트 조치는 사람이 확인 후. 카드는 다음 라운드의 입력.",
        f"2026-11-01 10:21:07 purple-ar add rule={ids[0] if ids else '-'} srcip=… action=quarantine-candidate\n" + card,
        "대응 + 라운드 카드", ["AR 연결", "카드 작성"], "host"))
    desc = (M.__doc__ or "").strip()
    y = (f"lab_id: purple-agg-{rnd}\ntitle: {json.dumps('퍼플 집계 ' + rnd.upper() + ' — ' + M.TITLE, ensure_ascii=False)}\n"
         f"version: purple-agg-1\ncourse: purple-agg\nweek: {cfg['week']}\n"
         f"description: |\n{block(desc + chr(10) + chr(10) + '실제 공격은 하지 않는다. 생성기가 만든 로그(정상 99.9% + 공격)를 인덱서에 적재해 집계로 찾고, 같은 판단을 Suricata·ModSecurity·Wazuh·Sigma·osquery 규칙과 모니터로 자동화한 뒤 대응한다. 명령은 한 줄씩 — answer 의 연결 명령은 자동 채점용.', 2)}\n"
         f"difficulty: medium\nduration_minutes: 180\nprerequisites:\n"
         f"  - \"kt66 설치·기동 + Wazuh 인덱서 https://10.20.32.110:9200 접근 (admin)\"\n"
         f"  - \"~/purple-agg 번들 배치 (README §1~4 최초 설정)\"\n  - \"jq, python3\"\n"
         f"objectives:\n" + "".join(f"  - {json.dumps(o, ensure_ascii=False)}\n" for o in cfg["objectives"]) +
         "pass_threshold: 0.7\nsteps:\n\n" + "\n".join(ms))
    yaml.safe_load(y)  # 형식 검증
    os.makedirs(OUT_LAB, exist_ok=True)
    open(f"{OUT_LAB}/lab_{rnd}.yaml", "w", encoding="utf-8").write(y)
    # ── 강의 ──
    pk = pack_summary(rnd)
    L = [f"# 퍼플 집계 {rnd.upper()} — {M.TITLE}", "",
         "> 실제 공격 없음 — 생성기가 만든 로그만 적재한다. 외부 IP 는 무작위(가상)이며 위협 인텔로 쓰지 않는다.", "",
         "## 1. 이 라운드의 질문", "", cfg["goal"], "", "## 2. 시나리오 (로그로만 재현)", "", "```", desc, "```", "",
         "## 3. 데이터", "", f"- {head or '총 건수: answers/ 생성 후 채워짐'}",
         "- 기간: 기본 90일(`--days` 7~365). 공격자 접근 시각·재방문 간격은 실제 장기 집계(labeling) 프로파일을 따른다.",
         "- 엔드포인트(가상 IP): " + ", ".join(f"{v[0]}={v[1]}" for v in P.WEB_EP.values()) + ", bastion 10.20.30.201, KT66-WIN-01 10.20.70.10", "",
         "## 4. 집계 문항", "", "| 문항 | 질문 | 왜 | Visualize |", "|---|---|---|---|"]
    for q in qs:
        L.append(f"| {q.id} | {q.title} | {cfg['concept'].get(q.id, '')} | {' → '.join(viz(q.body.get('aggs', {})))} |")
    L += ["", f"**모니터:** {M.MON.title} — 트리거 `{M.MON.trigger}`", "",
          f"![스크린샷: {rnd} 핵심 집계 시각화](images/{rnd}-viz.png)", "",
          "## 5. 규칙 팩 (`rules/" + rnd + "/`)", "", "| 도구 | ID | 내용 |", "|---|---|---|"]
    L += [f"| {a} | {b} | {c.replace('|', '/')} |" for a, b, c in pk]
    L += ["", "검증: Suricata 는 로그→pcap 재구성 오프라인(`-r`), ModSecurity 는 스텁 vhost 재생, Wazuh 는 manager 재생 파일(도착 시각 기준).", "",
          "## 6. 대응", "", cfg["response"], "", f"![스크린샷: {rnd} 대응 기록](images/{rnd}-response.png)", "",
          "## 7. 생각해 볼 것", "",
          "- 서명(한 줄)·상관(분~일)·집계(전체 기간) 중 이 라운드의 공격을 처음 드러낸 것은 무엇인가?",
          "- 정상 99.9% 안에서 임계값을 어디에 두면 오탐이 0 이 되는가? (미션 2~4 의 분포로 근거를 댄다)",
          "- 공격자가 기간을 두 배로 늘리면(--days 180) 어떤 집계가 약해지고 어떤 집계가 강해지는가?", ""]
    os.makedirs(OUT_LEC, exist_ok=True)
    open(f"{OUT_LEC}/lecture_{rnd}.md", "w", encoding="utf-8").write("\n".join(L))
    return len(ms)


if __name__ == "__main__":
    todo = sys.argv[1:] or list(C.R)
    for r in todo:
        print(r, build(r), "missions")
