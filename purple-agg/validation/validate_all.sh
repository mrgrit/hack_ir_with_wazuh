#!/bin/bash
# 번들 검증 — 로그에서 재구성한 pcap 을 Suricata 오프라인으로, HTTP 재생을 ModSecurity 스텁으로 돌려 규칙별 건수를 남긴다.
# 실제 공격·실제 망 전송 없음. 필요: suricata 7, apache2 + mod_security2 + remoteip + cgid, 스텁 vhost(rules/common).
set -u
B=$(cd "$(dirname "$0")/.." && pwd); W=${WORK:-/tmp/purple-val}; mkdir -p $W; cd $W
declare -A MOD=([r01]=r01_baseline [r02]=r02_recon [r03]=r03_webexploit [r04]=r04_persistence [r05]=r05_privesc_evasion [r06]=r06_credential [r07]=r07_lateral [r08]=r08_c2_exfil [r09]=r09_midterm [r10]=r10_impact [r12]=r12_ai_service [r13]=r13_ai_redteam [r15]=r15_final)
for r in ${ROUNDS:-r01 r02 r03 r04 r06 r07 r08 r09 r10 r12 r13 r15}; do
  m=${MOD[$r]}; R=$B/rules/$r
  if [ -f $R/suricata.rules ]; then
    python3 $B/$m.py pcap >/dev/null 2>&1
    rules=$R/suricata.rules
    [ $r = r09 ] && cat $B/rules/r03/suricata.rules $B/rules/r04/suricata.rules $R/suricata.rules > $W/r09_all.rules && rules=$W/r09_all.rules
    rm -rf $W/o$r; mkdir -p $W/o$r
    suricata -r $r.pcap -S $rules -k none -l $W/o$r --set outputs.1.eve-log.enabled=no >/dev/null 2>&1
    grep -o '\[1:[0-9]*:1\] [^[]*' $W/o$r/fast.log | sed 's/ *$//' | sort | uniq -c > $B/validation/${r}_suricata.txt
    echo "$r suricata: $(wc -l < $B/validation/${r}_suricata.txt) signatures fired"
  fi
  if [ -f $R/modsec.conf ]; then
    python3 $B/$m.py http >/dev/null 2>&1
    rm -f /etc/modsecurity/purple/*.conf
    confs=$R/modsec.conf; [ $r = r09 ] && confs="$B/rules/r03/modsec.conf $B/rules/r04/modsec.conf $R/modsec.conf"
    i=0; for c in $confs; do i=$((i+1)); cp $c /etc/modsecurity/purple/$i-$(basename $(dirname $c)).conf; done
    rm -rf /var/cache/modsecurity/*; : > /var/log/apache2/purple_test_error.log
    apache2ctl -k stop >/dev/null 2>&1; sleep 1; apache2ctl -k start >/dev/null 2>&1; sleep 1
    args=""; [ $r = r13 ] && args="--src $(python3 -c "import json,collections;print(collections.Counter(json.loads(l)['src'] for l in open('r13_http.jsonl') if 'httpx' in l).most_common(1)[0][0])") --speed 1 --max-gap 0.5"
    { python3 $B/rules/common/purple_http_replay.py ${r}_http.jsonl --host 127.0.0.1 $args 2>/dev/null | head -1
      grep -o 'id "9[0-9]\{4\}"' /var/log/apache2/purple_test_error.log | sort | uniq -c; } > $B/validation/${r}_modsec.txt
    echo "$r modsec: $(tail -n +2 $B/validation/${r}_modsec.txt | wc -l) rule ids fired"
  fi
done
