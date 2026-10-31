#!/bin/bash
# kt66-setup.sh — 퍼플 집계 트랙 사전작업을 한 번에 설치/원상복구한다.
#   up        README §3·§4 (ModSecurity 스텁 vhost + Wazuh 디코더·룰·localfile·AR·CDB) + 인덱스 패턴
#   down      위 전부를 되돌린다 (ossec.conf 는 마커 블록만 제거 — 나머지 설정은 건드리지 않음)
#   status    무엇이 적용돼 있는지 표시
# 멱등(up 을 여러 번 해도 안전). 실제 공격·실제 차단 없음. 생성기 로그 적재는 rNN_*.py gen 으로 따로.
# 필요: kt66 가 떠 있어야 함(kt66-web, kt66-siem). docker 는 sudo 가 필요하면 자동으로 붙인다.
set -u
B="$(cd "$(dirname "$0")" && pwd)"
WEB=kt66-web; SIEM=kt66-siem
DASH="${DASH:-https://192.168.0.189:5601}"; DUSER="${DUSER:-admin}"; DPASS="${DPASS:-SecretPassword}"
ROUNDS="r01 r02 r03 r04 r05 r06 r07 r08 r09 r10 r12 r13 r15"
BEGIN="<!-- PURPLE-AGG BEGIN (kt66-setup.sh) -->"
END="<!-- PURPLE-AGG END -->"

D() { if docker ps >/dev/null 2>&1; then docker "$@"; else sudo docker "$@"; fi; }
say() { echo "[purple-setup] $*"; }

ossec_strip() {   # ossec.conf 에서 마커 블록(여러 개라도) 제거 — 호스트에서 문자열 검색으로 안전하게
  local t; t=$(mktemp)
  D cp "$SIEM:/var/ossec/etc/ossec.conf" "$t" >/dev/null 2>&1 || { rm -f "$t"; return 0; }
  BEGIN="$BEGIN" END="$END" python3 - "$t" <<'PY'
import os, sys
p = sys.argv[1]; s = open(p).read()
B = os.environ["BEGIN"]; E = os.environ["END"]
while B in s and E in s[s.index(B):]:
    i = s.index(B); j = s.index(E, i) + len(E)
    s = s[:i].rstrip("\n") + "\n" + s[j:].lstrip("\n")
open(p, "w").write(s)
PY
  D cp "$t" "$SIEM:/var/ossec/etc/ossec.conf" >/dev/null 2>&1
  D exec "$SIEM" sh -c 'chown root:wazuh /var/ossec/etc/ossec.conf; chmod 660 /var/ossec/etc/ossec.conf'  # cp 는 root:root 로 덮으므로 원래 소유권 복원
  rm -f "$t"
}

web_up() {
  say "ModSecurity 스텁 vhost (kt66-web)"
  D exec "$WEB" a2enmod -q security2 remoteip cgid >/dev/null 2>&1 || true
  D exec "$WEB" mkdir -p /var/www/purple-test /etc/modsecurity/purple
  D cp "$B/rules/common/stub.cgi" "$WEB:/var/www/purple-test/stub.cgi"
  D exec "$WEB" chmod +x /var/www/purple-test/stub.cgi
  # kt66-web 는 sites-available 이 읽기전용 마운트 → 쓰기 가능하고 Apache 가 포함하는 conf-enabled 에 둔다
  D cp "$B/rules/common/purple-test-vhost.conf" "$WEB:/etc/apache2/conf-enabled/purple-test.conf"
  # 라운드별 ModSecurity 룰 (번호 접두사로)
  D exec "$WEB" sh -c 'rm -f /etc/modsecurity/purple/*.conf'
  i=0; for r in $ROUNDS; do
    [ -f "$B/rules/$r/modsec.conf" ] || continue
    i=$((i+1)); D cp "$B/rules/$r/modsec.conf" "$WEB:/etc/modsecurity/purple/$(printf %02d $i)-$r.conf"
  done
  if D exec "$WEB" apache2ctl -t >/dev/null 2>&1; then
    D exec "$WEB" apache2ctl -k graceful >/dev/null 2>&1 || true
    say "  apache 설정 OK · 스텁 vhost 적용"
  else
    say "  ! apache2ctl -t 실패 — 설정 확인 필요"; D exec "$WEB" apache2ctl -t
  fi
}

web_down() {
  say "ModSecurity 스텁 vhost 제거 (kt66-web)"
  D exec "$WEB" sh -c 'rm -f /etc/apache2/conf-enabled/purple-test.conf; rm -rf /var/www/purple-test /etc/modsecurity/purple'
  D exec "$WEB" apache2ctl -k graceful >/dev/null 2>&1 || true
}

siem_up() {
  say "Wazuh 디코더·룰·AR·CDB (kt66-siem)"
  D cp "$B/rules/common/kt66-purple-decoders.xml" "$SIEM:/var/ossec/etc/decoders/kt66-purple-decoders.xml"
  # 라운드별 룰 (purple- 접두사로 — 기존 룰과 안 섞인다)
  for r in $ROUNDS; do
    [ -f "$B/rules/$r/wazuh_rules.xml" ] && D cp "$B/rules/$r/wazuh_rules.xml" "$SIEM:/var/ossec/etc/rules/purple-$r.xml"
  done
  # CDB 허용 목록
  for l in "$B"/rules/*/lists/*; do
    [ -f "$l" ] && D cp "$l" "$SIEM:/var/ossec/etc/lists/$(basename "$l")"
  done
  # AR 스크립트
  D cp "$B/rules/common/purple-ar.sh" "$SIEM:/var/ossec/active-response/bin/purple-ar.sh"
  # docker cp 는 root:root 로 넣으므로 Wazuh 가 읽도록 소유권·권한을 바로잡는다 (안 하면 analysisd 가 못 읽는다)
  D exec "$SIEM" sh -c 'chown root:wazuh /var/ossec/etc/decoders/kt66-purple-decoders.xml /var/ossec/etc/rules/purple-*.xml /var/ossec/etc/lists/purple-allow-* 2>/dev/null; chmod 660 /var/ossec/etc/rules/purple-*.xml /var/ossec/etc/decoders/kt66-purple-decoders.xml /var/ossec/etc/lists/purple-allow-* 2>/dev/null; chown root:wazuh /var/ossec/active-response/bin/purple-ar.sh; chmod 750 /var/ossec/active-response/bin/purple-ar.sh; mkdir -p /var/ossec/logs/purple; chown wazuh:wazuh /var/ossec/logs/purple'
  # ossec.conf 마커 블록 (멱등: 먼저 지우고 다시 넣는다)
  ossec_strip
  local tmp; tmp=$(mktemp)
  { echo "$BEGIN"
    echo "<ossec_config>"
    cat "$B/rules/common/wazuh_localfile.xml" "$B/rules/common/ar_config.xml"
    for r in $ROUNDS; do [ -f "$B/rules/$r/wazuh_ar.xml" ] && cat "$B/rules/$r/wazuh_ar.xml"; done
    echo "  <ruleset>"
    echo "    <list>etc/lists/purple-allow-scanner</list>"
    echo "    <list>etc/lists/purple-allow-backup</list>"
    echo "  </ruleset>"
    echo "</ossec_config>"
    echo "$END"
  } > "$tmp"
  D cp "$tmp" "$SIEM:/tmp/purple-ossec-block.xml"; rm -f "$tmp"
  D exec "$SIEM" sh -c 'printf "\n" >> /var/ossec/etc/ossec.conf; cat /tmp/purple-ossec-block.xml >> /var/ossec/etc/ossec.conf; rm -f /tmp/purple-ossec-block.xml'
  if D exec "$SIEM" /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    say "  analysisd -t OK · 매니저 재시작"
    D exec "$SIEM" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
  else
    say "  ! analysisd -t 실패 — ossec.conf 블록 되돌림"; ossec_strip
    D exec "$SIEM" /var/ossec/bin/wazuh-analysisd -t
    return 1
  fi
}

siem_down() {
  say "Wazuh 퍼플 설정 제거 (kt66-siem)"
  ossec_strip
  D exec "$SIEM" sh -c 'rm -f /var/ossec/etc/decoders/kt66-purple-decoders.xml /var/ossec/etc/rules/purple-*.xml /var/ossec/etc/lists/purple-allow-* /var/ossec/active-response/bin/purple-ar.sh; rm -rf /var/ossec/logs/purple'
  D exec "$SIEM" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
}

idx_up() {
  say "인덱스 패턴 purple-* (대시보드)"
  curl -sk -u "$DUSER:$DPASS" -X POST "$DASH/api/saved_objects/index-pattern/purple-star" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -d '{"attributes":{"title":"purple-*","timeFieldName":"timestamp"}}' >/dev/null 2>&1 \
    && say "  purple-* 생성(또는 이미 있음)" || say "  (대시보드 접근 실패 — 수동 생성)"
}
idx_down() {
  curl -sk -u "$DUSER:$DPASS" -X DELETE "$DASH/api/saved_objects/index-pattern/purple-star" -H 'osd-xsrf: true' >/dev/null 2>&1 || true
}

case "${1:-}" in
  up)
    web_up; siem_up && idx_up
    say "완료. 이제 'python3 rNN_*.py gen --anchor 2026-11-01' 로 라운드 로그를 적재하세요."
    say "선택(§5 Sigma)·(§6 Sysmon/osquery)은 README 참고 — 기본 설치엔 포함하지 않음(기존 룰 보존)." ;;
  down)
    web_down; siem_down; idx_down
    say "원상복구 완료. 적재한 데이터는 'python3 rNN_*.py reset' 으로 지웁니다." ;;
  status)
    echo "== kt66-web =="; D exec "$WEB" sh -c 'ls /etc/apache2/conf-enabled/ | grep -q purple-test && echo "  스텁 vhost: 적용" || echo "  스텁 vhost: 없음"; ls /etc/modsecurity/purple/*.conf 2>/dev/null | wc -l | sed "s/^/  modsec 룰 파일: /"'
    echo "== kt66-siem =="; D exec "$SIEM" sh -c 'grep -q "PURPLE-AGG BEGIN" /var/ossec/etc/ossec.conf && echo "  ossec.conf 블록: 있음" || echo "  ossec.conf 블록: 없음"; ls /var/ossec/etc/rules/purple-*.xml 2>/dev/null | wc -l | sed "s/^/  purple 룰: /"'
    code=$(curl -sk -u "$DUSER:$DPASS" -o /dev/null -w '%{http_code}' "$DASH/api/saved_objects/index-pattern/purple-star" -H 'osd-xsrf: true' 2>/dev/null)
    echo "== dashboard =="; [ "$code" = 200 ] && echo "  purple-* 패턴: 있음" || echo "  purple-* 패턴: 없음" ;;
  *)
    echo "사용법: $0 {up|down|status}"; exit 1 ;;
esac
