#!/bin/sh
# purple-test 스텁: 요청 본문은 읽고 버린다. 상태코드만 흉내 낸다. 어떤 명령도 실행하지 않는다.
case "$HTTP_X_PURPLE_STATUS" in
  401|403|404|429|500|503) st="$HTTP_X_PURPLE_STATUS" ;;
  *) st=200 ;;
esac
[ -n "$CONTENT_LENGTH" ] && head -c "$CONTENT_LENGTH" >/dev/null
printf 'Status: %s\r\nContent-Type: text/plain\r\n\r\nok\n' "$st"
