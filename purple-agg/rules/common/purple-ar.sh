#!/bin/sh
# purple-ar.sh — 퍼플 실습용 액티브 리스폰스(모의 대응)
#  · Wazuh 4.x AR 은 stdin 으로 JSON 한 줄을 넘긴다. 이 스크립트는 '무엇을 했어야 하는지'를 기록만 한다.
#  · 실제 차단은 라운드 lab 미션 8 에서 nftables 블록리스트로 따로 한다(재생 IP 는 가상).
#  · 설치: /var/ossec/active-response/bin/purple-ar.sh (root:wazuh 750)
LOG=/var/ossec/logs/purple-ar.log
read -r INPUT
CMD=$(echo "$INPUT" | sed -n 's/.*"command":"\([a-z]*\)".*/\1/p')
RID=$(echo "$INPUT" | sed -n 's/.*"rule":{[^}]*"id":"\([0-9]*\)".*/\1/p')
SRC=$(echo "$INPUT" | sed -n 's/.*"srcip":"\([0-9.]*\)".*/\1/p')
USR=$(echo "$INPUT" | sed -n 's/.*"srcuser":"\([^"]*\)".*/\1/p')
echo "$(date '+%F %T') purple-ar $CMD rule=$RID srcip=${SRC:--} user=${USR:--} action=$(case $RID in 19*) echo quarantine-candidate;; *) echo log;; esac)" >> "$LOG"
exit 0
