# R09 규칙 팩 — 중간 종합
R09 는 새 기법이 아니라 R03·R04·R05·R07·R08 기법의 결합이다. 먼저 그 라운드 규칙을 함께 올린다.

    cat ../r03/wazuh_rules.xml ../r04/wazuh_rules.xml ../r05/wazuh_rules.xml ../r07/wazuh_rules.xml ../r08/wazuh_rules.xml wazuh_rules.xml

Wazuh 상관 규칙의 timeframe 은 분·시간 단위 기억이다. 35일에 걸친 체인(정찰 D-85 → 유출 D-5)은
규칙 하나로 이을 수 없다 → 단계별 경보(규칙) + 장기 연결(집계·모니터, lab 미션 6) 으로 나눈다.
