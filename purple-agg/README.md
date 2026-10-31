# purple-agg — 집계 중심 퍼플팀 탐지·대응 실습 번들 (kt66)

> **실제 공격은 하지 않는다.** 라운드별 생성기가 로그만 만들어 Wazuh 인덱서에 적재한다.
> 외부 IP 는 무작위(가상)이므로 위협 인텔로 공유하지 않는다.

PURPLE 15라운드 중 로그로 재현 가능한 13라운드(R01–R10, R12, R13, R15). 라운드마다
① 생성기(`rNN_*.py`) ② 정답 키(`answers/`) ③ 실습(`labs/lab_rNN.yaml`, 미션 8개) ④ 강의(`lectures/lecture_rNN.md`)
⑤ 규칙 팩(`rules/rNN/`: Suricata · ModSecurity · Wazuh 상관 + 액티브 리스폰스 · Sigma · osquery · Sysmon) 이 있다.

## 0. 데이터 설계 한눈에

| 항목 | 값 |
|---|---|
| 기간 | 기본 90일 (`--days 7~365`, 최대 1년), 기준일 `--anchor 2026-11-01` 이면 정답 키와 일치 |
| 규모 | 라운드당 약 240만 건, 서로 다른 외부 IP 100만+ (`--scale` 로 조절) |
| 정상 비율 | 99.86–99.99 % (엔드포인트 10곳: 웹 7 vhost · 웹메일 · bastion · Windows PC, + FW·IPS·DNS·메일) |
| 엔드포인트 IP | 포트 vhost 대신 시스템별 가상 IP — juice 198.51.100.81, dvwa .82, neobank .83, govportal .84, mediforum .85, admin .86, ai .87, webmail .26 (내부: 10.20.40.81–87, bastion 10.20.30.201, KT66-WIN-01 10.20.70.10) |
| 공격자 시간 패턴 | 실제 장기 집계(labeling_2019-03-02.xlsx, 출발지 13,543개)에서 뽑은 프로파일 `profile_2019.json` — 1회성 37% · 재방문 55% · 상주 8%, 활동 일수·주말 비율·업무시간 외 비율·시작 시각 분포 |
| 인덱스 | `purple-rNN` (템플릿 `purple-lab`, 인덱스 패턴 `purple-*`, 시간 필드 `timestamp`) |

다른 기간의 집계표로 프로파일을 바꾸려면: `python3 profile_from_labeling.py labeling_*.xlsx -o my.json` → `python3 rNN_*.py gen --profile my.json`.

## 1. 배치 (kt66 호스트)

```bash
# 번들을 홈에 둔다
cd ~
unzip purple-agg.zip
cd ~/purple-agg

# 인덱서 연결 확인 (기본 https://10.20.32.110:9200 admin/SecretPassword — 환경변수 IDX, IDX_USER, IDX_PASS 로 바꿀 수 있다)
python3 r01_baseline.py check
```

## 2. 생성기 명령 (모든 라운드 공통)

| 명령 | 하는 일 |
|---|---|
| `gen --anchor 2026-11-01` | 생성·적재 (`--out f.ndjson` 이면 파일로) |
| `answers --anchor 2026-11-01` | 인덱서 없이 정답 키 계산 (`answers/`) |
| `dsl Qn` · `ask Qn` | 질의 본문 출력 · 인덱서에 질의해 표로 |
| `monitor` | Alerting 모니터 드라이런(`_execute`) |
| `pcap` | 공격 + 같은 시간대 정상 표본을 패킷으로 재구성 → Suricata 오프라인 검증 |
| `http` | HTTP 재생 파일(출발지·상태·무해한 본문) → ModSecurity 스텁 검증 |
| `replay` | Wazuh 재생 파일(원래 시각 포함) → manager 상관 규칙 검증 |
| `samples` · `reset` | wazuh-logtest 용 표본 줄 · 인덱스 삭제 |

## 3. ModSecurity 스텁 vhost (kt66-web, 최초 1회)

규칙 검증은 운영 앱이 아니라 응답이 항상 "ok" 인 스텁에서만 한다. 재생기가 원래 출발지(`X-Purple-Client`)와
상태코드(`X-Purple-Status`)를 헤더로 보내면 mod_remoteip·stub.cgi 가 그대로 흉내 내 IP 별·응답 단계 카운터가 실제처럼 돈다.

```bash
# 모듈 켜기
docker exec kt66-web a2enmod security2 remoteip cgid

# 스텁 파일·vhost·규칙 폴더
docker exec kt66-web mkdir -p /var/www/purple-test /etc/modsecurity/purple
docker cp rules/common/stub.cgi kt66-web:/var/www/purple-test/stub.cgi
docker cp rules/common/purple-test-vhost.conf kt66-web:/etc/apache2/sites-available/purple-test.conf
docker exec kt66-web a2ensite purple-test

# 문법 검사 후 적용
docker exec kt66-web apache2ctl -t
docker exec kt66-web apache2ctl -k graceful
```

주의: ModSecurity 2 의 `expirevar` 를 요청마다 다시 걸면 창이 계속 밀린다(슬라이딩 → 느린 정상 사용자도 누적).
번들 규칙은 카운터를 **처음 만들 때 한 번만** 만료를 거는 고정 창으로 썼다. JSON 본문은 `modsecurity.conf` 의 200001 이
JSON 파서를 켜면 `ARGS`(json.message)로 들어온다.

## 4. Wazuh 공통 설정 (kt66-siem, 최초 1회)

```bash
# 디코더 (FW·메일 게이트웨이·DNS 요약 로그)
docker cp rules/common/kt66-purple-decoders.xml kt66-siem:/var/ossec/etc/decoders/kt66-purple-decoders.xml

# 재생 입력(localfile 2개)과 모의 대응 명령(purple-ar) — ossec.conf 끝에 블록 추가
docker cp rules/common/wazuh_localfile.xml kt66-siem:/tmp/
docker cp rules/common/ar_config.xml kt66-siem:/tmp/
docker exec kt66-siem sh -c "{ echo '<ossec_config>'; cat /tmp/wazuh_localfile.xml /tmp/ar_config.xml; echo '</ossec_config>'; } >> /var/ossec/etc/ossec.conf"
docker exec kt66-siem mkdir -p /var/ossec/logs/purple

# 모의 대응 스크립트 — '무엇을 했어야 하는지'만 /var/ossec/logs/purple-ar.log 에 적는다
docker cp rules/common/purple-ar.sh kt66-siem:/var/ossec/active-response/bin/purple-ar.sh
docker exec kt66-siem chown root:wazuh /var/ossec/active-response/bin/purple-ar.sh
docker exec kt66-siem chmod 750 /var/ossec/active-response/bin/purple-ar.sh

# R15 허용 목록(CDB) — ossec.conf 의 <ruleset> 안에 두 줄 추가 후 재시작
#   <list>etc/lists/purple-allow-scanner</list>
#   <list>etc/lists/purple-allow-backup</list>

# 검사·재시작
docker exec kt66-siem /var/ossec/bin/wazuh-analysisd -t
docker exec kt66-siem /var/ossec/bin/wazuh-control restart
```

**재생은 반드시 `purple_log_replay.py` 로.** Wazuh 상관 규칙(frequency·timeframe·if_matched_sid)은 로그 안의 날짜가 아니라
manager 에 도착한 시각으로 센다. 기본 `--speed 60 --max-gap 0.05` 는 전체를 몇 분에 흘려 넣는다(긴 창 규칙은 압축 때문에 더 잘 울린다).
초 단위 규칙(R13)은 `--speed 1 --max-gap 2` 로 공격 구간만(`--from-hour 4 --to-hour 5`).

규칙 ID 대역: Wazuh `19NN0k` (R01 190101 …, R15 191501), Sigma 단건 200001+ (kt66 변환기) · 상관 210001+ (`sigma_corr2wazuh.py`),
Suricata `96NN0xx`, ModSecurity `9NNxx`.

### Wazuh 규칙 작성 때 확인한 것 (4.10 소스·기본 룰셋 기준)

- `<field name=…>` 에는 정적 필드(srcip·dstip·srcport·dstport·user·srcuser·dstuser·url·id·data·extra_data·status·protocol·system_name·action)를 쓸 수 없다 → `<srcip>` `<url>` `<id>` 등 전용 옵션을 쓴다.
- `<same_user/>` 는 **dstuser** 를 비교한다(sshd 디코더의 user = dstuser). JSON 로그의 `srcuser` 는 `<same_srcuser/>`.
- `<srcuser>` 라는 규칙 옵션은 없다 → sudo 사용자는 `<match>^www-data\s+:</match>` 처럼 본문으로.
- 웹 로그 자식 규칙은 기본 31103·31104·31106 이 먼저 잡을 수 있다 → 번들은 `if_sid 31100,31103,31104,31105,31106,31108` 로 모든 경로에 걸었다.
- 5401(sudo 실패)은 본문의 "incorrect password attempt" 로 판별된다 — 생성기 로그도 이 문구를 쓴다.

## 5. Sigma (kt66 `sigma/`)

kt66 의 `sigma2wazuh.py` 는 단건 Sigma 를 full_log 정규식의 **최상위** 규칙으로 바꾼다. Wazuh 는 최상위 규칙 중 처음 맞는 것
(웹 31100, Suricata 86600, sshd 5700 …)의 자식만 보므로 그런 로그에서 최상위 Sigma 규칙은 평가되지 않는다.
`sigma_corr2wazuh.py --fix-parents` 가 logsource 에 맞는 부모를 끼워 넣고, 같은 도구가 Sigma 상관(event_count·value_count·temporal)을
Wazuh 빈도·순서 규칙으로 바꾼다.

```bash
cp rules/r*/sigma/*.yml ~/kt66/sigma/rules/
python3 ~/kt66/sigma/sigma2wazuh.py ~/kt66/sigma/rules > /tmp/sigma_rules.xml
python3 sigma_corr2wazuh.py --fix-parents /tmp/sigma_rules.xml > /tmp/sigma_rules.fixed.xml
python3 sigma_corr2wazuh.py ~/kt66/sigma/rules /tmp/sigma_rules.fixed.xml > /tmp/sigma_corr_rules.xml
docker cp /tmp/sigma_rules.fixed.xml kt66-siem:/var/ossec/etc/rules/sigma_rules.xml
docker cp /tmp/sigma_corr_rules.xml kt66-siem:/var/ossec/etc/rules/sigma_corr_rules.xml
```

## 6. 추가 설치 제안

| 도구 | 어디 | 왜 |
|---|---|---|
| Sysmon (Windows) | KT66-WIN-01 | R07·R08·R15 의 ProcessCreate(부모×자식)·DnsQuery·NetworkConnect — `rules/rNN/sysmon.xml` 의 RuleGroup 을 설정에 합쳐 `sysmon64 -c` |
| Sysmon for Linux | kt66-web·GPU 존 | R04·R05·R10·R13 의 apache2/node→sh, /dev/shm 실행, .kt66lock FileCreate |
| osquery 예약 팩 | kt66-web·서버 | `rules/rNN/osquery.conf` 를 `/etc/osquery/osquery.conf` packs 로 → Wazuh osquery 모듈 |
| OpenSearch Alerting | 인덱서 | 미션 5 모니터 (기본 포함) |

## 7. 검증 결과 (`validation/`)

`validation/validate_all.sh` 가 번들 작성 시 돌린 결과: 라운드별 Suricata 규칙 경보 수(`rNN_suricata.txt`)와
ModSecurity 규칙 차단 수(`rNN_modsec.txt`). 0 인 규칙은 이유가 있다 — pcap 은 본문을 재구성하지 않음(R12 9612002 → ModSec 91202 로 검증),
stream_size 대용량(R08·R09 → 집계 Q5), 압축 재생에서의 카운터 부풀림(R06 계정 카운터 → 임계값은 집계로).
Wazuh 규칙은 kt66-siem 에서 미션 7 로 검증한다(작성 환경에 Wazuh manager 가 없어 건수는 싣지 않았다).

## 8. 폴더

```
purplelab.py              공통 엔진 (엔드포인트·정상 트래픽·집계 평가기·pcap/http/replay)
rNN_*.py                  라운드 생성기 13개 (공격 시나리오 + 집계 문항 Q1~Qn + 모니터)
profile_2019.json         실제 장기 집계에서 뽑은 공격자 시간 패턴 · profile_from_labeling.py
sigma_corr2wazuh.py       Sigma 상관·부모 연결 (kt66 sigma2wazuh 확장)
rules/common/             디코더 · localfile · purple-ar · 스텁 vhost · 재생기 2종
rules/rNN/                라운드 규칙 팩
answers/                  정답 키 (강사용)
labs/ · lectures/         실습 YAML(미션 8) · 강의 MD
validation/               검증 스크립트·결과
make_labs.py · labs_config.py   실습·강의 생성기 (정답 키·규칙 팩에서 다시 만든다)
```
