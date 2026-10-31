# Dev Tools 집계 쿼리 6개 (고급 실습)

대시보드 → **Indexer management → Dev Tools** 왼쪽 창에 붙여 넣고, 쿼리 첫 줄의 ▶(Send request)를 누른다.
시간 범위는 쿼리 안의 `range`로 정한다(Discover 시간 선택기와 무관). 합성 데이터만 보려면 `synthetic.flag:true` 조건을 넣는다.

## 1. IP 집계 한 방 — 최대 레벨 순 상위 20개 IP

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {"bool": {"filter": [
    {"range": {"timestamp": {"gte": "now-90d"}}},
    {"term": {"synthetic.flag": true}},
    {"exists": {"field": "data.srcip"}}
  ]}},
  "aggs": {"by_ip": {
    "terms": {"field": "data.srcip", "size": 20, "order": {"max_level": "desc"}},
    "aggs": {
      "max_level":  {"max": {"field": "rule.level"}},
      "n_hosts":    {"cardinality": {"field": "agent.name"}},
      "n_types":    {"cardinality": {"field": "rule.id"}},
      "days": {"cardinality": {"script": {"source":
        "(doc['timestamp'].value.toInstant().toEpochMilli() + 32400000L) / 86400000L"}}},
      "fw_drop":   {"filter": {"term": {"rule.groups": "firewall_drop"}}},
      "waf_block": {"filter": {"bool": {"must": [
        {"term": {"rule.groups": "attack"}}, {"term": {"data.id": "403"}}]}}},
      "offhours": {"filter": {"script": {"script": {"source":
        "def t = doc['timestamp'].value.withZoneSameInstant(ZoneId.of('Asia/Seoul')); return t.getHour() < 9 || t.getHour() >= 18 || t.getDayOfWeek().getValue() >= 6;"}}}},
      "offhours_ratio": {"bucket_script": {"buckets_path": {"o": "offhours._count", "n": "_count"},
                                           "script": "params.o / params.n"}},
      "reputation": {"avg": {"field": "data.ip_reputation"}}
    }}}
}
```

## 2. 이벤트(룰)별 발생 IP 수·해외 비율·평균 평판

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {"bool": {"filter": [{"term": {"synthetic.flag": true}}, {"range": {"rule.level": {"gte": 5}}}]}},
  "aggs": {"by_rule": {
    "terms": {"field": "rule.id", "size": 15},
    "aggs": {
      "desc":     {"terms": {"field": "rule.description", "size": 1}},
      "ips":      {"cardinality": {"field": "data.srcip"}},
      "foreign":  {"filter": {"bool": {"must_not": [{"term": {"GeoLocation.country_name": "South Korea"}}],
                                        "must": [{"exists": {"field": "GeoLocation.country_name"}}]}}},
      "reputation": {"avg": {"field": "data.ip_reputation"}}
    }}}
}
```

## 3. 시간당 위험 이력 — 위험 = Σ 레벨², 24시간 롤링 합

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {"bool": {"filter": [{"term": {"synthetic.flag": true}}]}},
  "aggs": {"per_hour": {
    "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "time_zone": "Asia/Seoul"},
    "aggs": {
      "n_ips": {"cardinality": {"field": "data.srcip"}},
      "risk":  {"sum": {"script": "doc['rule.level'].value >= 5 ? doc['rule.level'].value * doc['rule.level'].value : 0"}},
      "risk_24h": {"moving_fn": {"buckets_path": "risk", "window": 24, "script": "MovingFunctions.sum(values)"}},
      "top_risk": {"bucket_sort": {"sort": [{"risk": {"order": "desc"}}], "size": 10}}
    }}}
}
```

## 4. 업무외 시간 비율 — 전체

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {"bool": {"filter": [{"term": {"synthetic.flag": true}}, {"range": {"rule.level": {"gte": 10}}}]}},
  "aggs": {"offhours": {"filter": {"script": {"script": {"source":
    "def t = doc['timestamp'].value.withZoneSameInstant(ZoneId.of('Asia/Seoul')); return t.getHour() < 9 || t.getHour() >= 18 || t.getDayOfWeek().getValue() >= 6;"}}}}}
}
```

## 5. 한 IP 의 단계(stage)별 첫 등장 시각 — 체인 확인 (정답 라벨 사용, 채점용)

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {"bool": {"filter": [{"term": {"synthetic.campaign": "apt-1"}}]}},
  "aggs": {"stage": {"terms": {"field": "synthetic.stage", "size": 10, "order": {"first": "asc"}},
           "aggs": {"first": {"min": {"field": "timestamp"}}}}}
}
```

## 6. 정리 — 합성 데이터 삭제 (강사)

```json
POST wazuh-alerts-4.x-*/_delete_by_query
{"query": {"term": {"synthetic.flag": true}}}
```
