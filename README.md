# flowsint-enrichers
This repository contains all my enrichers for Flowsint. Based on https://breach.vip/api/docs

### How to use it

1. **Save** the file as `plugins/enrichers/breachvip_search_enricher.py`.  
2. **Add it to your FlowSINT flow**:

```yaml
- name: BreachVIP Search
  type: enrich
  script: plugins/enrichers/breachvip_search_enricher.py
```

3. **Feed it items** like:

```json
{
  "term":   "test@*.com",
  "fields": ["email", "domain"],
  "wildcard": true
}
```

The enricher will return:

```json
{
  "term":"test@*.com",
  "fields":["email","domain"],
  "results":[
    {"source":"Adobe", "categories":"[\"some\",\"category\"]"},
    ...
  ],
  "timestamp_utc": "...",
}
```

---

## 3. Rate‑Limit Handling

The OpenAPI spec states **15 requests/min**.  
The script enforces this by:

* Using `RETRY_DELAY` and exponential back‑off for `429` responses.  
* Setting `MIN_INTERVAL = 60 / RATE_LIMIT` – you can add a simple sleep between consecutive calls if you are batching many requests in a loop.

---

## 4. Dependency 

```
requests==2.32.3
```
