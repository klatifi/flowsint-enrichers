#!/usr/bin/env python3
# plugins/enrichers/breachvip_search_enricher.py

"""
FlowSINT Enricher – Breach.VIP Search 
"""

import os, sys, json, time
import requests

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
BASE_URL      = "https://breach.vip"
SEARCH_PATH   = "/api/search"
MAX_RETRIES   = 3
RETRY_DELAY   = 2          
RATE_LIMIT    = 15        
MIN_INTERVAL  = 60 / RATE_LIMIT

# ------------------------------------------------------------------
def safe_json(text: str):
    try:
        return json.loads(text)
    except Exception as exc:
        return {"error": f"JSON parse error: {exc}"}

# ------------------------------------------------------------------
def post_search(payload: dict) -> dict:
    """
    Calls /api/search with the supplied payload.
    Retries on 429 (rate‑limit) with exponential back‑off.
    """
    url = f"{BASE_URL}{SEARCH_PATH}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            if resp.status_code == 429:
                # Too many requests – wait and retry
                time.sleep(RETRY_DELAY * attempt)
                continue

            resp.raise_for_status()
            return safe_json(resp.text)

        except requests.exceptions.RequestException as exc:
            if attempt == MAX_RETRIES:
                return {"error": f"HTTP error after {MAX_RETRIES} attempts: {exc}"}
            time.sleep(RETRY_DELAY * attempt)

    return {"error": "unreachable code – should never happen"}

# ------------------------------------------------------------------
def enrich(item: dict) -> dict:
    """
    FlowSINT entry point.
    Expected input:
        {
            "term":   "test@*.com",
            "fields": ["email", "domain"],
            "wildcard": True,          # optional
            "case_sensitive": False    # optional
        }
    """
    term   = item.get("term")
    fields = item.get("fields")

    if not term or not fields:
        return {"error": "Both 'term' and 'fields' must be supplied"}

    # Build the request body according to SearchRequest schema
    payload = {
        "term":   term,
        "fields": fields
    }

    # Optional properties – only include if present in the input
    for opt in ("categories", "wildcard", "case_sensitive"):
        if opt in item:
            payload[opt] = item[opt]

    raw_resp = post_search(payload)

    # If the API returned an error, forward it
    if "error" in raw_resp:
        return {"term": term, "fields": fields, "error": raw_resp["error"]}

    # The API returns a SearchResponse with a list of Result objects
    results = raw_resp.get("results", [])
    return {
        "term":   term,
        "fields": fields,
        "results": results,
        "timestamp_utc": json.dumps(time.time(), default=lambda x: x)
    }

# ------------------------------------------------------------------
if __name__ == "__main__":
    # FlowSINT passes a JSON object via stdin
    input_item = json.load(sys.stdin)
    output = enrich(input_item)
    print(json.dumps(output))
