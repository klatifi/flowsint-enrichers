#!/usr/bin/env python3
# plugins/enrichers/breachvip_search_flowsint.py

"""
FlowsInt Enricher – BreachVIP Search
------------------------------------
This script is a FlowsInt‑specific implementation that follows the
documentation at https://www.flowsint.io/docs/developers/managing-enrichers.
"""

import os
import json
import time
from typing import Dict, Any

import httpx
from flowsint.enrich import enrich  # <-- FlowsInt decorator

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
BASE_URL        = "https://breach.vip"
SEARCH_ENDPOINT = "/api/search"

RATE_LIMIT      = 15            
MIN_INTERVAL    = 60 / RATE_LIMIT

# Simple in‑memory counter – FlowsInt runs a single process per worker
_last_request_ts = 0.0

# ------------------------------------------------------------------
def _rate_limit_sleep() -> None:
    """
    Sleep if we are hitting the 15‑req/min limit.
    This is a *very* simple implementation – in production you might
    want to use a token bucket or Redis‑backed counter.
    """
    global _last_request_ts
    now = time.time()
    if now - _last_request_ts < MIN_INTERVAL:
        sleep_for = MIN_INTERVAL - (now - _last_request_ts)
        time.sleep(sleep_for)
    _last_request_ts = time.time()

# ------------------------------------------------------------------
def _build_payload(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert the incoming FlowsInt item into a SearchRequest
    that matches the OpenAPI spec.
    """
    payload = {
        "term":   item["term"],
        "fields": item["fields"]
    }
    # Optional properties – only include if present
    for opt in ("categories", "wildcard", "case_sensitive"):
        if opt in item:
            payload[opt] = item[opt]
    return payload

# ------------------------------------------------------------------
@enrich(name="BreachVIP Search")
async def breachvip_search(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    FlowsInt entry point.
    The function must be async and return a JSON‑serialisable dict.
    """
    # ------------------------------------------------------------------
    # Validate input
    if "term" not in item or "fields" not in item:
        return {"error": "Both 'term' and 'fields' must be supplied"}

    # ------------------------------------------------------------------
    _rate_limit_sleep()          # respect the 15‑req/min rule

    payload = _build_payload(item)

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                f"{BASE_URL}{SEARCH_ENDPOINT}",
                json=payload,
                headers={"Accept": "application/json"}
            )
        except httpx.RequestError as exc:
            return {"error": f"Request failed: {exc}"}

    # ------------------------------------------------------------------
    if resp.status_code == 429:
        return {"error": "Rate limited – try again later"}

    if resp.status_code >= 400:
        # Attempt to parse the error body
        try:
            err = resp.json()
            return {"error": err.get("error", f"HTTP {resp.status_code}")}
        except Exception:
            return {"error": f"HTTP {resp.status_code}"}

    # ------------------------------------------------------------------
    # Successful response
    try:
        data = resp.json()
    except Exception as exc:
        return {"error": f"JSON parse error: {exc}"}

    # The API returns a SearchResponse with a `results` array
    return {
        "term":   item["term"],
        "fields": item["fields"],
        "results": data.get("results", []),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

# ------------------------------------------------------------------
# The following block allows the script to be run directly for debugging
if __name__ == "__main__":
    import sys

    # FlowsInt passes a JSON object via stdin
    input_item = json.load(sys.stdin)
    # Run the async function synchronously for debugging
    import asyncio
    output = asyncio.run(breachvip_search(input_item))
    print(json.dumps(output, indent=2))
