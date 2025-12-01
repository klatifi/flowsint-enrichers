#!/usr/bin/env python3
# plugins/enrichers/breachvip_search.py

import time
from typing import List, Dict, Any

import httpx
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher

# Import the custom types
from .types import Email, ResultItem

# ------------------------------------------------------------------
BASE_URL          = "https://breach.vip"
SEARCH_ENDPOINT   = "/api/search"

RATE_LIMIT        = 15          # requests per minute
MIN_INTERVAL      = 60 / RATE_LIMIT

_last_request_ts = 0.0

def _sleep_if_needed() -> None:
    global _last_request_ts
    now = time.time()
    if now - _last_request_ts < MIN_INTERVAL:
        time.sleep(MIN_INTERVAL - (now - _last_request_ts))
    _last_request_ts = now

# ------------------------------------------------------------------
@flowsint_enricher
class BreachVIPSearch(Enricher):
    """Enrich a domain/email by querying the BreachVIP search API."""

    # Define input and output types (single objects, not lists)
    InputType = Email
    OutputType = ResultItem

    # ------------------------------------------------------------------
    @classmethod
    def name(cls) -> str:
        return "breachvip_search"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        # The field that uniquely identifies the input – here the email address
        return "domain"

    # ------------------------------------------------------------------
    async def scan(self, data: List[Email]) -> List[ResultItem]:
        """Core enrichment logic – call BreachVIP for each input."""
        results: List[ResultItem] = []

        async with httpx.AsyncClient(timeout=15) as client:
            for item in data:
                # Respect the rate limit
                _sleep_if_needed()

                payload: Dict[str, Any] = {
                    "term": item.domain,
                    "fields": ["email"],  # adjust fields as needed
                }
                if item.wildcard is not None:
                    payload["wildcard"] = item.wildcard
                if item.case_sensitive is not None:
                    payload["case_sensitive"] = item.case_sensitive
                if item.categories:
                    payload["categories"] = item.categories

                try:
                    resp = await client.post(
                        f"{BASE_URL}{SEARCH_ENDPOINT}",
                        json=payload,
                        headers={"Accept": "application/json"},
                    )
                except httpx.RequestError as exc:
                    # Skip this item, log the error
                    self.logger.error(f"Request failed for {item.domain}: {exc}")
                    continue

                if resp.status_code == 429:
                    self.logger.warning("Rate limited – sleeping for 60s")
                    time.sleep(60)
                    continue

                if resp.status_code >= 400:
                    self.logger.warning(f"HTTP {resp.status_code} for {item.domain}")
                    continue

                try:
                    data_resp = resp.json()
                except Exception as exc:
                    self.logger.error(f"JSON parse error for {item.domain}: {exc}")
                    continue

                # Each element in `data_resp['results']` is a dict
                for rec in data_resp.get("results", []):
                    # Map the API fields to our ResultItem
                    results.append(
                        ResultItem(
                            source=rec.get("source", ""),
                            categories=rec.get("categories", []),
                            email_address=item.domain,
                        )
                    )

        return results

    # ------------------------------------------------------------------
    def postprocess(self, results: List[ResultItem], original_input: List[Email]) -> List[ResultItem]:
        """
        Create graph nodes/relationships if needed.
        For this example we simply return the results unchanged,
        but you could attach them to a graph here.
        """
        # Example: add a custom tag
        for r in results:
            self.graph.add_tag(r, "breachvip")
        return results

# Export types for easy imports elsewhere
InputType = BreachVIPSearch.InputType
OutputType = BreachVIPSearch.OutputType
