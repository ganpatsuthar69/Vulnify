"""Asynchronous client for Open Source Vulnerabilities (OSV) API."""

import asyncio
from datetime import datetime, timezone
import logging
import random
import time
from typing import Any
import httpx

from vulnify.config import Settings
from vulnify.osv.models import OsvQuery, OsvVulnerability, parse_osv_vulnerability

logger = logging.getLogger("vulnify")

TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


class OsvApiError(Exception):
    """Raised when an OSV API request encounters an unrecoverable failure."""

    def __init__(self, message: str, status_code: int | None = None, is_transient: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.is_transient = is_transient


class OsvClient:
    """Official OSV REST API client supporting batch lookups, retries, and bounded concurrency."""

    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.base_url = settings.OSV_API_BASE_URL.rstrip("/")
        self.timeout = float(settings.OSV_API_TIMEOUT_SECONDS)
        self.max_retries = settings.OSV_API_MAX_RETRIES
        self.backoff_base = float(settings.OSV_API_BACKOFF_BASE_SECONDS)
        self.batch_size = settings.OSV_BATCH_SIZE
        self._semaphore = asyncio.Semaphore(settings.OSV_MAX_CONCURRENT_REQUESTS)
        self._custom_client = http_client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._custom_client is not None:
            return self._custom_client
        return httpx.AsyncClient(timeout=self.timeout)

    def _calculate_backoff(self, attempt: int, response: httpx.Response | None = None) -> float:
        """Calculate exponential backoff duration with jitter, respecting Retry-After if present."""
        if response is not None:
            retry_after = response.headers.get("retry-after")
            if retry_after:
                try:
                    sec = float(retry_after)
                    return min(max(sec, 0.5), 30.0)
                except ValueError:
                    pass

        # Exponential backoff with jitter: base * 2^attempt + [0, 0.5]
        backoff = min(self.backoff_base * (2**attempt), 30.0)
        jitter = random.uniform(0.0, 0.5)
        return backoff + jitter

    async def query_single(
        self,
        query: OsvQuery,
        client: httpx.AsyncClient | None = None,
    ) -> list[OsvVulnerability]:
        """Query OSV for a single package version using POST /v1/query with retries."""
        url = f"{self.base_url}/v1/query"
        payload = query.to_api_payload()
        now_ts = int(datetime.now(timezone.utc).timestamp())

        async with self._semaphore:
            active_client = client or await self._get_client()
            should_close = client is None and self._custom_client is None

            try:
                for attempt in range(self.max_retries + 1):
                    try:
                        resp = await active_client.post(url, json=payload)
                        if resp.status_code == 200:
                            data = resp.json()
                            vulns_raw = data.get("vulns") or []
                            return [parse_osv_vulnerability(v, now_ts) for v in vulns_raw if isinstance(v, dict)]

                        is_transient = resp.status_code in TRANSIENT_STATUS_CODES
                        if is_transient and attempt < self.max_retries:
                            backoff = self._calculate_backoff(attempt, resp)
                            logger.warning(
                                f"OSV query returned {resp.status_code} for {query.package.name}@{query.version}. "
                                f"Retrying in {backoff:.2f}s (attempt {attempt + 1}/{self.max_retries})"
                            )
                            await asyncio.sleep(backoff)
                            continue

                        raise OsvApiError(
                            f"OSV query failed with status {resp.status_code}: {resp.text[:200]}",
                            status_code=resp.status_code,
                            is_transient=is_transient,
                        )

                    except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                        if attempt < self.max_retries:
                            backoff = self._calculate_backoff(attempt)
                            logger.warning(
                                f"OSV network error for {query.package.name}@{query.version}: {net_err}. "
                                f"Retrying in {backoff:.2f}s (attempt {attempt + 1}/{self.max_retries})"
                            )
                            await asyncio.sleep(backoff)
                            continue
                        raise OsvApiError(f"OSV connection timeout or network failure: {net_err}", is_transient=True) from net_err

            finally:
                if should_close:
                    await active_client.aclose()

        return []

    async def query_batch(
        self,
        queries: list[OsvQuery],
        client: httpx.AsyncClient | None = None,
    ) -> tuple[dict[OsvQuery, list[OsvVulnerability]], list[tuple[OsvQuery, str]]]:
        """Query OSV for a batch of package versions using POST /v1/querybatch.
        
        Returns a tuple of:
          (successful_results_map, failed_queries_with_reasons)
        Falls back safely to individual queries if a batch call fails.
        """
        if not queries:
            return {}, []

        url = f"{self.base_url}/v1/querybatch"
        payload = {"queries": [q.to_api_payload() for q in queries]}
        now_ts = int(datetime.now(timezone.utc).timestamp())

        results_map: dict[OsvQuery, list[OsvVulnerability]] = {}
        failed_list: list[tuple[OsvQuery, str]] = []

        active_client = client or await self._get_client()
        should_close = client is None and self._custom_client is None

        batch_succeeded = False
        async with self._semaphore:
            try:
                for attempt in range(self.max_retries + 1):
                    try:
                        resp = await active_client.post(url, json=payload)
                        if resp.status_code == 200:
                            data = resp.json()
                            raw_results = data.get("results") or []
                            for idx, query in enumerate(queries):
                                if idx < len(raw_results):
                                    item = raw_results[idx]
                                    vulns_raw = item.get("vulns") or [] if isinstance(item, dict) else []
                                    results_map[query] = [
                                        parse_osv_vulnerability(v, now_ts)
                                        for v in vulns_raw
                                        if isinstance(v, dict)
                                    ]
                                else:
                                    results_map[query] = []
                            batch_succeeded = True
                            break

                        is_transient = resp.status_code in TRANSIENT_STATUS_CODES
                        if is_transient and attempt < self.max_retries:
                            backoff = self._calculate_backoff(attempt, resp)
                            logger.warning(
                                f"OSV querybatch returned {resp.status_code}. "
                                f"Retrying in {backoff:.2f}s (attempt {attempt + 1}/{self.max_retries})"
                            )
                            await asyncio.sleep(backoff)
                            continue

                        logger.warning(
                            f"OSV querybatch failed with status {resp.status_code}. Falling back to individual queries."
                        )
                        break

                    except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                        if attempt < self.max_retries:
                            backoff = self._calculate_backoff(attempt)
                            logger.warning(
                                f"OSV querybatch network error: {net_err}. "
                                f"Retrying in {backoff:.2f}s (attempt {attempt + 1}/{self.max_retries})"
                            )
                            await asyncio.sleep(backoff)
                            continue
                        logger.warning(
                            f"OSV querybatch network failure after retries: {net_err}. Falling back to individual queries."
                        )
                        break

            finally:
                if should_close and batch_succeeded:
                    await active_client.aclose()

        # Fallback to individual queries for resilient partial success if batch query failed
        if not batch_succeeded:
            try:
                for q in queries:
                    try:
                        vulns = await self.query_single(q, client=active_client)
                        results_map[q] = vulns
                    except Exception as err:
                        logger.warning(f"Failed lookup for {q.package.name}@{q.version}: {err}")
                        failed_list.append((q, str(err)))
            finally:
                if should_close:
                    await active_client.aclose()

        return results_map, failed_list
