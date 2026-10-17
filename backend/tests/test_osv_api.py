"""Tests for OSV advisory integration, client, caching, service, and API endpoints."""

import asyncio
from datetime import datetime, timezone
import json
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.config import Settings
from vulnify.graph.advisory_repository import (
    AdvisoryLinkRecord,
    InMemoryAdvisoryRepository,
    PackageVersionItem,
    VulnerabilityRecord,
)
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository
from vulnify.osv.cache import OsvCache
from vulnify.osv.client import OsvClient
from vulnify.osv.models import OsvPackage, OsvQuery, OsvVulnerability, parse_osv_vulnerability
from vulnify.osv.service import OsvService

SAMPLE_VULN_DICT = {
    "id": "GHSA-1234-5678-90ab",
    "summary": "Prototype pollution in sample-pkg",
    "details": "A prototype pollution vulnerability allows remote code execution.",
    "database_specific": {"severity": "CRITICAL"},
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "aliases": ["CVE-2023-99999"],
    "published": "2023-01-15T00:00:00Z",
    "modified": "2023-01-16T00:00:00Z",
    "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
    "affected": [
        {
            "package": {"name": "sample-pkg", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                }
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def seed_admin_user(mock_user_repo: InMemoryUserRepository) -> None:
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user:
        user.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user


# =====================================================================
# 1. OSV Parser & Model Tests
# =====================================================================

def test_parse_osv_vulnerability():
    parsed = parse_osv_vulnerability(SAMPLE_VULN_DICT, retrieved_at=1700000000)
    assert parsed.id == "GHSA-1234-5678-90ab"
    assert "Prototype pollution" in parsed.summary
    assert parsed.severity == "CRITICAL"
    assert parsed.cvss == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert "CVE-2023-99999" in parsed.aliases
    assert "1.2.3" in parsed.fixed_versions
    assert parsed.published == "2023-01-15T00:00:00Z"
    assert parsed.retrieved_at == 1700000000


def test_parse_osv_vulnerability_minimal():
    minimal = {"id": "OSV-TEST-1"}
    parsed = parse_osv_vulnerability(minimal, retrieved_at=1700000000)
    assert parsed.id == "OSV-TEST-1"
    assert parsed.summary == "Vulnerability OSV-TEST-1"
    assert parsed.severity == "UNKNOWN"
    assert parsed.aliases == []


# =====================================================================
# 2. OSV Cache Tests
# =====================================================================

def test_cache_hit_and_expiry():
    cache = OsvCache(default_ttl_seconds=1)
    q = OsvQuery(package=OsvPackage(name="pkg-a", ecosystem="npm"), version="1.0.0")
    vuln = parse_osv_vulnerability(SAMPLE_VULN_DICT, retrieved_at=1700000000)

    # Initially missing
    assert cache.get(q.package.ecosystem, q.package.name, q.version) is None

    # Set and hit
    cache.set(q.package.ecosystem, q.package.name, q.version, [vuln])
    hit = cache.get(q.package.ecosystem, q.package.name, q.version)
    assert hit is not None
    assert len(hit) == 1
    assert hit[0].id == "GHSA-1234-5678-90ab"

    # Set negative cache (no vulnerabilities found)
    cache.set("npm", "clean-pkg", "2.0.0", [])
    empty_hit = cache.get("npm", "clean-pkg", "2.0.0")
    assert empty_hit is not None
    assert len(empty_hit) == 0  # Confirmed clean package cached

    # Expiry test via time.time
    current_time = time.time()
    with patch("time.time", return_value=current_time + 10):
        assert cache.get(q.package.ecosystem, q.package.name, q.version) is None

    # Clear test
    cache.clear()
    assert cache.size() == 0


# =====================================================================
# 3. OSV Client Tests (Mocked HTTP)
# =====================================================================

@pytest.mark.asyncio
async def test_client_batch_query_success():
    settings = Settings(
        SESSION_SECRET="test_session_secret_that_is_at_least_32_chars_long!",
        OSV_API_BASE_URL="http://osv.test",
        OSV_API_TIMEOUT_SECONDS=5.0,
    )

    mock_response_data = {
        "results": [
            {"vulns": [SAMPLE_VULN_DICT]},
            {},  # clean
        ]
    }

    mock_response = httpx.Response(
        status_code=200,
        json=mock_response_data,
        request=httpx.Request("POST", "http://osv.test/v1/querybatch"),
    )

    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_response)

    client = OsvClient(settings, http_client=mock_http_client)

    queries = [
        OsvQuery(package=OsvPackage(name="sample-pkg", ecosystem="npm"), version="1.0.0"),
        OsvQuery(package=OsvPackage(name="clean-pkg", ecosystem="npm"), version="2.0.0"),
    ]
    results_map, failed_list = await client.query_batch(queries)

    assert len(results_map) == 2
    assert len(failed_list) == 0
    assert len(results_map[queries[0]]) == 1
    assert results_map[queries[0]][0].id == "GHSA-1234-5678-90ab"
    assert len(results_map[queries[1]]) == 0


@pytest.mark.asyncio
async def test_client_retry_and_backoff_on_503():
    settings = Settings(
        SESSION_SECRET="test_session_secret_that_is_at_least_32_chars_long!",
        OSV_API_BASE_URL="http://osv.test",
        OSV_API_MAX_RETRIES=2,
        OSV_API_BACKOFF_BASE_SECONDS=0.01,
    )

    resp_503 = httpx.Response(status_code=503, request=httpx.Request("POST", "http://osv.test/v1/query"))
    resp_200 = httpx.Response(
        status_code=200,
        json={"vulns": [SAMPLE_VULN_DICT]},
        request=httpx.Request("POST", "http://osv.test/v1/query"),
    )

    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(side_effect=[resp_503, resp_200])

    client = OsvClient(settings, http_client=mock_http_client)

    q = OsvQuery(package=OsvPackage(name="sample-pkg", ecosystem="npm"), version="1.0.0")
    vulns = await client.query_single(q)
    assert len(vulns) == 1
    assert mock_http_client.post.call_count == 2


# =====================================================================
# 4. OSV Service Ingestion & Persistence Tests
# =====================================================================

@pytest.mark.asyncio
async def test_service_import_deduplication_and_caching():
    settings = Settings(
        SESSION_SECRET="test_session_secret_that_is_at_least_32_chars_long!",
        OSV_ENABLED=True,
    )
    repo = InMemoryAdvisoryRepository()
    cache = OsvCache(default_ttl_seconds=300)

    # Set up project packages with 2 identical packages (deduplication check) and 1 distinct
    repo.set_project_packages(
        "proj-1",
        [
            PackageVersionItem(id="pv:npm:lod:1.0", name="lod", version="1.0", ecosystem="npm", purl="pkg:npm/lod@1.0"),
            PackageVersionItem(id="pv:npm:lod:1.0", name="lod", version="1.0", ecosystem="npm", purl="pkg:npm/lod@1.0"),
            PackageVersionItem(id="pv:npm:clean:2.0", name="clean", version="2.0", ecosystem="npm", purl="pkg:npm/clean@2.0"),
        ],
    )

    mock_client = AsyncMock()
    vuln = parse_osv_vulnerability(SAMPLE_VULN_DICT, retrieved_at=1700000000)

    q_lod = OsvQuery(package=OsvPackage(name="lod", ecosystem="npm"), version="1.0")
    q_clean = OsvQuery(package=OsvPackage(name="clean", ecosystem="npm"), version="2.0")

    mock_client.query_batch.return_value = ({q_lod: [vuln], q_clean: []}, [])

    service = OsvService(settings=settings, advisory_repo=repo, client=mock_client, cache=cache)

    summary = await service.import_project_advisories("proj-1")

    assert summary.status == "completed"
    assert summary.total_package_versions == 3
    assert summary.eligible_package_versions == 3
    assert summary.unique_lookups == 2  # lod:1.0 and clean:2.0
    assert summary.cache_hits == 0
    assert summary.advisories_found == 1
    assert summary.advisories_created == 1
    assert summary.relationships_created == 1

    # Second run should be 100% cache hits, 0 OSV API calls
    mock_client.query_batch.reset_mock()
    summary2 = await service.import_project_advisories("proj-1")
    assert summary2.cache_hits == 2
    mock_client.query_batch.assert_not_called()


@pytest.mark.asyncio
async def test_service_disabled_osv():
    settings = Settings(
        SESSION_SECRET="test_session_secret_that_is_at_least_32_chars_long!",
        OSV_ENABLED=False,
    )
    service = OsvService(settings=settings)
    summary = await service.import_project_advisories("proj-disabled")
    assert summary.status == "skipped"
    assert summary.advisories_found == 0
    assert "disabled" in summary.errors[0].lower()


@pytest.mark.asyncio
async def test_service_partial_failure_reporting():
    settings = Settings(
        SESSION_SECRET="test_session_secret_that_is_at_least_32_chars_long!",
        OSV_ENABLED=True,
    )
    repo = InMemoryAdvisoryRepository()
    cache = OsvCache(default_ttl_seconds=300)

    repo.set_project_packages(
        "proj-fail",
        [
            PackageVersionItem(id="pv:1", name="ok-pkg", version="1.0", ecosystem="npm", purl=""),
            PackageVersionItem(id="pv:2", name="bad-pkg", version="2.0", ecosystem="npm", purl=""),
        ],
    )

    q_ok = OsvQuery(package=OsvPackage(name="ok-pkg", ecosystem="npm"), version="1.0")
    q_bad = OsvQuery(package=OsvPackage(name="bad-pkg", ecosystem="npm"), version="2.0")
    vuln = parse_osv_vulnerability(SAMPLE_VULN_DICT, retrieved_at=1700000000)

    mock_client = AsyncMock()
    mock_client.query_batch.return_value = ({q_ok: [vuln]}, [(q_bad, "Connection reset")])

    service = OsvService(settings=settings, advisory_repo=repo, client=mock_client, cache=cache)
    summary = await service.import_project_advisories("proj-fail")

    assert summary.status == "partial_failure"
    assert summary.failed_lookups == 1
    assert summary.advisories_found == 1
    assert len(summary.errors) >= 1


# =====================================================================
# 5. HTTP API Endpoint Tests
# =====================================================================

@pytest.mark.asyncio
async def test_advisory_endpoints_auth_required(client: AsyncClient):
    resp = await client.post("/api/projects/proj-123/advisories/import")
    assert resp.status_code == 401

    resp = await client.get("/api/projects/proj-123/advisories")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_advisory_endpoints_project_not_found(client: AsyncClient):
    authenticate_client(client)

    resp = await client.post("/api/projects/non-existent-proj/advisories/import")
    assert resp.status_code == 404

    resp = await client.get("/api/projects/non-existent-proj/advisories")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_advisory_endpoints_full_flow(
    client: AsyncClient,
    mock_advisory_repo: InMemoryAdvisoryRepository,
):
    authenticate_client(client)

    # Create project via API
    res = await client.post(
        "/api/projects",
        json={
            "name": "OSV Integration Project",
            "ecosystem": "npm",
            "description": "Testing OSV workflow",
        },
    )
    assert res.status_code == 201
    project_id = res.json()["id"]

    # Seed package versions
    mock_advisory_repo.set_project_packages(
        project_id,
        [
            PackageVersionItem(id="pv:npm:sample:1.0", name="sample-pkg", version="1.0", ecosystem="npm", purl=""),
        ],
    )

    vuln = parse_osv_vulnerability(SAMPLE_VULN_DICT, retrieved_at=1700000000)

    async def mock_batch(queries, **kwargs):
        return {q: [vuln] for q in queries}, []

    with patch.object(OsvClient, "query_batch", side_effect=mock_batch):
        # Trigger import
        resp = await client.post(f"/api/projects/{project_id}/advisories/import")
        assert resp.status_code == 200
        data = resp.json()
        assert data["project_id"] == project_id
        assert data["advisories_found"] == 1
        assert data["advisories_created"] == 1
        assert data["status"] == "completed"

        # Query GET advisories
        resp_get = await client.get(f"/api/projects/{project_id}/advisories")
        assert resp_get.status_code == 200
        advs = resp_get.json()
        assert len(advs) == 1
        assert advs[0]["id"] == "GHSA-1234-5678-90ab"
        assert advs[0]["package_name"] == "sample-pkg"
        assert advs[0]["severity"] == "CRITICAL"
