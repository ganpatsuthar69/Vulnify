"""Comprehensive automated regression tests for Multi-Project Data Isolation.

Scenarios verified:
- Scenario A: Project switching (isolated services, dependencies, and findings).
- Scenario B: API isolation (read/update operations scoped strictly to project).
- Scenario C: Multi-user authorization & project scoping (403 for unauthorized project access).
- Scenario D: Cache & state isolation (no cross-project leakage in findings and summary metrics).
- Scenario E: Data integrity & cross-project mutation resistance (changes in Project A never affect Project B).
"""

import time
import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_USER, authenticate_client
from vulnify.graph.project_repository import InMemoryProjectRepository
from vulnify.graph.user_repository import InMemoryUserRepository, UserRecord
from vulnify.graph.vulnerability_repository import InMemoryVulnerabilityRepository
from vulnify.models import IngestionJobRecord, JobStatus, JobType
from vulnify.security import create_session_jwt
from vulnify.dependencies import COOKIE_SESSION_NAME

USER_ALICE = {
    "id": "alice-user-uuid",
    "name": "Alice Developer",
    "email": "alice@example.com",
    "role": "user",
}

USER_BOB = {
    "id": "bob-user-uuid",
    "name": "Bob Analyst",
    "email": "bob@example.com",
    "role": "user",
}


def authenticate_user(client: AsyncClient, user_data: dict[str, str], secret: str) -> None:
    token = create_session_jwt(
        user_id=user_data["id"],
        email=user_data["email"],
        role=user_data["role"],
        secret=secret,
        ttl_minutes=480,
    )
    client.cookies.set(COOKIE_SESSION_NAME, token)


@pytest.fixture(autouse=True)
def setup_users(mock_user_repo: InMemoryUserRepository) -> None:
    mock_user_repo.create_user(
        email=ADMIN_USER["email"],
        name=ADMIN_USER["name"],
        password_hash="mock_hash",
        role=ADMIN_USER["role"],
    )
    user_admin = mock_user_repo.get_by_email(ADMIN_USER["email"])
    if user_admin:
        user_admin.id = ADMIN_USER["id"]
        mock_user_repo._users_by_id[ADMIN_USER["id"]] = user_admin

    mock_user_repo.create_user(
        email=USER_ALICE["email"],
        name=USER_ALICE["name"],
        password_hash="mock_hash",
        role=USER_ALICE["role"],
    )
    user_alice = mock_user_repo.get_by_email(USER_ALICE["email"])
    if user_alice:
        user_alice.id = USER_ALICE["id"]
        mock_user_repo._users_by_id[USER_ALICE["id"]] = user_alice

    mock_user_repo.create_user(
        email=USER_BOB["email"],
        name=USER_BOB["name"],
        password_hash="mock_hash",
        role=USER_BOB["role"],
    )
    user_bob = mock_user_repo.get_by_email(USER_BOB["email"])
    if user_bob:
        user_bob.id = USER_BOB["id"]
        mock_user_repo._users_by_id[USER_BOB["id"]] = user_bob


# ==============================================================================
# Scenario A: Project switching (Distinct records per project)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_a_project_switching_isolates_records(
    client: AsyncClient,
    mock_project_repo: InMemoryProjectRepository,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Project A and Project B have distinct records. Switching displays only the active project's data."""
    authenticate_client(client, ADMIN_USER)

    # 1. Create Project A and Project B
    res_a = await client.post("/api/projects", json={"name": "Project Alpha", "ecosystem": "npm"})
    assert res_a.status_code == 201
    proj_a_id = res_a.json()["id"]

    res_b = await client.post("/api/projects", json={"name": "Project Beta", "ecosystem": "npm"})
    assert res_b.status_code == 201
    proj_b_id = res_b.json()["id"]

    # 2. Add distinct services to each project
    mock_vuln_repo.services[proj_a_id] = [
        {
            "id": f"{proj_a_id}:alpha-service",
            "name": "alpha-service",
            "project_id": proj_a_id,
            "internet_facing": True,
        }
    ]
    mock_vuln_repo.services[proj_b_id] = [
        {
            "id": f"{proj_b_id}:beta-service",
            "name": "beta-service",
            "project_id": proj_b_id,
            "internet_facing": False,
        }
    ]

    # 3. Add distinct findings override for each project
    mock_vuln_repo.findings_override[proj_a_id] = [
        {
            "id": "finding-alpha-1",
            "project_id": proj_a_id,
            "service_id": f"{proj_a_id}:alpha-service",
            "service_name": "alpha-service",
            "advisory_id": "GHSA-alpha-1111",
            "advisory_summary": "ReDoS in alpha-pkg",
            "severity": "HIGH",
            "package_version_id": "npm:alpha-pkg@1.0.0",
            "package_name": "alpha-pkg",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "priority": "High",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
        }
    ]

    mock_vuln_repo.findings_override[proj_b_id] = [
        {
            "id": "finding-beta-1",
            "project_id": proj_b_id,
            "service_id": f"{proj_b_id}:beta-service",
            "service_name": "beta-service",
            "advisory_id": "GHSA-beta-2222",
            "advisory_summary": "RCE in beta-pkg",
            "severity": "CRITICAL",
            "package_version_id": "npm:beta-pkg@2.0.0",
            "package_name": "beta-pkg",
            "package_version": "2.0.0",
            "ecosystem": "npm",
            "priority": "Highest",
            "status": "open",
            "path_depth": 2,
            "path_status": "path_found",
        }
    ]

    # 4. Query Project A services and findings
    services_a_res = await client.get(f"/api/projects/{proj_a_id}/services")
    assert services_a_res.status_code == 200
    services_a = services_a_res.json()
    assert len(services_a) == 1
    assert services_a[0]["name"] == "alpha-service"

    findings_a_res = await client.get(f"/api/projects/{proj_a_id}/findings")
    assert findings_a_res.status_code == 200
    findings_a = findings_a_res.json()["items"]
    assert len(findings_a) == 1
    assert findings_a[0]["advisory_id"] == "GHSA-alpha-1111"
    assert findings_a[0]["package_name"] == "alpha-pkg"

    # 5. Switch to Project B and verify Project A's records do not appear
    services_b_res = await client.get(f"/api/projects/{proj_b_id}/services")
    assert services_b_res.status_code == 200
    services_b = services_b_res.json()
    assert len(services_b) == 1
    assert services_b[0]["name"] == "beta-service"

    findings_b_res = await client.get(f"/api/projects/{proj_b_id}/findings")
    assert findings_b_res.status_code == 200
    findings_b = findings_b_res.json()["items"]
    assert len(findings_b) == 1
    assert findings_b[0]["advisory_id"] == "GHSA-beta-2222"
    assert findings_b[0]["package_name"] == "beta-pkg"

    # 6. Switch back to Project A and verify only Project A's records appear
    findings_a_again = (await client.get(f"/api/projects/{proj_a_id}/findings")).json()["items"]
    assert len(findings_a_again) == 1
    assert findings_a_again[0]["advisory_id"] == "GHSA-alpha-1111"


# ==============================================================================
# Scenario B: API isolation & Cross-Project Triage Decision Immunity
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_b_triage_decision_isolation(
    client: AsyncClient,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Updating triage decision on a finding in Project A does NOT alter Project B's triage status."""
    authenticate_client(client, ADMIN_USER)

    # 1. Create Project A and Project B
    proj_a = (await client.post("/api/projects", json={"name": "Project A", "ecosystem": "npm"})).json()
    proj_b = (await client.post("/api/projects", json={"name": "Project B", "ecosystem": "npm"})).json()
    proj_a_id = proj_a["id"]
    proj_b_id = proj_b["id"]

    # 2. Both projects share a finding for the same vulnerable package
    shared_advisory_id = "GHSA-shared-vuln"
    shared_pv_id = "npm:shared-lib@1.0.0"

    mock_vuln_repo.findings_override[proj_a_id] = [
        {
            "id": f"finding-{proj_a_id}-1",
            "project_id": proj_a_id,
            "service_id": f"{proj_a_id}:svc",
            "service_name": "svc",
            "advisory_id": shared_advisory_id,
            "advisory_summary": "Shared vulnerability in library",
            "severity": "HIGH",
            "package_version_id": shared_pv_id,
            "package_name": "shared-lib",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "priority": "High",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
        }
    ]

    mock_vuln_repo.findings_override[proj_b_id] = [
        {
            "id": f"finding-{proj_b_id}-1",
            "project_id": proj_b_id,
            "service_id": f"{proj_b_id}:svc",
            "service_name": "svc",
            "advisory_id": shared_advisory_id,
            "advisory_summary": "Shared vulnerability in library",
            "severity": "HIGH",
            "package_version_id": shared_pv_id,
            "package_name": "shared-lib",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "priority": "High",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
        }
    ]

    # Verify initial status in both projects is 'open'
    f_a_initial = (await client.get(f"/api/projects/{proj_a_id}/findings")).json()["items"][0]
    f_b_initial = (await client.get(f"/api/projects/{proj_b_id}/findings")).json()["items"][0]
    assert f_a_initial["status"] == "open"
    assert f_b_initial["status"] == "open"

    # 3. Record triage decision in Project A marking as 'not_affected'
    decision_payload = {
        "status": "not_affected",
        "justification": "Input sanitized by custom middleware in Project A.",
    }
    dec_res = await client.post(
        f"/api/projects/{proj_a_id}/findings/{f_a_initial['id']}/decision",
        json=decision_payload,
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["status"] == "not_affected"

    # 4. Verify Project A finding is now 'not_affected'
    f_a_updated = (await client.get(f"/api/projects/{proj_a_id}/findings/{f_a_initial['id']}")).json()
    assert f_a_updated["status"] == "not_affected"
    assert f_a_updated["triage_justification"] == "Input sanitized by custom middleware in Project A."

    # 5. Verify Project B finding is STILL 'open' and has NO justification from Project A
    f_b_after = (await client.get(f"/api/projects/{proj_b_id}/findings/{f_b_initial['id']}")).json()
    assert f_b_after["status"] == "open"
    assert f_b_after.get("triage_justification") is None


# ==============================================================================
# Scenario C: Multi-User Authorization & Access Control
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_c_user_authorization_and_project_scoping(
    client: AsyncClient,
    test_settings,
) -> None:
    """Non-admin User 2 cannot access or mutate User 1's projects."""
    secret = test_settings.SESSION_SECRET

    # Alice creates Project Alpha
    authenticate_user(client, USER_ALICE, secret)
    alice_create_res = await client.post(
        "/api/projects",
        json={"name": "Alice Private Project", "ecosystem": "npm"},
    )
    assert alice_create_res.status_code == 201
    alice_project_id = alice_create_res.json()["id"]

    # Bob creates Project Beta
    authenticate_user(client, USER_BOB, secret)
    bob_create_res = await client.post(
        "/api/projects",
        json={"name": "Bob Private Project", "ecosystem": "npm"},
    )
    assert bob_create_res.status_code == 201
    bob_project_id = bob_create_res.json()["id"]

    # Bob attempts to read Alice's project by ID -> 403 Forbidden
    bob_get_alice = await client.get(f"/api/projects/{alice_project_id}")
    assert bob_get_alice.status_code == 403
    assert "forbidden" in bob_get_alice.json()["message"].lower()

    # Bob attempts to read Alice's findings -> 403 Forbidden
    bob_get_findings = await client.get(f"/api/projects/{alice_project_id}/findings")
    assert bob_get_findings.status_code == 403

    # Bob attempts to read Alice's services -> 403 Forbidden
    bob_get_services = await client.get(f"/api/projects/{alice_project_id}/services")
    assert bob_get_services.status_code == 403

    # Bob attempts to record a decision on Alice's project -> 403 Forbidden
    bob_post_decision = await client.post(
        f"/api/projects/{alice_project_id}/findings/find-any/decision",
        json={"status": "affected", "justification": None},
    )
    assert bob_post_decision.status_code == 403

    # Bob lists projects -> sees ONLY Bob's project
    bob_list = await client.get("/api/projects")
    assert bob_list.status_code == 200
    bob_projects = bob_list.json()
    assert len(bob_projects) == 1
    assert bob_projects[0]["id"] == bob_project_id

    # Alice lists projects -> sees ONLY Alice's project
    authenticate_user(client, USER_ALICE, secret)
    alice_list = await client.get("/api/projects")
    assert alice_list.status_code == 200
    alice_projects = alice_list.json()
    assert len(alice_projects) == 1
    assert alice_projects[0]["id"] == alice_project_id

    # Admin user lists projects -> sees both projects
    authenticate_client(client, ADMIN_USER)
    admin_list = await client.get("/api/projects")
    assert admin_list.status_code == 200
    admin_projects = admin_list.json()
    ids = [p["id"] for p in admin_projects]
    assert alice_project_id in ids
    assert bob_project_id in ids


# ==============================================================================
# Scenario D: Cache & Metric State Isolation
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_d_summary_metrics_isolation(
    client: AsyncClient,
    mock_vuln_repo: InMemoryVulnerabilityRepository,
) -> None:
    """Summary metrics (advisory matches, needing decision) are isolated per project."""
    authenticate_client(client, ADMIN_USER)

    proj_1 = (await client.post("/api/projects", json={"name": "Project 1", "ecosystem": "npm"})).json()["id"]
    proj_2 = (await client.post("/api/projects", json={"name": "Project 2", "ecosystem": "npm"})).json()["id"]

    # Project 1 has 3 findings
    mock_vuln_repo.findings_override[proj_1] = [
        {
            "id": f"f1-{i}",
            "project_id": proj_1,
            "service_id": f"{proj_1}:svc",
            "service_name": "svc",
            "advisory_id": f"GHSA-100{i}",
            "severity": "HIGH",
            "package_version_id": f"npm:pkg{i}@1.0.0",
            "package_name": f"pkg{i}",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "priority": "High",
            "status": "open",
            "path_depth": 1,
            "path_status": "path_found",
        }
        for i in range(3)
    ]

    # Project 2 has 1 finding
    mock_vuln_repo.findings_override[proj_2] = [
        {
            "id": "f2-0",
            "project_id": proj_2,
            "service_id": f"{proj_2}:svc",
            "service_name": "svc",
            "advisory_id": "GHSA-2000",
            "severity": "LOW",
            "package_version_id": "npm:pkgX@1.0.0",
            "package_name": "pkgX",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "priority": "Low",
            "status": "fixed",
            "path_depth": 0,
            "path_status": "no_path_found",
        }
    ]

    summary_1 = (await client.get(f"/api/projects/{proj_1}/findings/summary")).json()
    assert summary_1["advisory_matches"] == 3
    assert summary_1["findings_needing_decision"] == 3
    assert summary_1["findings_with_path"] == 3

    summary_2 = (await client.get(f"/api/projects/{proj_2}/findings/summary")).json()
    assert summary_2["advisory_matches"] == 1
    assert summary_2["findings_needing_decision"] == 0
    assert summary_2["findings_with_path"] == 0


# ==============================================================================
# Scenario E: Data Integrity & Ingestion Job Isolation
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_e_ingestion_jobs_data_integrity(
    client: AsyncClient,
    mock_job_repo,
) -> None:
    """Ingestion jobs created for Project A do not appear in or affect Project B."""
    authenticate_client(client, ADMIN_USER)

    proj_a = (await client.post("/api/projects", json={"name": "Job Proj A", "ecosystem": "npm"})).json()["id"]
    proj_b = (await client.post("/api/projects", json={"name": "Job Proj B", "ecosystem": "npm"})).json()["id"]

    job_a = IngestionJobRecord(
        id="job-alpha-123",
        project_id=proj_a,
        job_type=JobType.DEPENDENCY_IMPORT,
        status=JobStatus.SUCCEEDED,
        stage="completed",
        service_name="payment-service",
        processed_items=42,
        created_at=int(time.time()),
    )
    mock_job_repo.upsert_job(job_a)

    # Project A can view the job
    jobs_a_res = await client.get(f"/api/projects/{proj_a}/jobs")
    assert jobs_a_res.status_code == 200
    jobs_a = jobs_a_res.json()["items"]
    assert len(jobs_a) == 1
    assert jobs_a[0]["id"] == "job-alpha-123"

    # Project B jobs list is empty
    jobs_b_res = await client.get(f"/api/projects/{proj_b}/jobs")
    assert jobs_b_res.status_code == 200
    jobs_b = jobs_b_res.json()["items"]
    assert len(jobs_b) == 0

    # Project B cannot access Project A's job by ID
    job_detail_b = await client.get(f"/api/projects/{proj_b}/jobs/{job_a.id}")
    assert job_detail_b.status_code == 404
