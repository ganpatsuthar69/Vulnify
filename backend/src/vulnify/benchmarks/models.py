"""Pydantic data models for Vulnify Benchmark Question Set (US-801).

Implements strict validation for:
- 5 official benchmark categories (path_exists, no_path, exposure, ranking, remediation).
- Structured expected answers with evidence requirements, forbidden claims, and mandatory caveats.
- Independent verification records citing queries, tools, and provenance.
- Two-person human reviewer records capturing review status and verification notes.
"""

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class BenchmarkCategory(str, Enum):
    """The 5 official benchmark categories defined in US-801."""

    PATH_EXISTS = "path_exists"
    NO_PATH = "no_path"
    EXPOSURE = "exposure"
    RANKING = "ranking"
    REMEDIATION = "remediation"


class DifficultyLevel(str, Enum):
    """Benchmark case difficulty level."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class VerificationStatus(str, Enum):
    """Ground truth evidence verification state."""

    VERIFIED = "verified"
    PENDING = "pending"
    BLOCKED = "blocked"


class ReviewStatus(str, Enum):
    """Review outcome for a single reviewer."""

    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    PENDING = "pending"
    BLOCKED = "blocked"


class ExpectedAnswer(BaseModel):
    """Structured representation of verified expected answer criteria."""

    model_config = ConfigDict(extra="forbid")

    conclusion: str = Field(..., min_length=5, description="Core concise answer conclusion.")
    explanation: str = Field(..., min_length=20, description="Detailed reasoning and architectural explanation.")
    required_evidence: list[str] = Field(..., min_length=1, description="Specific factual evidence required (paths, depths, reasons).")
    forbidden_claims: list[str] = Field(..., min_length=1, description="Incorrect or hallucinatory statements that must not appear.")
    required_caveats: list[str] = Field(default_factory=list, description="Mandatory safety or uncertainty caveats (e.g. exposure != exploitability).")


class VerificationRecord(BaseModel):
    """Ground truth verification provenance and method."""

    model_config = ConfigDict(extra="forbid")

    status: VerificationStatus = Field(..., description="Verification state of this expected answer.")
    method: str = Field(..., min_length=3, description="Evaluation method (e.g. graph_traversal_query, scoring_policy_v1.0.0).")
    query_or_tool: str = Field(..., min_length=3, description="Underlying query ID or registered tool name used to verify ground truth.")
    evidence_provenance: str = Field(..., min_length=3, description="Data provenance (e.g. synthetic_fixture, service_manifest, osv_advisory).")
    verified_at: str = Field(..., description="ISO 8601 timestamp of verification.")
    verification_notes: str = Field(..., min_length=10, description="Technical rationale verifying accuracy against project data.")


class ReviewRecord(BaseModel):
    """Record of an independent human review for a benchmark answer (AC2)."""

    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(..., min_length=3, description="Unique, stable identifier for the reviewer.")
    role: str = Field(..., min_length=3, description="Technical role of the reviewer (e.g. Security Graph Architect).")
    status: ReviewStatus = Field(..., description="Outcome of the review.")
    reviewed_at: str = Field(..., description="ISO 8601 timestamp of review.")
    dataset_version: str = Field(..., description="Dataset version reviewed (e.g. 1.0.0).")
    notes: str = Field(..., min_length=5, description="Reviewer comments confirming verification of ground truth evidence.")


class BenchmarkCase(BaseModel):
    """A single hand-verified benchmark question and answer specification."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=r"^BM-\d{3}$", description="Stable benchmark case ID (e.g. BM-001).")
    title: str = Field(..., min_length=5, description="Short human-readable title.")
    category: BenchmarkCategory = Field(..., description="Official benchmark category.")
    difficulty: DifficultyLevel = Field(..., description="Difficulty rating.")
    question: str = Field(..., min_length=10, description="Natural language question to pose to the agent.")
    project_id: str = Field(..., min_length=3, description="Target project ID in the graph or fixture.")
    service_name: str | None = Field(default=None, description="Target service name if applicable.")
    package_name: str | None = Field(default=None, description="Target package name if applicable.")
    package_version: str | None = Field(default=None, description="Target package version if applicable.")
    advisory_id: str | None = Field(default=None, description="Target advisory ID if applicable.")
    expected_answer: ExpectedAnswer = Field(..., description="Structured expected answer and validation criteria.")
    verification: VerificationRecord = Field(..., description="Evidence verification metadata.")
    reviews: list[ReviewRecord] = Field(..., min_length=2, max_length=2, description="Exactly two independent reviewer records (AC2).")


class BenchmarkDataset(BaseModel):
    """Top-level container for the version-controlled benchmark dataset."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Schema version.")
    dataset_version: str = Field(default="1.0.0", description="Dataset semantic version.")
    dataset_title: str = Field(..., min_length=5, description="Dataset title.")
    description: str = Field(..., min_length=10, description="Overview and purpose.")
    created_at: str = Field(..., description="Creation ISO timestamp.")
    updated_at: str = Field(..., description="Last update ISO timestamp.")
    cases: list[BenchmarkCase] = Field(..., min_length=1, description="List of benchmark cases.")


class CoverageSummary(BaseModel):
    """Computed distribution metrics across the benchmark dataset."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    by_category: dict[str, int]
    by_difficulty: dict[str, int]
    verified_count: int
    pending_verification_count: int
    blocked_verification_count: int


class ReviewSummary(BaseModel):
    """Computed review progress metrics across the benchmark dataset."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    fully_approved_count: int
    pending_first_review_count: int
    pending_second_review_count: int
    changes_requested_count: int
    blocked_count: int
    reviewer_counts: dict[str, int]
