"""Pydantic models for US-802 Benchmark Execution Results and Comparison Schema."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ExecutionStatus(str, Enum):
    """Execution status for a single system evaluation on a benchmark case."""

    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class SystemExecutionResult(BaseModel):
    """Execution result for a single system (Graph Agent or RAG Baseline) on one case."""

    model_config = ConfigDict(extra="forbid")

    system_id: str = Field(..., description="Unique system identifier ('graph_agent' or 'rag_baseline').")
    status: ExecutionStatus = Field(..., description="Outcome of the execution.")
    answer: str = Field(..., description="Generated answer text.")
    evidence_references: list[str] = Field(default_factory=list, description="IDs or citations of evidence supplied or used.")
    retrieval_metadata: dict[str, Any] = Field(default_factory=dict, description="Metadata about the retrieval process (e.g. top_k, scores, tool calls).")
    duration_ms: float = Field(..., ge=0, description="Elapsed wall-clock execution time in milliseconds.")
    tokens_used: int | None = Field(default=None, description="Reported token count if available from provider.")
    error_message: str | None = Field(default=None, description="Sanitized error description if execution failed.")


class CaseComparisonResult(BaseModel):
    """Comparative evaluation result for a single benchmark case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Benchmark case ID (e.g. BM-001).")
    category: str = Field(..., description="Benchmark category (path_exists, no_path, exposure, ranking, remediation).")
    difficulty: str = Field(..., description="Case difficulty (easy, medium, hard).")
    question: str = Field(..., description="Benchmark question text.")
    expected_conclusion: str = Field(..., description="Ground truth conclusion from US-801 dataset.")
    graph_result: SystemExecutionResult = Field(..., description="Result from Vulnify Graph-Based Agent.")
    rag_result: SystemExecutionResult = Field(..., description="Result from RAG Baseline.")


class ComparisonProtocol(BaseModel):
    """Detailed record of the shared experimental protocol and configuration."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: str = Field(default="1.0.0", description="Protocol specification version.")
    graph_system_name: str = Field(default="vulnify-graph-agent", description="Graph-based agent pipeline identifier.")
    rag_system_name: str = Field(default="text-rag-baseline", description="RAG baseline pipeline identifier.")
    shared_model: str = Field(..., description="Common LLM model name used by both systems (e.g. gpt-4o-mini).")
    shared_provider: str = Field(..., description="Common LLM provider name (e.g. auto, openai, deterministic_test).")
    temperature: float = Field(default=0.0, description="Common temperature parameter.")
    max_tokens: int = Field(default=1000, description="Maximum token generation limit.")
    retrieval_strategy: str = Field(default="bm25_text_chunks", description="RAG retrieval algorithm.")
    top_k_chunks: int = Field(default=5, description="Number of evidence chunks retrieved by RAG.")


class CategorySummaryMetrics(BaseModel):
    """Per-category aggregated execution metrics."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    graph_success_count: int
    rag_success_count: int
    graph_avg_duration_ms: float
    rag_avg_duration_ms: float


class RunSummary(BaseModel):
    """Overall summary metrics for the benchmark run."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    graph_success_count: int
    rag_success_count: int
    graph_error_count: int
    rag_error_count: int
    graph_avg_duration_ms: float
    rag_avg_duration_ms: float
    by_category: dict[str, CategorySummaryMetrics]


class BenchmarkRunResult(BaseModel):
    """Top-level container for a complete benchmark comparison experiment run (US-802)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0.0", description="Result JSON schema version.")
    run_id: str = Field(..., description="Unique run identifier (e.g. run-20261018-123456).")
    dataset_version: str = Field(..., description="US-801 benchmark dataset version evaluated.")
    corpus_id: str = Field(..., description="Approved evidence corpus snapshot ID.")
    started_at: str = Field(..., description="ISO 8601 start timestamp.")
    completed_at: str = Field(..., description="ISO 8601 completion timestamp.")
    protocol: ComparisonProtocol = Field(..., description="Effective comparison protocol.")
    summary: RunSummary = Field(..., description="Aggregated summary metrics.")
    cases: list[CaseComparisonResult] = Field(..., description="Per-case comparative results.")
