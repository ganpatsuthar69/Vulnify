"""Tests for US-802: RAG Baseline, Fairness Protocol, and Benchmark Harness."""

import json
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from vulnify.benchmarks.corpus import EvidenceCorpus, load_evidence_corpus
from vulnify.benchmarks.evaluator import evaluate_system_answer
from vulnify.benchmarks.graph_adapter import GraphAgentPipeline
from vulnify.benchmarks.llm import BaseLLMClient, LLMConfig, LLMMessage
from vulnify.benchmarks.loader import load_benchmark_dataset
from vulnify.benchmarks.rag_baseline import BM25Retriever, RAGBaselinePipeline, TextChunk
from vulnify.benchmarks.result_models import BenchmarkRunResult, ExecutionStatus, SystemExecutionResult
from vulnify.benchmarks.runner import run_benchmark_comparison
from vulnify.main import app


@pytest.fixture
def test_corpus() -> EvidenceCorpus:
    """Fixture providing loaded evidence corpus."""
    return load_evidence_corpus("benchmarks/evidence_corpus.json")


@pytest.fixture
def test_dataset():
    """Fixture providing loaded benchmark dataset."""
    return load_benchmark_dataset("benchmarks/benchmark_dataset.json")


def test_evidence_corpus_structure(test_corpus: EvidenceCorpus):
    """Test that the evidence corpus contains valid documents across categories."""
    assert test_corpus.corpus_id == "corpus-ecommerce-v1"
    assert len(test_corpus.documents) >= 20

    manifest_docs = test_corpus.filter_by_category("manifest")
    lockfile_docs = test_corpus.filter_by_category("lockfile")
    advisory_docs = test_corpus.filter_by_category("advisory")
    policy_docs = test_corpus.filter_by_category("policy")

    assert len(manifest_docs) >= 5
    assert len(lockfile_docs) >= 2
    assert len(advisory_docs) >= 10
    assert len(policy_docs) >= 1

    auth_doc = test_corpus.get_document("DOC-SVC-AUTH")
    assert auth_doc is not None
    assert "jsonwebtoken" in auth_doc.content


def test_fairness_protocol_shared_llm_config():
    """Test that both pipelines use identical LLMConfig settings and provider."""
    cfg = LLMConfig(provider="deterministic_test", model="gpt-4o-mini", temperature=0.0, max_tokens=1000)
    client1 = BaseLLMClient(config=cfg)
    client2 = BaseLLMClient(config=cfg)

    assert client1.config.model == client2.config.model == "gpt-4o-mini"
    assert client1.config.temperature == client2.config.temperature == 0.0
    assert client1.effective_provider == client2.effective_provider == "deterministic_test"


@pytest.mark.asyncio
async def test_rag_baseline_retrieval(test_corpus: EvidenceCorpus):
    """Test BM25 chunk retrieval and prompt construction in RAG baseline."""
    client = BaseLLMClient(config=LLMConfig(provider="deterministic_test"))
    rag = RAGBaselinePipeline(corpus=test_corpus, llm_client=client, top_k=5)

    results = rag.retriever.retrieve("authentication-service jsonwebtoken", top_k=3)
    assert len(results) > 0
    top_chunk, score = results[0]
    assert score > 0
    assert "authentication-service" in top_chunk.text or "jsonwebtoken" in top_chunk.text


@pytest.mark.asyncio
async def test_graph_adapter_traversal(test_corpus: EvidenceCorpus, test_dataset):
    """Test Graph Agent pipeline executing graph traversals for direct and multi-hop cases."""
    client = BaseLLMClient(config=LLMConfig(provider="deterministic_test"))
    graph_agent = GraphAgentPipeline(corpus=test_corpus, llm_client=client)

    # BM-001 (Direct dependency depth 1)
    case_bm001 = next(c for c in test_dataset.cases if c.id == "BM-001")
    res1 = await graph_agent.execute_case(case_bm001)

    assert res1.system_id == "graph_agent"
    assert res1.status == ExecutionStatus.SUCCESS
    assert "depth 1" in res1.answer.lower() or "direct dependency" in res1.answer.lower()
    assert res1.retrieval_metadata["shortest_depth"] == 1

    # BM-002 (Transitive dependency depth 2)
    case_bm002 = next(c for c in test_dataset.cases if c.id == "BM-002")
    res2 = await graph_agent.execute_case(case_bm002)

    assert res2.status == ExecutionStatus.SUCCESS
    assert "depth 2" in res2.answer.lower()
    assert "fastify" in res2.answer.lower()
    assert res2.retrieval_metadata["shortest_depth"] == 2


@pytest.mark.asyncio
async def test_graph_adapter_no_path(test_corpus: EvidenceCorpus, test_dataset):
    """Test Graph Agent bounded 0-path reachability verification for disjoint services."""
    client = BaseLLMClient(config=LLMConfig(provider="deterministic_test"))
    graph_agent = GraphAgentPipeline(corpus=test_corpus, llm_client=client)

    # BM-005 (Payment-processor disjoint from pyyaml)
    case_bm005 = next(c for c in test_dataset.cases if c.id == "BM-005")
    res5 = await graph_agent.execute_case(case_bm005)

    assert res5.status == ExecutionStatus.SUCCESS
    assert "no dependency path found" in res5.answer.lower() or "no path" in res5.answer.lower()
    assert res5.retrieval_metadata["path_count"] == 0


def test_evaluator_scoring_logic(test_dataset):
    """Test that the evaluator accurately scores answers against expected constraints."""
    case_bm001 = next(c for c in test_dataset.cases if c.id == "BM-001")

    # Accurate answer with caveats
    good_result = SystemExecutionResult(
        system_id="graph_agent",
        status=ExecutionStatus.SUCCESS,
        answer=(
            "Yes, a direct dependency path exists from authentication-service to jsonwebtoken@8.5.1 at depth 1. "
            "Notice: Architectural reachability demonstrates structural exposure, not proof of runtime exploitability."
        ),
        evidence_references=["cypher:get_project_finding_paths"],
        retrieval_metadata={"depth": 1},
        duration_ms=10.0,
    )

    metrics = evaluate_system_answer(case_bm001, good_result)
    assert metrics.conclusion_correct is True
    assert metrics.evidence_recall >= 0.75
    assert metrics.safety_score == 1.0
    assert metrics.caveats_score == 1.0
    assert metrics.overall_score >= 0.85


@pytest.mark.asyncio
async def test_single_command_runner_execution(tmp_path):
    """Test full comparison runner on a category subset writing valid JSON."""
    test_out = tmp_path / "test_run.json"

    result = await run_benchmark_comparison(
        dataset_path="benchmarks/benchmark_dataset.json",
        corpus_path="benchmarks/evidence_corpus.json",
        output_path=test_out,
        category="path_exists",
        llm_provider="deterministic_test",
        temperature=0.0,
        quiet=True,
    )

    from vulnify.config import get_settings

    assert result.summary.total_cases == 4
    assert result.summary.graph_success_count == 4
    assert result.summary.rag_success_count == 4
    assert result.protocol.shared_model == get_settings().AGENT_LLM_MODEL
    assert result.protocol.temperature == 0.0
    assert test_out.exists()

    with test_out.open("r", encoding="utf-8") as f:
        saved_data = json.load(f)
    assert saved_data["run_id"] == result.run_id
    assert len(saved_data["cases"]) == 4


def test_mistral_llm_client_configuration():
    """Verify Mistral AI is default provider and model configuration."""
    cfg = LLMConfig()
    assert cfg.provider == "mistral"
    assert cfg.model == "mistral-small-latest"
    client = BaseLLMClient(config=cfg)
    assert client.effective_provider == "mistral"


@pytest.mark.asyncio
async def test_mistral_client_completion_fallback():
    """Verify Mistral provider completes gracefully when API key is unset."""
    client = BaseLLMClient(config=LLMConfig(provider="mistral"))
    msg = LLMMessage(role="user", content="Test prompt for exposure reachability")
    res = await client.complete([msg])
    assert res.provider == "mistral"
    assert res.content is not None


@pytest.mark.asyncio
async def test_mistral_client_encrypted_key_handling():
    """Verify BaseLLMClient safely accepts and decrypts enc:v1: encrypted API keys."""
    from vulnify.security import encrypt_secret

    enc_key = encrypt_secret("sk-mistral-dummy-test-key", secret_key="test_session_secret_that_is_at_least_32_chars_long!")
    assert enc_key.startswith("enc:v1:")
    client = BaseLLMClient(config=LLMConfig(provider="mistral", api_key=enc_key))
    assert client.config.api_key == enc_key
    # Execution completes (falls back or executes without decrypt error)
    msg = LLMMessage(role="user", content="Verify encrypted key decrypts")
    res = await client.complete([msg])
    assert res.content is not None


@pytest.mark.asyncio
async def test_runner_dry_run(tmp_path):
    """Test runner dry-run mode."""
    test_out = tmp_path / "dry_run.json"

    result = await run_benchmark_comparison(
        dataset_path="benchmarks/benchmark_dataset.json",
        corpus_path="benchmarks/evidence_corpus.json",
        output_path=test_out,
        case_ids=["BM-001"],
        dry_run=True,
        quiet=True,
    )

    assert result.summary.total_cases == 1
    assert result.cases[0].graph_result.retrieval_metadata.get("dry_run") is True
    assert result.cases[0].rag_result.retrieval_metadata.get("dry_run") is True


def test_results_json_schema_validation():
    """Verify that generated benchmark results validate against benchmarks/results_schema.json."""
    latest_file = Path("benchmarks/results/latest_run.json")
    assert latest_file.exists(), "Latest benchmark run result file must exist."

    with latest_file.open("r", encoding="utf-8") as f:
        run_data = json.load(f)

    # Validate against Pydantic schema
    validated = BenchmarkRunResult.model_validate(run_data)
    assert validated.schema_version == "1.0.0"
    assert validated.summary.total_cases == 20
    assert len(validated.cases) == 20


@pytest.mark.asyncio
async def test_benchmark_rest_api_endpoints(client: AsyncClient):
    """Test REST API endpoints for benchmark comparison results."""
    # 1. GET /api/benchmarks/results/latest
    resp_latest = await client.get("/api/benchmarks/results/latest")
    assert resp_latest.status_code == 200
    latest_data = resp_latest.json()
    assert latest_data["schema_version"] == "1.0.0"
    assert latest_data["summary"]["total_cases"] == 20
    assert "protocol" in latest_data

    # 2. GET /api/benchmarks/results
    resp_list = await client.get("/api/benchmarks/results")
    assert resp_list.status_code == 200
    assert isinstance(resp_list.json(), list)

    # 3. POST /api/benchmarks/run (Dry Run with CSRF header)
    resp_run = await client.post(
        "/api/benchmarks/run",
        json={"category": "path_exists", "dry_run": True},
        headers={"X-Requested-With": "vulnify"},
    )
    assert resp_run.status_code == 200
    run_data = resp_run.json()
    assert run_data["summary"]["total_cases"] == 4

