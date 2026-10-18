"""Evidence corpus data model and loader for US-802 fair comparison.

Ensures both Vulnify Graph Agent and RAG Baseline draw from the exact same
underlying repository evidence documents stored in benchmarks/evidence_corpus.json.
"""

import json
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class CorpusDocument(BaseModel):
    """A single document/chunk in the shared benchmark evidence corpus."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique document identifier (e.g. DOC-SVC-AUTH, DOC-ADV-JWT-001).")
    project_id: str = Field(default="proj-ecommerce-core", description="Project identifier.")
    category: Literal["manifest", "lockfile", "advisory", "topology", "policy"] = Field(
        ..., description="Document category."
    )
    title: str = Field(..., description="Human-readable title.")
    content: str = Field(..., description="Full text content of the evidence document.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Structured metadata attributes.")


class EvidenceCorpus(BaseModel):
    """The complete immutable evidence corpus used for benchmark evaluation."""

    model_config = ConfigDict(extra="forbid")

    corpus_id: str = Field(default="corpus-ecommerce-v1", description="Corpus snapshot identifier.")
    dataset_version: str = Field(default="1.0.0", description="Associated US-801 dataset version.")
    created_at: str = Field(default="2026-10-18T10:00:00Z", description="Corpus snapshot timestamp.")
    documents: list[CorpusDocument] = Field(..., description="Collection of evidence documents.")

    def get_document(self, doc_id: str) -> CorpusDocument | None:
        """Lookup a document by ID."""
        for doc in self.documents:
            if doc.id == doc_id:
                return doc
        return None

    def filter_by_category(self, category: str) -> list[CorpusDocument]:
        """Return documents matching a category."""
        return [d for d in self.documents if d.category == category]


def get_default_corpus_path() -> Path:
    """Resolve default path to benchmarks/evidence_corpus.json."""
    from vulnify.benchmarks.loader import resolve_benchmark_path
    return resolve_benchmark_path(None, "evidence_corpus.json")


def save_evidence_corpus(corpus: EvidenceCorpus, output_path: Path | str) -> Path:
    """Save an evidence corpus instance to JSON."""
    from vulnify.benchmarks.loader import resolve_benchmark_path
    path = resolve_benchmark_path(output_path, "evidence_corpus.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(corpus.model_dump(), f, indent=2)
    return path


def load_evidence_corpus(corpus_path: Path | str | None = None) -> EvidenceCorpus:
    """Load the shared benchmark evidence corpus from JSON disk file."""
    from vulnify.benchmarks.loader import resolve_benchmark_path
    target = resolve_benchmark_path(corpus_path, "evidence_corpus.json")

    if not target.exists():
        raise FileNotFoundError(
            f"Evidence corpus file not found at '{target}'. "
            "Please ensure benchmarks/evidence_corpus.json exists."
        )

    with target.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return EvidenceCorpus.model_validate(data)
