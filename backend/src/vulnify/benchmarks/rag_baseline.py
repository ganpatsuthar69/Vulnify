"""RAG Baseline Retrieval and Answer Generation Pipeline (US-802).

Implements a standard Retrieval-Augmented Generation baseline over the shared
evidence corpus (benchmarks/evidence_corpus.json).

Fairness properties:
- Ingests the exact same documents and raw evidence as the Vulnify Graph Agent.
- Uses the exact same language model client and sampling parameters (temperature=0.0).
- Applies standard token-matching / BM25 lexical chunk retrieval without graph topology.
"""

from collections import Counter
import math
import re
import time
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from vulnify.benchmarks.corpus import CorpusDocument, EvidenceCorpus
from vulnify.benchmarks.llm import BaseLLMClient, LLMMessage
from vulnify.benchmarks.models import BenchmarkCase
from vulnify.benchmarks.result_models import ExecutionStatus, SystemExecutionResult


class TextChunk(BaseModel):
    """An individual indexed text chunk derived from an evidence document."""

    model_config = ConfigDict(extra="forbid")

    chunk_id: str
    doc_id: str
    category: str
    title: str
    text: str
    tokens: list[str] = Field(default_factory=list)


def tokenize(text: str) -> list[str]:
    """Tokenize text into lowercase alphanumeric terms."""
    return re.findall(r"\b[a-zA-Z0-9_\-@\.]+\b", text.lower())


class BM25Retriever:
    """BM25 ranking retriever over corpus chunks."""

    def __init__(self, chunks: list[TextChunk], k1: float = 1.5, b: float = 0.75) -> None:
        self.chunks = chunks
        self.k1 = k1
        self.b = b
        self.doc_count = len(chunks)
        self.doc_lengths = [len(c.tokens) for c in chunks]
        self.avg_doc_len = sum(self.doc_lengths) / max(1, self.doc_count)

        # Term document frequency
        self.df: dict[str, int] = Counter()
        for c in chunks:
            unique_terms = set(c.tokens)
            for term in unique_terms:
                self.df[term] += 1

    def retrieve(self, query: str, top_k: int = 5) -> list[tuple[TextChunk, float]]:
        """Score and return the top-k scoring chunks for a query string."""
        query_terms = tokenize(query)
        if not query_terms:
            return [(c, 0.0) for c in self.chunks[:top_k]]

        scores: list[float] = []
        for idx, chunk in enumerate(self.chunks):
            doc_len = self.doc_lengths[idx]
            tf = Counter(chunk.tokens)
            score = 0.0
            for term in query_terms:
                if term not in tf:
                    continue
                doc_freq = self.df.get(term, 0)
                # BM25 IDF formula
                idf = math.log((self.doc_count - doc_freq + 0.5) / (doc_freq + 0.5) + 1.0)
                freq = tf[term]
                numerator = freq * (self.k1 + 1)
                denominator = freq + self.k1 * (1 - self.b + self.b * (doc_len / max(1.0, self.avg_doc_len)))
                score += idf * (numerator / max(1e-6, denominator))
            scores.append(score)

        # Sort descending by score
        indexed_scores = list(enumerate(scores))
        indexed_scores.sort(key=lambda x: x[1], reverse=True)
        return [(self.chunks[i], round(s, 4)) for i, s in indexed_scores[:top_k]]


class RAGBaselinePipeline:
    """Fair RAG baseline pipeline executing against shared evidence and shared LLM."""

    def __init__(
        self,
        corpus: EvidenceCorpus,
        llm_client: BaseLLMClient,
        top_k: int = 5,
    ) -> None:
        self.corpus = corpus
        self.llm_client = llm_client
        self.top_k = top_k
        self.chunks = self._build_chunks(corpus)
        self.retriever = BM25Retriever(self.chunks)

    def _build_chunks(self, corpus: EvidenceCorpus) -> list[TextChunk]:
        """Convert evidence documents into indexed text chunks."""
        chunks: list[TextChunk] = []
        for doc in corpus.documents:
            # We index each document as a structured chunk
            tokens = tokenize(f"{doc.title} {doc.content}")
            chunks.append(
                TextChunk(
                    chunk_id=f"chunk-{doc.id}",
                    doc_id=doc.id,
                    category=doc.category,
                    title=doc.title,
                    text=f"### {doc.title} [{doc.category}]\n{doc.content}",
                    tokens=tokens,
                )
            )
        return chunks

    def build_prompt(self, case: BenchmarkCase, retrieved: list[tuple[TextChunk, float]]) -> list[LLMMessage]:
        """Construct the prompt using only retrieved context text chunks."""
        context_blocks = []
        for chunk, score in retrieved:
            context_blocks.append(
                f"[Chunk: {chunk.doc_id} | Score: {score:.2f} | Category: {chunk.category}]\n{chunk.text}"
            )
        joined_context = "\n\n".join(context_blocks)

        system_msg = (
            "You are a security vulnerability analysis assistant. "
            "You answer questions based strictly on the provided retrieved context documents. "
            "Report exposure, not proof of runtime exploitability. "
            "Do not fabricate paths, versions, or claims not present in the context."
        )

        user_msg = (
            f"Case: {case.id}\n"
            f"Question: {case.question}\n"
            f"Project: {case.project_id}\n\n"
            f"=== RETRIEVED CONTEXT (Top-{len(retrieved)}) ===\n"
            f"{joined_context}\n\n"
            f"=== INSTRUCTION ===\n"
            f"Answer the question concisely based only on the retrieved context above. "
            f"State clearly if a path exists or if evidence is insufficient."
        )

        return [
            LLMMessage(role="system", content=system_msg),
            LLMMessage(role="user", content=user_msg),
        ]

    async def execute_case(self, case: BenchmarkCase) -> SystemExecutionResult:
        """Execute RAG retrieval and generation for a single benchmark case."""
        start = time.perf_counter()
        try:
            # 1. Retrieve top-k chunks matching the question and entity identifiers
            query_text = (
                f"{case.question} "
                f"{case.service_name or ''} "
                f"{case.package_name or ''} "
                f"{case.advisory_id or ''}"
            )
            retrieved = self.retriever.retrieve(query_text, top_k=self.top_k)
            retrieved_doc_ids = [c.doc_id for c, _ in retrieved]

            # 2. Build prompt with retrieved context
            messages = self.build_prompt(case, retrieved)

            # 3. Call shared LLM
            llm_result = await self.llm_client.complete(messages)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            return SystemExecutionResult(
                system_id="rag_baseline",
                status=ExecutionStatus.SUCCESS,
                answer=llm_result.content,
                evidence_references=retrieved_doc_ids,
                retrieval_metadata={
                    "retrieval_strategy": "bm25_text_chunks",
                    "top_k": self.top_k,
                    "retrieved_count": len(retrieved),
                    "retrieved_chunks": [
                        {"doc_id": c.doc_id, "score": s, "category": c.category} for c, s in retrieved
                    ],
                },
                duration_ms=elapsed_ms,
                tokens_used=(
                    (llm_result.prompt_tokens or 0) + (llm_result.completion_tokens or 0)
                    if llm_result.prompt_tokens is not None
                    else None
                ),
                error_message=None,
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return SystemExecutionResult(
                system_id="rag_baseline",
                status=ExecutionStatus.FAILED,
                answer="Error during RAG baseline execution.",
                evidence_references=[],
                retrieval_metadata={"error": str(exc)},
                duration_ms=elapsed_ms,
                tokens_used=None,
                error_message=str(exc),
            )
