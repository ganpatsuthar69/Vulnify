"""Dataset loader and serialization utilities for Vulnify benchmarks (US-801)."""

import json
from pathlib import Path
from typing import Union

from vulnify.benchmarks.models import BenchmarkDataset


def get_benchmarks_root() -> Path:
    """Resolve benchmarks root directory containing dataset, corpus, and results."""
    current_dir = Path(__file__).resolve().parent
    repo_root = current_dir.parent.parent.parent.parent
    candidate = repo_root / "benchmarks"
    if candidate.exists() and candidate.is_dir():
        return candidate
    cwd_benchmarks = Path.cwd().resolve() / "benchmarks"
    if cwd_benchmarks.exists() and cwd_benchmarks.is_dir():
        return cwd_benchmarks
    for parent in Path.cwd().resolve().parents:
        cand = parent / "benchmarks"
        if cand.exists() and cand.is_dir():
            return cand
    return candidate


def resolve_benchmark_path(path: Union[Path, str, None] = None, default_filename: str = "") -> Path:
    """Resolve a path to a benchmark file or directory across different working directories."""
    benchmarks_root = get_benchmarks_root()
    repo_root = benchmarks_root.parent

    if path is None or str(path).strip() == "":
        return (benchmarks_root / default_filename).resolve() if default_filename else benchmarks_root.resolve()

    p = Path(path)
    if p.is_absolute():
        return p.resolve()

    if p.exists():
        return p.resolve()

    parts = p.parts
    if parts and parts[0] == "benchmarks":
        cand = repo_root / p
        return cand.resolve()

    bench_cand = benchmarks_root / p
    if bench_cand.exists():
        return bench_cand.resolve()

    root_cand = repo_root / p
    if root_cand.exists():
        return root_cand.resolve()

    return bench_cand.resolve()


def get_default_dataset_path() -> Path:
    """Resolve the default location of the version-controlled benchmark dataset."""
    return resolve_benchmark_path(None, "benchmark_dataset.json")


def get_default_schema_path() -> Path:
    """Resolve default location of the benchmark JSON schema."""
    return resolve_benchmark_path(None, "schema.json")


def load_benchmark_dataset(path: Union[Path, str, None] = None) -> BenchmarkDataset:
    """Load and validate the benchmark dataset from a JSON file.
    
    Raises:
        FileNotFoundError: If the benchmark dataset file does not exist.
        ValueError: If JSON syntax or schema validation fails.
    """
    file_path = resolve_benchmark_path(path, "benchmark_dataset.json")

    if not file_path.exists():
        raise FileNotFoundError(f"Benchmark dataset not found at expected path: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        raise ValueError(f"Failed to read benchmark dataset file {file_path}: {e}") from e

    try:
        dataset = BenchmarkDataset.model_validate_json(content)
    except Exception as e:
        raise ValueError(f"Benchmark dataset failed schema validation: {e}") from e

    return dataset


def save_benchmark_dataset(dataset: BenchmarkDataset, path: Union[Path, str, None] = None) -> Path:
    """Serialize and write benchmark dataset with deterministic formatting."""
    file_path = resolve_benchmark_path(path, "benchmark_dataset.json")
    file_path.parent.mkdir(parents=True, exist_ok=True)

    json_str = json.dumps(dataset.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    file_path.write_text(json_str, encoding="utf-8")
    return file_path
