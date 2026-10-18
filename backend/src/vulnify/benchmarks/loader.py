"""Dataset loader and serialization utilities for Vulnify benchmarks (US-801)."""

import json
from pathlib import Path
from typing import Union

from vulnify.benchmarks.models import BenchmarkDataset


def get_default_dataset_path() -> Path:
    """Resolve the default location of the version-controlled benchmark dataset."""
    # Start at current file: backend/src/vulnify/benchmarks/loader.py
    # Repo root is 4 levels up: benchmarks/loader.py -> vulnify -> src -> backend -> Vulnify
    current_dir = Path(__file__).resolve().parent
    repo_root = current_dir.parent.parent.parent.parent
    candidate = repo_root / "benchmarks" / "benchmark_dataset.json"
    if candidate.exists():
        return candidate
    # Fallback to local working directory
    cwd_candidate = Path("benchmarks") / "benchmark_dataset.json"
    return cwd_candidate.resolve()


def get_default_schema_path() -> Path:
    """Resolve default location of the benchmark JSON schema."""
    current_dir = Path(__file__).resolve().parent
    repo_root = current_dir.parent.parent.parent.parent
    candidate = repo_root / "benchmarks" / "schema.json"
    if candidate.exists():
        return candidate
    return (Path("benchmarks") / "schema.json").resolve()


def load_benchmark_dataset(path: Union[Path, str, None] = None) -> BenchmarkDataset:
    """Load and validate the benchmark dataset from a JSON file.
    
    Raises:
        FileNotFoundError: If the benchmark dataset file does not exist.
        ValueError: If JSON syntax or schema validation fails.
    """
    file_path = Path(path) if path is not None else get_default_dataset_path()

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
    file_path = Path(path) if path is not None else get_default_dataset_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    json_str = json.dumps(dataset.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    file_path.write_text(json_str, encoding="utf-8")
    return file_path
