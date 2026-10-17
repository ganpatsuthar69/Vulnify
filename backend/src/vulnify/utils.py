"""Shared utility functions across Vulnify backend modules."""

from collections.abc import Iterator
from typing import Any, TypeVar

T = TypeVar("T")


def chunk_sequence(items: list[T], chunk_size: int = 500) -> Iterator[list[T]]:
    """Yield successive chunks of items up to chunk_size."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]
