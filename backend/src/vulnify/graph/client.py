"""FalkorDB graph client connection manager and query loader."""

from functools import lru_cache
from pathlib import Path
from typing import Any
from falkordb import FalkorDB

from vulnify.config import Settings, get_settings

QUERIES_DIR = Path(__file__).parent / "queries"


def load_query(filename: str) -> str:
    """Load Cypher query from queries directory."""
    path = QUERIES_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Cypher query file not found: {filename}")
    return path.read_text(encoding="utf-8")


class GraphClient:
    """Manages FalkorDB connection and schema setup."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._db: FalkorDB | None = None
        self._graph = None

    def get_graph(self):
        """Get or initialize the FalkorDB graph instance."""
        if self._graph is None:
            self._db = FalkorDB(
                host=self.settings.FALKORDB_HOST,
                port=self.settings.FALKORDB_PORT,
                password=self.settings.FALKORDB_PASSWORD,
            )
            self._graph = self._db.select_graph(self.settings.FALKORDB_GRAPH)
            self._init_schema()
        return self._graph

    def _init_schema(self) -> None:
        """Create necessary indexes for User and Project lookup properties."""
        try:
            self._graph.query("CREATE INDEX FOR (u:User) ON (u.email)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (u:User) ON (u.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (p:Project) ON (p.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (p:Project) ON (p.normalized_name)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (s:Service) ON (s.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (pv:PackageVersion) ON (pv.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (pv:PackageVersion) ON (pv.name)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (ie:ImportEvent) ON (ie.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (ie:ImportEvent) ON (ie.sha256_hash)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (v:Vulnerability) ON (v.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (ij:IngestionJob) ON (ij.id)")
        except Exception:
            pass
        try:
            self._graph.query("CREATE INDEX FOR (ij:IngestionJob) ON (ij.project_id)")
        except Exception:
            pass


@lru_cache
def get_graph_client() -> GraphClient:
    return GraphClient(get_settings())
