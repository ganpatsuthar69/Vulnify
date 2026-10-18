"""FalkorDB graph client connection manager, query telemetry, and health inspection."""

from functools import lru_cache
from pathlib import Path
import socket
import threading
import time
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
    """Manages FalkorDB connection, schema setup, query metrics, and health inspection."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._db: FalkorDB | None = None
        self._graph = None
        self._lock = threading.Lock()
        self._query_count = 0
        self._success_count = 0
        self._failed_count = 0
        self._timeout_count = 0
        self._total_duration_ms = 0.0

    def get_graph(self):
        """Get or initialize the FalkorDB graph instance with query telemetry instrumentation."""
        if self._graph is None:
            connect_timeout = getattr(self.settings, "FALKORDB_CONNECT_TIMEOUT_SECONDS", 3.0)
            self._db = FalkorDB(
                host=self.settings.FALKORDB_HOST,
                port=self.settings.FALKORDB_PORT,
                password=self.settings.FALKORDB_PASSWORD,
                socket_timeout=connect_timeout,
                socket_connect_timeout=connect_timeout,
            )
            raw_graph = self._db.select_graph(self.settings.FALKORDB_GRAPH)
            self._raw_graph = raw_graph
            self._graph = raw_graph
            self._init_schema()
            self._graph = self._instrument_graph(raw_graph)
        return self._graph

    def _instrument_graph(self, graph_instance: Any) -> Any:
        """Wrap graph.query and graph.ro_query to record duration and success/failure telemetry."""
        orig_query = graph_instance.query
        orig_ro_query = graph_instance.ro_query
        self._raw_ro_query = orig_ro_query

        def instrumented_query(q: str, params: dict[str, object] | None = None, timeout: int | None = None):
            t0 = time.perf_counter()
            with self._lock:
                self._query_count += 1
            try:
                res = orig_query(q, params=params, timeout=timeout)
                duration = (time.perf_counter() - t0) * 1000.0
                with self._lock:
                    self._success_count += 1
                    self._total_duration_ms += duration
                return res
            except Exception as exc:
                is_timeout = isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in str(exc).lower()
                with self._lock:
                    self._failed_count += 1
                    if is_timeout:
                        self._timeout_count += 1
                raise

        def instrumented_ro_query(q: str, params: dict[str, object] | None = None, timeout: int | None = None):
            t0 = time.perf_counter()
            with self._lock:
                self._query_count += 1
            try:
                res = orig_ro_query(q, params=params, timeout=timeout)
                duration = (time.perf_counter() - t0) * 1000.0
                with self._lock:
                    self._success_count += 1
                    self._total_duration_ms += duration
                return res
            except Exception as exc:
                is_timeout = isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in str(exc).lower()
                with self._lock:
                    self._failed_count += 1
                    if is_timeout:
                        self._timeout_count += 1
                raise

        graph_instance.query = instrumented_query
        graph_instance.ro_query = instrumented_ro_query
        return graph_instance

    def reset_metrics(self) -> None:
        """Reset query telemetry counters (primarily used for test isolation)."""
        with self._lock:
            self._query_count = 0
            self._success_count = 0
            self._failed_count = 0
            self._timeout_count = 0
            self._total_duration_ms = 0.0

    def get_query_metrics(self) -> dict[str, Any]:
        """Return a snapshot of aggregated query telemetry."""
        with self._lock:
            avg_latency = (
                round(self._total_duration_ms / self._success_count, 2)
                if self._success_count > 0
                else None
            )
            return {
                "total_queries": self._query_count,
                "successful_queries": self._success_count,
                "failed_queries": self._failed_count,
                "timeout_queries": self._timeout_count,
                "avg_query_latency_ms": avg_latency,
            }

    def check_health(self, timeout_ms: int = 2000) -> dict[str, Any]:
        """Perform a minimal, non-mutating readiness probe against FalkorDB.
        
        Returns real database signals (latency, memory, uptime, connected clients, server version)
        with safe error categorization and secret redaction on failure.
        """
        try:
            self.get_graph()
            probe_func = getattr(self, "_raw_ro_query", self._graph.ro_query)
            t0 = time.perf_counter()
            # Non-mutating read-only lightweight Cypher probe
            probe_func("RETURN 1", timeout=timeout_ms)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            info: dict[str, Any] = {}
            if self._db is not None and hasattr(self._db, "connection"):
                try:
                    info = self._db.connection.info()
                except Exception:
                    pass

            uptime_sec = info.get("uptime_in_seconds")
            uptime = int(uptime_sec) if uptime_sec is not None else None

            connected_clients = info.get("connected_clients")
            clients = int(connected_clients) if connected_clients is not None else None

            used_mem = info.get("used_memory_human")
            redis_ver = info.get("redis_version")

            return {
                "status": "connected",
                "latency_ms": latency_ms,
                "uptime_seconds": uptime,
                "used_memory_human": str(used_mem) if used_mem is not None else None,
                "connected_clients": clients,
                "server_version": str(redis_ver) if redis_ver is not None else None,
                "graph_name": self.settings.FALKORDB_GRAPH,
                "error": None,
            }
        except Exception as exc:
            err_str = str(exc).lower()
            if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in err_str or "timed out" in err_str:
                error_category = "TIMEOUT"
            elif isinstance(exc, ConnectionRefusedError) or "connection refused" in err_str:
                error_category = "CONNECTION_REFUSED"
            elif "auth" in err_str or "password" in err_str:
                error_category = "AUTHENTICATION_FAILED"
            else:
                error_category = "DATABASE_UNAVAILABLE"

            return {
                "status": "disconnected",
                "latency_ms": None,
                "uptime_seconds": None,
                "used_memory_human": None,
                "connected_clients": None,
                "server_version": None,
                "graph_name": self.settings.FALKORDB_GRAPH,
                "error": error_category,
            }

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
