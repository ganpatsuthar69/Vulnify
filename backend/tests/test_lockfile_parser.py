"""Unit tests for npm lockfile parser covering valid, invalid, scoped, nested, and edge-case inputs."""

import json
import pytest

from vulnify.parsers.models import LockfileParseError
from vulnify.parsers.npm import parse_npm_lockfile


def test_parse_valid_npm_v3_lockfile() -> None:
    content = {
        "name": "sample-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "sample-app",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.18.2",
                },
                "devDependencies": {
                    "jest": "^29.5.0",
                },
            },
            "node_modules/express": {
                "version": "4.18.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                "dependencies": {
                    "accepts": "~1.3.8",
                    "cookie": "0.5.0",
                },
            },
            "node_modules/accepts": {
                "version": "1.3.8",
                "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                "dependencies": {
                    "mime-types": "~2.1.34",
                },
            },
            "node_modules/mime-types": {
                "version": "2.1.34",
                "resolved": "https://registry.npmjs.org/mime-types/-/mime-types-2.1.34.tgz",
            },
            "node_modules/cookie": {
                "version": "0.5.0",
                "resolved": "https://registry.npmjs.org/cookie/-/cookie-0.5.0.tgz",
            },
            "node_modules/jest": {
                "version": "29.5.0",
                "resolved": "https://registry.npmjs.org/jest/-/jest-29.5.0.tgz",
            },
        },
    }

    graph = parse_npm_lockfile(json.dumps(content))
    assert len(graph.packages) == 5  # express, accepts, mime-types, cookie, jest
    pkg_ids = {p.id for p in graph.packages}
    assert "npm:express@4.18.2" in pkg_ids
    assert "npm:accepts@1.3.8" in pkg_ids
    assert "npm:mime-types@2.1.34" in pkg_ids
    assert "npm:cookie@0.5.0" in pkg_ids
    assert "npm:jest@29.5.0" in pkg_ids

    # Direct dependencies of root service
    assert "npm:express@4.18.2" in graph.direct_dependency_ids
    assert "npm:jest@29.5.0" in graph.direct_dependency_ids
    assert "npm:accepts@1.3.8" not in graph.direct_dependency_ids

    # Transitive dependency edges
    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("npm:express@4.18.2", "npm:accepts@1.3.8") in edge_pairs
    assert ("npm:express@4.18.2", "npm:cookie@0.5.0") in edge_pairs
    assert ("npm:accepts@1.3.8", "npm:mime-types@2.1.34") in edge_pairs


def test_parse_scoped_packages() -> None:
    content = {
        "name": "typescript-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "@types/node": "^20.1.0",
                    "@babel/core": "^7.22.0",
                },
            },
            "node_modules/@types/node": {
                "version": "20.1.0",
            },
            "node_modules/@babel/core": {
                "version": "7.22.0",
                "dependencies": {
                    "@babel/generator": "^7.22.0",
                },
            },
            "node_modules/@babel/generator": {
                "version": "7.22.0",
            },
        },
    }

    graph = parse_npm_lockfile(json.dumps(content))
    assert len(graph.packages) == 3
    names = {p.name for p in graph.packages}
    assert "@types/node" in names
    assert "@babel/core" in names
    assert "@babel/generator" in names

    assert "npm:@types/node@20.1.0" in graph.direct_dependency_ids
    assert "npm:@babel/core@7.22.0" in graph.direct_dependency_ids
    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("npm:@babel/core@7.22.0", "npm:@babel/generator@7.22.0") in edge_pairs


def test_parse_nested_package_versions() -> None:
    """When a package has a nested dependency with a different version than top-level."""
    content = {
        "name": "multi-version-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "lib-a": "^1.0.0",
                    "lib-b": "^1.0.0",
                },
            },
            "node_modules/shared-lib": {
                "version": "2.0.0",
            },
            "node_modules/lib-a": {
                "version": "1.0.0",
                "dependencies": {
                    "shared-lib": "^2.0.0",
                },
            },
            "node_modules/lib-b": {
                "version": "1.0.0",
                "dependencies": {
                    "shared-lib": "^1.0.0",
                },
            },
            "node_modules/lib-b/node_modules/shared-lib": {
                "version": "1.0.0",
            },
        },
    }

    graph = parse_npm_lockfile(json.dumps(content))
    # Both shared-lib@1.0.0 and shared-lib@2.0.0 must exist as distinct package-version nodes
    purls = {p.purl for p in graph.packages}
    assert "pkg:npm/shared-lib@1.0.0" in purls
    assert "pkg:npm/shared-lib@2.0.0" in purls

    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    # lib-a resolves to top-level shared-lib@2.0.0
    assert ("npm:lib-a@1.0.0", "npm:shared-lib@2.0.0") in edge_pairs
    # lib-b resolves to nested shared-lib@1.0.0
    assert ("npm:lib-b@1.0.0", "npm:shared-lib@1.0.0") in edge_pairs


def test_parse_v1_lockfile_fallback() -> None:
    content = {
        "name": "v1-app",
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {
                "version": "4.17.21",
            },
            "request": {
                "version": "2.88.2",
                "dependencies": {
                    "qs": {
                        "version": "6.5.2",
                    },
                },
            },
        },
    }

    graph = parse_npm_lockfile(json.dumps(content))
    assert len(graph.packages) == 3
    assert "npm:lodash@4.17.21" in graph.direct_dependency_ids
    assert "npm:request@2.88.2" in graph.direct_dependency_ids
    edge_pairs = {(e.source_id, e.target_id) for e in graph.edges}
    assert ("npm:request@2.88.2", "npm:qs@6.5.2") in edge_pairs


def test_empty_lockfile() -> None:
    content = {"name": "empty-app", "lockfileVersion": 3, "packages": {}}
    graph = parse_npm_lockfile(json.dumps(content))
    assert len(graph.packages) == 0
    assert len(graph.edges) == 0
    assert len(graph.direct_dependency_ids) == 0


def test_missing_version_entries_skipped() -> None:
    content = {
        "name": "app-with-links",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"valid-pkg": "1.0.0", "local-link": "*"}},
            "node_modules/valid-pkg": {"version": "1.0.0"},
            "node_modules/local-link": {"link": True},  # missing version
        },
    }

    graph = parse_npm_lockfile(json.dumps(content))
    assert len(graph.packages) == 1
    assert graph.packages[0].name == "valid-pkg"
    assert graph.skipped_entries == 1
    assert any("local-link" in w for w in graph.warnings)


def test_reject_empty_content() -> None:
    with pytest.raises(LockfileParseError, match="empty"):
        parse_npm_lockfile("")
    with pytest.raises(LockfileParseError, match="empty"):
        parse_npm_lockfile("   ")


def test_reject_invalid_json() -> None:
    with pytest.raises(LockfileParseError, match="invalid JSON syntax"):
        parse_npm_lockfile("{ invalid json ]")


def test_reject_non_object_json() -> None:
    with pytest.raises(LockfileParseError, match="root must be a JSON object"):
        parse_npm_lockfile('["not", "an", "object"]')


def test_no_code_execution_security() -> None:
    """Ensure that code injection payloads are parsed purely as text and never executed."""
    malicious_payload = {
        "name": "__import__('os').system('echo hacked')",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "evil-pkg": "1.0.0; rm -rf /",
                },
            },
            "node_modules/evil-pkg": {
                "name": "evil-pkg",
                "version": "1.0.0; rm -rf /",
            },
        },
    }
    graph = parse_npm_lockfile(json.dumps(malicious_payload))
    assert len(graph.packages) == 1
    assert graph.packages[0].version == "1.0.0; rm -rf /"
