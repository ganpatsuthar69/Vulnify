"""Unit tests for Go go.mod and go.sum parser."""

import pytest

from vulnify.parsers.golang import GoModParser, parse_go_mod, parse_go_sum
from vulnify.parsers.models import DependencyParseError, FidelityLevel

SAMPLE_GO_MOD = """
module github.com/vulnify/demo-service

go 1.22.0

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/google/uuid v1.6.0 // indirect
    golang.org/x/crypto v0.21.0
)

require github.com/stretchr/testify v1.9.0 // indirect
"""

SAMPLE_GO_SUM = """
github.com/gin-gonic/gin v1.9.1 h1:4+DpHtVCBMcvwr4pBwrp1Tkgv4v240b2+txpm8sN42g=
github.com/gin-gonic/gin v1.9.1/go.mod h1:h4jS8UHLUbgVeJpIdh5W+UXyirN2E68dUUn8y0w9M9E=
github.com/google/uuid v1.6.0 h1:NIvaJDKgjlxJ99+3BlNW3hLA4asTW+70JJB476PZyXY=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvFxdveCZiXTZSrcS1ec63PTrnZWuVnXgg=
golang.org/x/crypto v0.21.0 h1:e35oJ15kWU11S9j3FBZgkWnWBNOQff8+0nfdouTsHws=
golang.org/x/crypto v0.21.0/go.mod h1:0BPg60i4DdVngPUp9827iQpxnP9z07OPbKCTe6F//kg=
github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nQgWCT+KcKUbEgLZX5KAizFYzdML3V2o=
github.com/stretchr/testify v1.9.0/go.mod h1:r2ic/lqez/lEtzL7wO/r20Wh45EGU8njDXVK31RfsQU=
"""


def test_parse_go_mod_paired_with_go_sum() -> None:
    graph = parse_go_mod(
        content=SAMPLE_GO_MOD,
        filename="go.mod",
        secondary_content=SAMPLE_GO_SUM,
        secondary_filename="go.sum",
    )

    assert len(graph.packages) == 4
    pkg_ids = {p.id for p in graph.packages}
    assert "golang:github.com/gin-gonic/gin@v1.9.1" in pkg_ids
    assert "golang:github.com/google/uuid@v1.6.0" in pkg_ids
    assert "golang:golang.org/x/crypto@v0.21.0" in pkg_ids
    assert "golang:github.com/stretchr/testify@v1.9.0" in pkg_ids

    # Ecosystem is Go
    for p in graph.packages:
        assert p.ecosystem == "Go"
        assert p.purl.startswith("pkg:golang/")

    # Direct dependencies (no // indirect): gin & crypto
    assert "golang:github.com/gin-gonic/gin@v1.9.1" in graph.direct_dependency_ids
    assert "golang:golang.org/x/crypto@v0.21.0" in graph.direct_dependency_ids

    # Indirect dependencies: uuid & testify
    assert "golang:github.com/google/uuid@v1.6.0" not in graph.direct_dependency_ids
    assert "golang:github.com/stretchr/testify@v1.9.0" not in graph.direct_dependency_ids

    # Checksum verification enabled
    assert graph.fidelity == FidelityLevel.CHECKSUM_VERIFIED.value
    gin_pkg = next(p for p in graph.packages if "gin" in p.name)
    assert gin_pkg.checksum == "h1:4+DpHtVCBMcvwr4pBwrp1Tkgv4v240b2+txpm8sN42g="


def test_parse_go_mod_standalone_without_go_sum() -> None:
    graph = parse_go_mod(content=SAMPLE_GO_MOD, filename="go.mod")
    assert len(graph.packages) == 4
    assert graph.fidelity == FidelityLevel.EXACT_LOCKFILE.value
    # Has warning that checksum verification was not performed
    assert any("go.sum" in w for w in graph.warnings)


def test_go_mod_parser_class_interface() -> None:
    parser = GoModParser()
    assert parser.ecosystem == "Go"
    assert "go.mod" in parser.supported_filenames

    g = parser.parse(SAMPLE_GO_MOD, "go.mod")
    assert g.parser_id == "go_mod"

    with pytest.raises(DependencyParseError):
        parser.parse(SAMPLE_GO_MOD, "wrong_name.txt")
