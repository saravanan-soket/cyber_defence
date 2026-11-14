"""Interface registry sanity."""

from __future__ import annotations

from cvepatch.contract import interfaces


def test_registry_contains_expected_interfaces() -> None:
    assert set(interfaces.REGISTRY) == {"rl.mcp.base.v1", "rl.mcp.vulnerability_defense.v1"}


def test_lookup_vulnerability_defense() -> None:
    iface = interfaces.lookup("rl.mcp.vulnerability_defense.v1")
    assert iface is not None
    assert iface.submission_kind == "patch"
    assert iface.grader_kind == "cli_oneshot"
    assert "grade" not in iface.mcp_tools  # verifier never exposed to the agent


def test_lookup_unknown_returns_none() -> None:
    assert interfaces.lookup("rl.mcp.totally-fake.v99") is None
    assert not interfaces.is_known("rl.mcp.totally-fake.v99")


def test_each_non_base_inherits_from_base() -> None:
    """Sanity: every concrete interface points at a registered parent."""
    for name, iface in interfaces.REGISTRY.items():
        if iface.base is None:
            continue
        assert iface.base in interfaces.REGISTRY, (
            f"{name} declares base={iface.base} which is not registered"
        )


def test_all_names_sorted() -> None:
    assert interfaces.all_names() == sorted(interfaces.REGISTRY)
