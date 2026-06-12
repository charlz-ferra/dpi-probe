"""Pure-logic tests for the TTL-based RST-injection forensics (no network/root)."""

from dpiprobe.inject import analyze, hops_from_ttl, is_injected


def test_hops_from_ttl_assumes_nearest_initial():
    assert hops_from_ttl(64) == 0  # Linux/BSD origin, 0 hops
    assert hops_from_ttl(54) == 10  # 64 - 10
    assert hops_from_ttl(128) == 0  # Windows origin
    assert hops_from_ttl(118) == 10  # 128 - 10


def test_genuine_rst_same_path_is_not_injected():
    # SYN-ACK at TTL 54 and a RST at TTL 53 → same path, normal close.
    assert is_injected(53, 54) is False


def test_forged_rst_with_inconsistent_ttl_is_flagged():
    # Server's genuine packets arrive at TTL ~54; a RST at TTL 250 came from a
    # box only a few hops away → forged.
    assert is_injected(250, 54) is True


def test_injected_when_hopcount_differs_beyond_tolerance():
    # Same initial-TTL family (64) but 20 hops apart → suspicious.
    assert is_injected(44, 64) is True


def test_none_ttls_are_never_injected():
    assert is_injected(None, 64) is False
    assert is_injected(64, None) is False


def test_analyze_without_baseline_is_inconclusive():
    res = analyze(None, [60])
    assert res.injected is False
    assert any("baseline" in e for e in res.evidence)


def test_analyze_flags_forged_rst():
    res = analyze(54, [250])
    assert res.injected is True
    assert res.baseline_ttl == 54
    assert any("forged" in e for e in res.evidence)


def test_analyze_passes_genuine_rst():
    res = analyze(54, [53])
    assert res.injected is False
    assert any("genuine" in e for e in res.evidence)


def test_analyze_no_rst_observed():
    res = analyze(54, [])
    assert res.injected is False
    assert any("no RST" in e for e in res.evidence)
