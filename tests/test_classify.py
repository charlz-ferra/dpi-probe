"""Tests for the verdict logic that fuses TCP + TLS-differential + injection."""

from dpiprobe.classify import (
    CLEAN,
    INCONCLUSIVE,
    PORT_BLOCKED,
    RST_INJECTED,
    SNI_BLOCKED,
    TLS_INTERFERENCE,
    assess,
)
from dpiprobe.inject import InjectResult
from dpiprobe.probe import TcpResult, TlsResult


def _tcp(state, detail="x"):
    return TcpResult(state, 10.0 if state == "open" else None, detail)


def _tls(sni, state, detail="x"):
    return TlsResult(sni, state, None, detail)


def test_port_block_when_syn_dropped():
    a = assess(_tcp("timeout"), _tls("a", "tcp_error"), _tls("b", "tcp_error"))
    assert a.verdict == PORT_BLOCKED
    assert a.confidence == "high"


def test_clean_when_target_sni_handshakes():
    a = assess(_tcp("open"), _tls("benign", "handshake_ok"), _tls("target", "handshake_ok"))
    assert a.verdict == CLEAN


def test_sni_block_high_confidence_on_reset():
    a = assess(_tcp("open"), _tls("benign", "handshake_ok"), _tls("target", "reset"))
    assert a.verdict == SNI_BLOCKED
    assert a.confidence == "high"


def test_sni_block_medium_confidence_on_silent_drop():
    a = assess(_tcp("open"), _tls("benign", "handshake_ok"), _tls("target", "timeout"))
    assert a.verdict == SNI_BLOCKED
    assert a.confidence == "medium"


def test_tls_interference_when_all_reset():
    a = assess(_tcp("open"), _tls("benign", "reset"), _tls("target", "reset"))
    assert a.verdict == TLS_INTERFERENCE


def test_injection_overrides_to_rst_injected():
    inj = InjectResult(injected=True, baseline_ttl=54, rst_ttls=[250], evidence=["forged"])
    # even if TLS looked benign, a forged RST is the stronger signal
    a = assess(_tcp("open"), _tls("benign", "handshake_ok"), _tls("target", "reset"), inj)
    assert a.verdict == RST_INJECTED
    assert a.confidence == "high"


def test_tls_error_counts_as_reachable_peer():
    # a TLS alert means a real TLS server answered → not a block
    a = assess(_tcp("open"), _tls("benign", "handshake_ok"), _tls("target", "tls_error"))
    assert a.verdict == CLEAN


def test_inconclusive_when_no_handshake_but_mixed():
    a = assess(_tcp("open"), _tls("benign", "timeout"), _tls("target", "reset"))
    assert a.verdict == INCONCLUSIVE
