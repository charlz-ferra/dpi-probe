"""Combine probe results into a single DPI assessment. Pure logic, no I/O."""

from __future__ import annotations

from dataclasses import dataclass, field

from .inject import InjectResult
from .probe import TcpResult, TlsResult

# Verdict codes.
CLEAN = "clean"
SNI_BLOCKED = "sni_blocked"
RST_INJECTED = "rst_injected"
PORT_BLOCKED = "port_blocked"
TLS_INTERFERENCE = "tls_interference"
INCONCLUSIVE = "inconclusive"

# Verdicts that mean "something is interfering" → non-zero exit.
INTERFERENCE = {SNI_BLOCKED, RST_INJECTED, PORT_BLOCKED, TLS_INTERFERENCE}


@dataclass
class Assessment:
    verdict: str
    confidence: str  # high | medium | low
    summary: str
    evidence: list[str] = field(default_factory=list)


def _handshook(tls: TlsResult) -> bool:
    # A TLS-level error still proves a real TLS peer answered the ClientHello.
    return tls.state in ("handshake_ok", "tls_error")


def assess(
    tcp: TcpResult,
    tls_benign: TlsResult,
    tls_target: TlsResult,
    inject: InjectResult | None = None,
) -> Assessment:
    """Fuse TCP, the SNI-differential TLS probes, and optional injection forensics."""
    ev: list[str] = []

    # 1. TCP layer — if we can't even reach the port, nothing else matters.
    if tcp.state in ("timeout", "unreach"):
        return Assessment(
            PORT_BLOCKED,
            "high",
            f"TCP never completed ({tcp.detail}).",
            [f"tcp: {tcp.detail}"],
        )
    ev.append(f"tcp: {tcp.detail}")

    # 2. Injection forensics are the strongest signal — a forged RST is proof.
    if inject is not None:
        ev.extend(f"inject: {line}" for line in inject.evidence)
        if inject.injected:
            return Assessment(
                RST_INJECTED,
                "high",
                "Forged RST — a middlebox, not the server, is tearing the connection down.",
                ev,
            )

    # 3. TLS SNI differential.
    benign_ok = _handshook(tls_benign)
    target_ok = _handshook(tls_target)
    ev.append(f"tls[{tls_benign.sni or 'no-sni'}]: {tls_benign.state} — {tls_benign.detail}")
    ev.append(f"tls[{tls_target.sni}]: {tls_target.state} — {tls_target.detail}")

    if benign_ok and not target_ok:
        if tls_target.state == "reset":
            return Assessment(
                SNI_BLOCKED,
                "high",
                f"Benign SNI completes but '{tls_target.sni}' is reset — classic SNI-based DPI.",
                ev,
            )
        if tls_target.state == "timeout":
            return Assessment(
                SNI_BLOCKED,
                "medium",
                f"Benign SNI completes but '{tls_target.sni}' is silently dropped — SNI-based DPI.",
                ev,
            )
        return Assessment(
            TLS_INTERFERENCE,
            "medium",
            f"Benign SNI works but target SNI fails ({tls_target.state}).",
            ev,
        )

    if not benign_ok and not target_ok:
        if tls_benign.state == tls_target.state == "reset":
            return Assessment(
                TLS_INTERFERENCE,
                "medium",
                "Every TLS handshake resets regardless of SNI — TLS-fingerprint block, "
                "full port block, or the server is down.",
                ev,
            )
        return Assessment(
            INCONCLUSIVE,
            "low",
            "No TLS handshake completed; cause can't be isolated.",
            ev,
        )

    if tcp.state == "refused":
        return Assessment(
            INCONCLUSIVE,
            "low",
            "Port reset on SYN yet TLS later succeeded — likely transient, retry.",
            ev,
        )
    return Assessment(
        CLEAN,
        "high",
        "TLS completes with the target SNI — no interference from here.",
        ev,
    )
