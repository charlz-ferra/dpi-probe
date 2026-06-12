"""Tier-2: TTL-based RST-injection forensics. Needs scapy + root (raw sockets).

A censorship middlebox that forges a RST almost never sits at the same network
distance as the real server. Its packets therefore arrive with an IP TTL that
doesn't line up with the genuine path. We learn the server's true TTL from the
SYN-ACK (which *is* genuine — TCP completes before the SNI is even sent), then
flag any RST whose TTL betrays a different, closer origin.

The packet-sniffing orchestration needs root and a live network, so it lives in
`probe_injection`. The decision logic is pulled out into pure functions
(`hops_from_ttl`, `is_injected`, `analyze`) that are unit-tested without any
network or privileges.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Standard initial TTLs different stacks ship with.
_INITIAL_TTLS = (64, 128, 255)

# How many hops of slack before a TTL gap counts as "different origin".
# Genuine same-flow packets vary by 0-1; a real middlebox is usually well beyond.
TTL_TOLERANCE = 2


@dataclass
class InjectResult:
    injected: bool
    baseline_ttl: int | None
    rst_ttls: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def hops_from_ttl(observed_ttl: int) -> int:
    """Estimate hop count from an observed TTL, assuming the nearest initial TTL."""
    for initial in _INITIAL_TTLS:
        if observed_ttl <= initial:
            return initial - observed_ttl
    return 255 - observed_ttl


def is_injected(
    rst_ttl: int | None, baseline_ttl: int | None, tolerance: int = TTL_TOLERANCE
) -> bool:
    """Pure: does this RST's TTL imply a different origin than the SYN-ACK's?

    A genuine RST from the server takes the same path as the SYN-ACK, so its TTL
    matches almost exactly. An injected RST is forged by a middlebox at a
    different network distance, so its TTL drifts beyond the jitter tolerance.
    """
    if rst_ttl is None or baseline_ttl is None:
        return False
    return abs(rst_ttl - baseline_ttl) > tolerance


def analyze(baseline_ttl: int | None, rst_ttls: list[int]) -> InjectResult:
    """Pure: given the genuine SYN-ACK TTL and observed RST TTLs, decide."""
    ev: list[str] = []
    if baseline_ttl is None:
        ev.append("no SYN-ACK captured — cannot establish a TTL baseline")
        return InjectResult(False, None, rst_ttls, ev)

    ev.append(f"server SYN-ACK TTL={baseline_ttl} (~{hops_from_ttl(baseline_ttl)} hops)")
    injected = False
    for ttl in rst_ttls:
        if is_injected(ttl, baseline_ttl):
            injected = True
            ev.append(
                f"RST TTL={ttl} (~{hops_from_ttl(ttl)} hops) ≠ server path "
                "→ forged by a middlebox closer than the server"
            )
        else:
            ev.append(f"RST TTL={ttl} consistent with the server (genuine close)")
    if not rst_ttls:
        ev.append("no RST observed during the handshake")
    return InjectResult(injected, baseline_ttl, rst_ttls, ev)


def probe_injection(host: str, port: int, sni: str, timeout: float = 6.0) -> InjectResult:
    """Sniff a real TLS handshake to the target and analyze any RSTs for forgery.

    Requires scapy and root. Lets the kernel perform the handshake while scapy
    passively observes, then compares the SYN-ACK and RST TTLs.
    """
    try:
        from scapy.all import IP, TCP, AsyncSniffer  # noqa: N811  (lazy: deep extra)
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError("deep mode needs scapy: pip install 'dpi-probe[deep]'") from exc

    import socket as _socket

    ip = _socket.gethostbyname(host)
    bpf = f"tcp and host {ip} and port {port}"
    sniffer = AsyncSniffer(filter=bpf, store=True)
    sniffer.start()
    try:
        from .probe import tls_probe

        tls_probe(host, port, sni, connect_timeout=timeout, read_timeout=timeout)
    finally:
        pkts = sniffer.stop() or []

    baseline_ttl = None
    rst_ttls: list[int] = []
    for pkt in pkts:
        if IP not in pkt or TCP not in pkt:
            continue
        if pkt[IP].src != ip:
            continue  # only packets coming *from* the server/path
        flags = pkt[TCP].flags
        if "S" in flags and "A" in flags and baseline_ttl is None:
            baseline_ttl = int(pkt[IP].ttl)
        if "R" in flags:
            rst_ttls.append(int(pkt[IP].ttl))
    return analyze(baseline_ttl, rst_ttls)
