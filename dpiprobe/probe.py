"""Tier-1 probes: TCP reachability and TLS-with-SNI.

Pure standard library — no root, no third-party deps. These tell us whether the
TCP port answers and whether a TLS handshake carrying a given SNI completes,
gets reset, or is silently dropped. The SNI differential (a benign name vs the
one you actually care about) is what exposes SNI-based DPI blocking.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0


@dataclass
class TcpResult:
    state: str  # open | refused | timeout | unreach
    rtt_ms: float | None
    detail: str


@dataclass
class TlsResult:
    sni: str | None
    state: str  # handshake_ok | reset | timeout | closed | tls_error | tcp_error
    rtt_ms: float | None
    detail: str


def tcp_connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> TcpResult:
    """Plain TCP connect — does the SYN get a SYN-ACK, a RST, or nothing?"""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            rtt = (time.monotonic() - start) * 1000
            return TcpResult("open", round(rtt, 1), f"SYN-ACK in {rtt:.0f}ms")
    except ConnectionRefusedError:
        return TcpResult("refused", None, "RST on SYN (port closed or reset-filtered)")
    except (socket.timeout, TimeoutError):
        return TcpResult("timeout", None, "no SYN-ACK — SYN dropped/filtered")
    except OSError as exc:
        return TcpResult("unreach", None, f"{exc.__class__.__name__}: {exc}")


def _tls_context() -> ssl.SSLContext:
    # We test reachability of the *handshake*, not certificate validity, so we
    # deliberately don't verify — a real TLS peer answering is the signal.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_probe(
    host: str,
    port: int,
    sni: str | None,
    connect_timeout: float = CONNECT_TIMEOUT,
    read_timeout: float = READ_TIMEOUT,
) -> TlsResult:
    """Drive a TLS handshake with the given SNI (or none) and classify the outcome."""
    try:
        raw = socket.create_connection((host, port), timeout=connect_timeout)
    except ConnectionRefusedError:
        return TlsResult(sni, "tcp_error", None, "RST on SYN (never reached TLS)")
    except (socket.timeout, TimeoutError):
        return TlsResult(sni, "tcp_error", None, "SYN dropped (never reached TLS)")
    except OSError as exc:
        return TlsResult(sni, "tcp_error", None, str(exc))

    raw.settimeout(read_timeout)
    ctx = _tls_context()
    start = time.monotonic()
    try:
        kwargs = {"server_hostname": sni} if sni else {}
        with ctx.wrap_socket(raw, **kwargs) as tls:
            rtt = (time.monotonic() - start) * 1000
            return TlsResult(
                sni,
                "handshake_ok",
                round(rtt, 1),
                f"ServerHello ({tls.version()}) in {rtt:.0f}ms",
            )
    except ConnectionResetError:
        rtt = (time.monotonic() - start) * 1000
        return TlsResult(sni, "reset", round(rtt, 1), f"RST {rtt:.0f}ms after ClientHello")
    except (socket.timeout, TimeoutError):
        return TlsResult(sni, "timeout", None, "no ServerHello — dropped after ClientHello")
    except ssl.SSLError as exc:
        # A TLS-level error still means a genuine TLS peer answered our ClientHello.
        reason = getattr(exc, "reason", None) or str(exc)
        return TlsResult(sni, "tls_error", None, f"TLS peer answered (error: {reason})")
    except OSError as exc:
        return TlsResult(sni, "closed", None, f"connection closed: {exc}")
    finally:
        try:
            raw.close()
        except OSError:
            pass
