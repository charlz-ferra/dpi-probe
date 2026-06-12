"""Command-line entry point for dpi-probe."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .classify import INTERFERENCE, assess
from .probe import tcp_connect, tls_probe
from .report import to_human, to_json

# A benign control SNI that censors don't block — the differential baseline.
DEFAULT_BENIGN_SNI = "www.example.com"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dpi-probe",
        description="Detect DPI interference and RST injection from your vantage point.",
        epilog="Example: dpi-probe vpn.example.net --sni www.microsoft.com --deep",
    )
    p.add_argument("host", help="target host (your proxy/server, or any host to test the path)")
    p.add_argument("-p", "--port", type=int, default=443, help="target port (default: 443)")
    p.add_argument(
        "--sni",
        help="the SNI you actually care about (the one a censor might block); "
        "defaults to the host itself",
    )
    p.add_argument(
        "--benign-sni",
        default=DEFAULT_BENIGN_SNI,
        help=f"control SNI assumed un-blocked (default: {DEFAULT_BENIGN_SNI})",
    )
    p.add_argument(
        "--deep",
        action="store_true",
        help="packet-level RST-injection forensics via scapy (needs root + 'dpi-probe[deep]')",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="per-probe timeout seconds (default: 5)",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-color", action="store_true", help="strip ANSI colors")
    p.add_argument("-V", "--version", action="version", version=f"dpi-probe {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    target_sni = args.sni or args.host

    tcp = tcp_connect(args.host, args.port, timeout=args.timeout)
    tls_benign = tls_probe(args.host, args.port, args.benign_sni, args.timeout, args.timeout)
    tls_target = tls_probe(args.host, args.port, target_sni, args.timeout, args.timeout)

    inject = None
    if args.deep:
        try:
            from .inject import probe_injection

            inject = probe_injection(args.host, args.port, target_sni, timeout=args.timeout)
        except (RuntimeError, PermissionError, OSError) as exc:
            print(f"dpi-probe: deep mode unavailable ({exc})", file=sys.stderr)

    assessment = assess(tcp, tls_benign, tls_target, inject)

    if args.json:
        print(to_json(f"{args.host}", args.port, assessment, args.deep))
    else:
        color = False if args.no_color else None
        print(to_human(args.host, args.port, assessment, color))

    return 1 if assessment.verdict in INTERFERENCE else 0


if __name__ == "__main__":
    raise SystemExit(main())
