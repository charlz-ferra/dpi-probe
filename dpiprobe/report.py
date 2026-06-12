"""Render an Assessment as a colored human report or JSON."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .classify import CLEAN, INCONCLUSIVE, Assessment

_COLORS = {
    "rst_injected": "\033[31m",
    "sni_blocked": "\033[31m",
    "port_blocked": "\033[31m",
    "tls_interference": "\033[33m",
    "inconclusive": "\033[33m",
    "clean": "\033[32m",
}
_RST = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def to_json(target: str, port: int, assessment: Assessment, deep: bool) -> str:
    payload = {
        "target": target,
        "port": port,
        "deep": deep,
        **asdict(assessment),
    }
    return json.dumps(payload, ensure_ascii=False)


def to_human(target: str, port: int, assessment: Assessment, color: bool | None = None) -> str:
    if color is None:
        color = _supports_color()
    c = _COLORS.get(assessment.verdict, "") if color else ""
    rst = _RST if color else ""
    dim = _DIM if color else ""
    bold = _BOLD if color else ""

    label = assessment.verdict.replace("_", " ").upper()
    lines = [
        f"{bold}dpi-probe{rst} {dim}→ {target}:{port}{rst}",
        "",
        "  evidence:",
    ]
    lines += [f"    {dim}·{rst} {line}" for line in assessment.evidence]
    lines += [
        "",
        f"  verdict: {c}{bold}{label}{rst}  {dim}(confidence: {assessment.confidence}){rst}",
        f"  {assessment.summary}",
        "",
    ]
    if assessment.verdict == CLEAN:
        lines.append(f"  {dim}Clean from here — retry from inside the censored network.{rst}")
    elif assessment.verdict == INCONCLUSIVE:
        lines.append(
            f"  {dim}Inconclusive — rerun, or add --deep for packet forensics (root).{rst}"
        )
    return "\n".join(lines)
