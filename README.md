# dpi-probe

[![ci](https://github.com/charlz-ferra/dpi-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/charlz-ferra/dpi-probe/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)

> Is the censor messing with your connection, or is it just down? `dpi-probe`
> tells the difference — from your side of the wall, no server needed.

When a proxy "stops working" behind a censoring network, you're left guessing:
dead server, blocked IP, throttled link, or active DPI tearing down your TLS the
moment it sees the SNI? `dpi-probe` answers that. It runs a differential TLS
probe and, with `--deep`, packet-level forensics that catch a **forged RST** by
its TTL — the fingerprint of a middlebox impersonating your server.

```text
dpi-probe → myproxy.example.net:443

  evidence:
    · tcp: SYN-ACK in 31ms
    · tls[www.example.com]: handshake_ok — ServerHello (TLSv1.3) in 34ms
    · tls[myproxy.example.net]: reset — RST 33ms after ClientHello
    · inject: server SYN-ACK TTL=117 (~11 hops)
    · inject: RST TTL=250 (~5 hops) ≠ server path → forged by a middlebox

  verdict: RST INJECTED  (confidence: high)
  Forged RST — a middlebox, not the server, is tearing the connection down.
```

## How it works

**Tier 1 — SNI differential (no privileges, standard library only).**
`dpi-probe` opens two TLS handshakes to the same host: one carrying a benign
control SNI (`www.example.com`), one carrying the name you actually care about.
If the benign handshake completes but the target one is **reset** or **silently
dropped**, the block is keyed on the SNI — textbook DPI. If plain TCP itself
never completes, it's an IP/port block, not DPI.

**Tier 2 — RST-injection forensics (`--deep`, needs `scapy` + root).**
A censorship box that forges a RST sits at a different network distance than the
real server, so its packets arrive with a mismatched IP **TTL**. `dpi-probe`
learns the server's true TTL from the genuine SYN-ACK (TCP completes before the
SNI is even sent), then flags any RST whose TTL betrays a closer, forged origin.
That's the difference between "the server hung up" and "someone _pretended_ to
be the server and hung up for it."

| Verdict            | Meaning                                                     |
| ------------------ | ----------------------------------------------------------- |
| `clean`            | Target SNI handshakes fine — no interference from here      |
| `sni_blocked`      | Benign SNI works, target SNI reset/dropped — SNI-based DPI  |
| `rst_injected`     | A forged RST was caught red-handed by its TTL (`--deep`)    |
| `port_blocked`     | TCP never completed — IP/port filtered, not DPI             |
| `tls_interference` | All TLS fails regardless of SNI — fingerprint block or down |
| `inconclusive`     | Couldn't isolate a cause — rerun, or go `--deep`            |

## Install

```bash
pipx install dpi-probe            # or: pip install dpi-probe
pipx install 'dpi-probe[deep]'    # with scapy, for --deep TTL forensics
```

From source:

```bash
git clone https://github.com/charlz-ferra/dpi-probe
cd dpi-probe && pip install -e .
```

## Usage

```bash
dpi-probe myproxy.example.net                       # SNI differential, defaults to host as SNI
dpi-probe 203.0.113.7 --sni www.microsoft.com       # test a specific masquerade SNI
dpi-probe myproxy.example.net --deep                 # + RST-injection forensics (sudo)
dpi-probe myproxy.example.net --json                 # machine-readable
```

```bash
# alert from cron when your endpoint starts getting tampered with
dpi-probe myproxy.example.net --json | jq -e '.verdict=="clean"' >/dev/null || notify "DPI on the endpoint"
```

**Exit code:** `0` clean, `1` interference detected (`sni_blocked` / `rst_injected`
/ `port_blocked` / `tls_interference`), `2` on a usage error.

### Man page & shell completions

The repo ships `dpi-probe.1` and bash/zsh/fish completions under `completions/`
(pip doesn't place these automatically):

```bash
sudo install -Dm644 dpi-probe.1 /usr/local/share/man/man1/dpi-probe.1
sudo install -Dm644 completions/dpi-probe.fish /usr/share/fish/vendor_completions.d/dpi-probe.fish
sudo install -Dm644 completions/dpi-probe.bash /usr/share/bash-completion/completions/dpi-probe
sudo install -Dm644 completions/_dpi-probe /usr/share/zsh/site-functions/_dpi-probe
```

## Why this exists

VLESS+Reality, Hysteria2, and friends are an arms race against DPI. When an
endpoint degrades you need to know _which_ move the censor just played, because
the fix is different each time — rotate the SNI, switch the IP, change transport,
or wait out a throttle. `dpi-probe` turns "it's not working 🤷" into a verdict
with evidence.

## Limitations

A vantage-point tool is only as honest as its vantage point — run it from _inside_
the censored network to see what that network does. TTL forensics can miss a
middlebox that happens to sit at the server's exact distance, and can't see
into an already-encrypted tunnel. It detects interference; it doesn't bypass it.
For rigorous measurement studies, see [OONI](https://ooni.org/). This is the
fast field instrument you reach for first.

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check . && pytest -q
```

The verdict logic and TTL forensics are pure functions with full unit coverage —
no network or root needed to run the test suite.

## License

[MIT](LICENSE)
