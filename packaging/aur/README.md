# AUR packaging

`PKGBUILD` + `.SRCINFO` to build and publish **dpi-probe** on the
[AUR](https://aur.archlinux.org/).

## Install (once published)

```bash
yay -S dpi-probe     # or: paru -S dpi-probe
```

`python-scapy` is an optional dependency — install it for `--deep` (packet-level
RST-injection forensics).

## Build locally from this directory

```bash
makepkg -si
```

## Maintainer: publish / update on the AUR

```bash
git clone ssh://aur@aur.archlinux.org/dpi-probe.git aur-dpi-probe
cp PKGBUILD aur-dpi-probe/
cd aur-dpi-probe
updpkgsums                          # refresh sha256sums for the tagged release
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "dpi-probe 1.1.0"
git push
```

On a new release, bump `pkgver` in `PKGBUILD`, then re-run `updpkgsums` and
regenerate `.SRCINFO` before pushing.
