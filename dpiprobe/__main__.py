"""Allow `python -m dpiprobe`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
