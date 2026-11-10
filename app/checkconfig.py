"""Validate the relay's configuration from the environment.

    python -m app.checkconfig      # exit 0 if OK, 1 with a list of problems otherwise

Used by app/serve.py at startup and by rebuild.sh before it stops the running container.
"""
from __future__ import annotations

import sys

from .config import Settings


def problems() -> list[str]:
    return Settings.from_env().validate()


def main() -> int:
    found = problems()
    if found:
        print("Invalid configuration (.env):", file=sys.stderr)
        for p in found:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("Configuration OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
