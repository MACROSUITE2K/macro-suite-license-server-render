"""Hardened licensing client entrypoint.

Run with:
    python -m client.app
"""

from client.app import main


if __name__ == "__main__":
    raise SystemExit(main())
