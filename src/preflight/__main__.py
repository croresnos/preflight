"""Lets ``python -m preflight`` work without an installed console script."""

from preflight.cli import main

raise SystemExit(main())
