"""A host that loads four plugins. Three of them do not deserve to load.

Run it::

    python examples/host.py

or, once preflight is installed::

    preflight demo

Read the output for the lines that say ``top-level plugin code is executing``.
Those are tripwires: the earliest statement in each plugin package, printed only
if that plugin got as far as being imported. Two of the three refusals happen
with the plugin still inert on disk, and their tripwires never fire.
"""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent
PLUGINS = EXAMPLES / "plugins"

# Convenience so a clean clone can run this without installing anything.
sys.path.insert(0, str(EXAMPLES.parent / "src"))

# preflight never modifies sys.path. Making the plugin directory importable is
# the host's job -- a library that mutates global import state as a side effect
# of a security check is worse than one that documents the requirement.
sys.path.insert(0, str(PLUGINS))

from preflight import load_plugins  # noqa: E402


def main() -> None:
    # Every package below is on the allowlist, is marked public, and is in the
    # stable ring, so each refusal is about the plugin itself rather than about
    # this host's tier policy. Order matters: the first plugin to claim a tool
    # name keeps it, and this list is where that precedence is decided.
    result = load_plugins(
        PLUGINS,
        allow=[
            "example.greeter",
            "example.trespasser",
            "example.collider",
            "example.impostor",
        ],
    )

    print()
    print(result)

    print("\ntool ownership is exclusive")
    registry = result.registry
    print(f"  greeter.hello -> {registry.tool_owner('greeter.hello')}")
    print(f"  impostor.read_profile -> {registry.tool_owner('impostor.read_profile')}")

    greeter = result.plugins["greeter"]
    print(f"\ncalling the one plugin that loaded\n  {greeter.hello('world')}")


if __name__ == "__main__":
    main()
