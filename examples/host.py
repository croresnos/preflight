"""A host that loads four plugins. Three of them do not deserve to load.

Run it::

    python examples/host.py

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

from preflight import PluginRejected, public_build  # noqa: E402


def attempt(registry, package_directory: str) -> None:
    print(f"\n{package_directory}")
    try:
        registered = registry.load_manifest_file(
            PLUGINS / package_directory / "manifest.json",
            trusted_root=PLUGINS,
        )
    except PluginRejected as refusal:
        print(f"  REFUSED  {refusal}")
        return
    print(f"  LOADED   {registered.package.plugin.name}")


def main() -> None:
    registry = public_build(
        allowed_package_ids={
            "example.greeter",
            "example.trespasser",
            "example.collider",
            "example.impostor",
        }
    )

    # Every one of these is on the allowlist, is marked public, and is in the
    # stable ring, so each refusal below is about the plugin itself rather than
    # about this build's tier policy.
    attempt(registry, "greeter")
    attempt(registry, "trespasser")
    attempt(registry, "collider")
    attempt(registry, "impostor")

    print("\nregistered plugins")
    for manifest in registry.available():
        print(f"  {manifest.plugin_id}  {manifest.name} {manifest.module_version}")
        for tool in manifest.tools:
            print(f"    tool {tool.name} (risk: {tool.risk.value})")

    print("\ntool ownership is exclusive")
    print(f"  greeter.hello -> {registry.tool_owner('greeter.hello')}")
    print(f"  impostor.read_profile -> {registry.tool_owner('impostor.read_profile')}")

    greeter = registry.get("greeter")
    print(f"\ncalling the one plugin that loaded\n  {greeter.hello('world')}")


if __name__ == "__main__":
    main()
