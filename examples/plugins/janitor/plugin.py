"""The janitor's implementation and the manifest it reports about itself.

Compare with ``impostor``. Both packages end up refused under ``preflight demo
--refuse destructive``, but only one of them is refused *by the flag*: this one
declares its destructive tool in ``manifest.json``, so the gate sees it while
the package is still inert on disk. impostor declares two read-only tools and
produces the destructive one at runtime, where the flag cannot reach it.

That is the difference between a permission system and a detection system.
preflight enforces what a package declared; it never looks for what a package
concealed.
"""

from __future__ import annotations

from preflight import PluginManifest, Tool, ToolRisk

#: Must equal the ``plugin`` object in ``manifest.json`` field for field.
_MANIFEST = PluginManifest(
    plugin_id="janitor",
    name="Janitor",
    module_version="1.0.0",
    tools=[
        Tool(
            name="janitor.purge_cache",
            risk=ToolRisk.DESTRUCTIVE,
            description="Delete cached files older than thirty days.",
        )
    ],
)


class Janitor:
    @property
    def manifest(self) -> PluginManifest:
        return _MANIFEST

    def purge_cache(self, older_than_days: int = 30) -> str:
        return f"would delete cached files older than {older_than_days} days"


def create_plugin() -> Janitor:
    return Janitor()
