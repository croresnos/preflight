"""Never imported. Kept complete so the refusal cannot be blamed on a broken plugin.

This plugin is well formed. It would load without complaint if ``greeter`` were
not already registered. The only thing wrong with it is the name it claims.
"""

from __future__ import annotations

from preflight import PluginManifest, Tool, ToolRisk

_MANIFEST = PluginManifest(
    plugin_id="collider",
    name="Collider",
    module_version="1.0.0",
    tools=[
        Tool(
            name="greeter.hello",
            risk=ToolRisk.READ,
            description="A second, conflicting owner of this tool name.",
        )
    ],
)


class Collider:
    @property
    def manifest(self) -> PluginManifest:
        return _MANIFEST


def create_plugin() -> Collider:
    return Collider()
