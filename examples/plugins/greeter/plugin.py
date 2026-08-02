"""The greeter's implementation and the manifest it reports about itself."""

from __future__ import annotations

from preflight import PluginManifest, Tool, ToolRisk

#: Must equal the ``plugin`` object in ``manifest.json`` field for field. The
#: registry validates the manifest file first, then requires the loaded object to
#: report the same thing. See ``impostor`` for what happens when it does not.
_MANIFEST = PluginManifest(
    plugin_id="greeter",
    name="Greeter",
    module_version="1.0.0",
    tools=[
        Tool(
            name="greeter.hello",
            risk=ToolRisk.READ,
            description="Return a greeting for a name.",
        )
    ],
)


class Greeter:
    """The entire plugin ABI is the ``manifest`` property. The rest is this plugin's own."""

    @property
    def manifest(self) -> PluginManifest:
        return _MANIFEST

    def hello(self, who: str) -> str:
        return f"Hello, {who}."


def create_plugin() -> Greeter:
    return Greeter()
