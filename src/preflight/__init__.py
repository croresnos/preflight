"""preflight -- decide whether a plugin may load, before any of its code runs.

    from preflight import public_build

    registry = public_build(allowed_package_ids={"example.greeter"})
    registry.load_manifest_file(
        plugins / "greeter" / "manifest.json",
        trusted_root=plugins,
    )

Every check happens against the manifest file. The import is what a plugin gets
for passing, not the first thing that happens to it.
"""

from preflight.manifest import (
    Health,
    HealthState,
    Migration,
    Platform,
    Plugin,
    PluginManifest,
    PluginPackageManifest,
    ReleaseRing,
    Tool,
    ToolRisk,
    ToolSurface,
    UIContribution,
    Visibility,
)
from preflight.registry import (
    Edition,
    PluginRegistry,
    PluginRejected,
    RegisteredPlugin,
    development_build,
    internal_build,
    public_build,
)

__all__ = [
    "Edition",
    "Health",
    "HealthState",
    "Migration",
    "Platform",
    "Plugin",
    "PluginManifest",
    "PluginPackageManifest",
    "PluginRegistry",
    "PluginRejected",
    "RegisteredPlugin",
    "ReleaseRing",
    "Tool",
    "ToolRisk",
    "ToolSurface",
    "UIContribution",
    "Visibility",
    "development_build",
    "internal_build",
    "public_build",
]

__version__ = "0.1.0"
