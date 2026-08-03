"""preflight -- decide whether a plugin may load, before any of its code runs.

Two ways in. The command line, for something you downloaded and have not read::

    preflight check ./some-plugin      # reads its paperwork. Executes nothing.

And the library, for your own application at runtime::

    from preflight import load_plugins

    result = load_plugins("plugins", allow=["example.greeter"])
    print(result)
    greeter = result.plugins["greeter"]

Every decision is made against the plugin's manifest file. The import is what a
plugin gets for passing, not the first thing that happens to it.

This is not a sandbox and not a scanner. Once a plugin is imported it is
ordinary Python with the full run of the process, and preflight has no power
after that. It never reads a plugin's code, so it cannot tell you whether the
code matches what the manifest claims.
"""

# --- the front door: what almost every host needs -------------------------
from preflight.load import (
    MANIFEST_NAME,
    LoadReport,
    Outcome,
    Policy,
    load_plugins,
)

# --- inspection: reading a package without running it ---------------------
from preflight.inspect import (
    Inspection,
    format_inspection,
    inspect_directory,
    inspect_package,
)

# --- the manifest schema: what a plugin author writes ---------------------
from preflight.manifest import (
    Health,
    HealthState,
    Migration,
    Platform,
    Plugin,
    PluginManifest,
    PluginPackageManifest,
    Tool,
    ToolRisk,
    ToolSurface,
    UIContribution,
)

# --- the gate itself, and its refusal -------------------------------------
from preflight.registry import (
    PluginRegistry,
    PluginRejected,
    RegisteredPlugin,
)

# --- release tiers: opt-in, and unnecessary for a single-tier host ---------
from preflight.manifest import ReleaseRing, Visibility
from preflight.registry import (
    Edition,
    development_build,
    internal_build,
    public_build,
)

__all__ = [
    # front door
    "load_plugins",
    "LoadReport",
    "Outcome",
    "Policy",
    "MANIFEST_NAME",
    # inspection
    "inspect_package",
    "inspect_directory",
    "format_inspection",
    "Inspection",
    # manifest schema
    "PluginPackageManifest",
    "PluginManifest",
    "Plugin",
    "Tool",
    "ToolRisk",
    "ToolSurface",
    "Platform",
    "Health",
    "HealthState",
    "Migration",
    "UIContribution",
    # the gate
    "PluginRegistry",
    "PluginRejected",
    "RegisteredPlugin",
    # release tiers (opt-in)
    "Edition",
    "Visibility",
    "ReleaseRing",
    "public_build",
    "internal_build",
    "development_build",
]

__version__ = "0.2.0"
