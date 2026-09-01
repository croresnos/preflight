"""preflight -- decide whether a plugin may load, before any of its code runs.

This goes inside your program and runs every time it starts, deciding which
plugins are allowed to load::

    from preflight import Policy, ToolRisk, load_plugins

    result = load_plugins(
        "plugins",
        allow=["acme.weather"],          # required, and there is no wildcard
        policy=Policy(refuse_tool_risks={ToolRisk.DESTRUCTIVE}),
    )

Packages in the directory but missing from ``allow`` are discovered, reported,
and never imported. Every decision is made against the plugin's manifest file,
so the import is what a plugin gets for passing rather than the first thing that
happens to it.

There is also a command line -- ``preflight check`` and ``preflight create`` -- for
the separate moment where you are adopting a package you did not write and want
to read its paperwork, or write down what you will permit it to do. That is the
on-ramp to the gate above, not a substitute for it.

This is not a sandbox and not a scanner. Once a plugin is imported it is
ordinary Python with the full run of the process, and preflight has no power
after that. It never reads a plugin's code, so it cannot tell you whether the
code matches what the manifest claims.
"""

# --- the front door: what almost every host needs -------------------------
# --- inspection: reading a package without running it ---------------------
from preflight.inspect import (
    Inspection,
    format_inspection,
    inspect_directory,
    inspect_package,
)
from preflight.load import (
    MANIFEST_NAME,
    LoadReport,
    Outcome,
    Policy,
    load_plugins,
)

# --- the manifest schema: what a plugin author writes ---------------------
# --- release tiers: opt-in, and unnecessary for a single-tier host ---------
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

# --- the gate itself, and its refusal -------------------------------------
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

__version__ = "0.7.0"
