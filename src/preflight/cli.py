"""``preflight`` on the command line.

Five commands, and the important one is the first::

    preflight check  ./some-plugin     # read its paperwork. Executes nothing.
    preflight create ./some-plugin     # write down what you will permit it to do
    preflight demo                     # watch three plugins get refused
    preflight try                      # a host and a plugin, to break yourself
    preflight settings                 # stop retyping --refuse on every command

``check`` is the command you run on something you downloaded and have not read.
It is safe to point at untrusted code because it never imports it -- see
:mod:`preflight.inspect`. It is *not* a malware scanner, does not read the
package's code, and cannot tell you whether a package does what it says. It
tells you what the package **claims**, and whether those claims are coherent.

``--refuse`` on ``check`` and ``demo`` is not a fourth thing preflight knows how
to do. It is ``Policy(refuse_tool_risks=...)`` -- the gate that runs inside a
host at every startup -- asked at a terminal, so the exit code answers to the
host's rules rather than to preflight's defaults.

``settings`` saves that flag so it need not be retyped. It configures the
commands in this module and nothing else: :func:`~preflight.load.load_plugins`
does not read a settings file, and this is the only module that does.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from preflight import __version__
from preflight.inspect import (
    MANIFEST_NAME,
    format_inspection,
    inspect_directory,
    risk_set_literal,
)
from preflight.manifest import ToolRisk
from preflight.registry import Edition, PluginRegistry, host_platform
from preflight.settings import (
    SETTINGS_NAME,
    Origin,
    Settings,
    SettingsError,
    find_project_settings,
    load_settings,
    parse_risks,
    save_setting,
    settings_path_for,
    user_settings_path,
)

_NOT_IDENTIFIER = re.compile(r"[^0-9a-zA-Z_]+")


def _tool_risks(value: str) -> frozenset[ToolRisk]:
    """Parse one ``--refuse`` value: a comma-separated list of risk names.

    Raising ``ArgumentTypeError`` hands the failure to argparse, which reports
    it and exits ``2`` -- the same code the rest of this module uses for "you
    pointed me at something I cannot work with".
    """
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names:
        raise argparse.ArgumentTypeError("expected at least one risk name")
    risks = set()
    for name in names:
        try:
            risks.add(ToolRisk(name.lower()))
        except ValueError:
            valid = ", ".join(risk.value for risk in ToolRisk)
            raise argparse.ArgumentTypeError(
                f"unknown risk '{name}'. Valid risks: {valid}"
            ) from None
    return frozenset(risks)


def _flag_risks(args: argparse.Namespace) -> frozenset[ToolRisk] | None:
    """Every risk named across all occurrences of ``--refuse``, or ``None``.

    ``None`` and ``frozenset()`` are different answers. The first means the flag
    was never passed, so a saved setting still applies; the second cannot arise,
    because ``_tool_risks`` rejects an empty value.
    """
    given = getattr(args, "refuse", None)
    return frozenset().union(*given) if given else None


def _refused_risks(args: argparse.Namespace, settings: Settings) -> frozenset[ToolRisk]:
    """The risks in force: the flag if one was given, otherwise the file's.

    A flag *replaces* the saved value rather than adding to it. Someone reaching
    for ``--refuse`` at a prompt is usually trying to get out of what the file
    says, and an override that can only ever narrow is not an override. Repeated
    flags still union with each other -- that part is unchanged.
    """
    from_flag = _flag_risks(args)
    return from_flag if from_flag is not None else settings.refuse


def _settings_for(args: argparse.Namespace, *, inspected: Path | None = None) -> Settings:
    """Load saved settings for a command that consults them.

    ``inspected`` is the folder the command is about to read, and is passed so
    :func:`~preflight.settings.load_settings` can drop -- loudly -- a settings
    file sitting inside it.
    """
    resolved = load_settings(profile=getattr(args, "profile", None), inspected=inspected)
    for item in resolved.ignored:
        print(
            f"preflight: ignoring {item.path}\n"
            f"           {item.reason}, so it is in the hands of whatever put it "
            f"there.\n           preflight is not configured by the thing it is "
            f"inspecting. Move it to\n           your project root to have it apply.",
            file=sys.stderr,
        )
    return resolved


def _add_profile_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        metavar="NAME",
        help=(
            "use a named profile from your settings file -- one saved set of "
            "rules per agent. See `preflight settings`."
        ),
    )


def _add_refuse_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--refuse",
        metavar="RISK[,RISK...]",
        type=_tool_risks,
        action="append",
        help=(
            "declared tool risks you will not accept. Repeatable, and repeats "
            "combine. This is your rule, not preflight's -- the same one a host "
            "writes as Policy(refuse_tool_risks=...). Passing this REPLACES any "
            "saved setting rather than adding to it, so it can loosen as well as "
            "tighten. Valid: "
            + ", ".join(risk.value for risk in ToolRisk)
        ),
    )


def _slug(name: str) -> str:
    """A folder name turned into something a Python module could be called."""
    cleaned = _NOT_IDENTIFIER.sub("_", name).strip("_").lower()
    return cleaned or "plugin"


def _guess_entrypoint(folder: Path) -> str:
    """Propose an entrypoint from what is on disk. ``check`` verifies it after."""
    module = _slug(folder.name)
    if (folder / "__init__.py").is_file():
        if (folder / "plugin.py").is_file():
            return f"{module}.plugin:create_plugin"
        return f"{module}:create_plugin"
    return f"{module}.plugin:create_plugin"


def _not_a_directory(path: Path, command: str) -> str:
    """Say which of the two things went wrong, because they are fixed differently.

    ``is not a directory`` is true of a path that does not exist and of a path
    that is a file, and a person who typed the wrong thing has no way to tell
    which they did. Both exits stay ``2``.
    """
    if path.exists():
        return f"preflight: '{path}' is a file, not a directory"
    return (
        f"preflight: '{path}' does not exist.\n"
        f"preflight {command} works on a package that is already on disk -- it "
        f"reads\nthe folder, and never creates one. Make the folder and put its "
        f"Python in it\nfirst, then run this again."
    )


def _check(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.is_dir():
        print(_not_a_directory(target, "check"), file=sys.stderr)
        return 2

    settings = _settings_for(args, inspected=target)
    refuse = _refused_risks(args, settings)
    # The rest of what a host decides before importing. Defaulting to the running
    # OS and a public build is what `load_plugins` with no Policy does, so an
    # unconfigured `check` answers the same question an unconfigured host would.
    platform = settings.platform
    edition = settings.edition

    inspections = inspect_directory(target)
    for index, inspection in enumerate(inspections):
        if index:
            print()
        print(
            format_inspection(
                inspection,
                refuse_tool_risks=refuse,
                platform=platform,
                edition=edition,
            )
        )

    # Every condition means the same thing -- this would not load -- so all of
    # them are exit 1. Incoherent paperwork, a refused risk, an unsupported
    # platform and a tier this build will not take are four reasons for one
    # answer, and a script acting on the answer needs one code.
    would_load = all(
        item.consistent
        and not item.refusals(
            platform=platform, edition=edition, refuse_tool_risks=refuse
        )
        for item in inspections
    )
    return 0 if would_load else 1


def _create(args: argparse.Namespace) -> int:
    # Resolved, because everything below is derived from the folder's *name* --
    # the slug, the guessed entrypoint, the rename advice. `Path('.').name` is
    # the empty string, so `preflight create .` from inside the package, which
    # is the obvious way to run this, would otherwise be told that '' cannot be
    # a Python package name. `check` resolves for the same reason.
    folder = Path(args.path).resolve()
    if not folder.is_dir():
        print(_not_a_directory(folder, "create"), file=sys.stderr)
        return 2

    destination = folder / MANIFEST_NAME
    if destination.exists() and not args.force:
        print(
            f"preflight: {destination} already exists. Pass --force to overwrite it.",
            file=sys.stderr,
        )
        return 2

    slug = _slug(folder.name)
    # A folder whose name is not a Python identifier can never be imported, and
    # no manifest can fix that. Say so instead of writing a file that looks like
    # progress and resolves to nothing.
    if slug != folder.name and not args.entrypoint:
        print(
            f"preflight: '{folder.name}' cannot be a Python package name, so nothing\n"
            f"inside it can be reached by an entrypoint. No manifest fixes this.\n"
            f"\n"
            f"Rename the folder first:\n"
            f"    {folder.name}  ->  {slug}\n"
            f"\n"
            f"Or pass --entrypoint if the module lives somewhere else.",
            file=sys.stderr,
        )
        return 2

    manifest = {
        "schema_version": "1.0",
        "package_id": args.package_id or f"local.{slug}",
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": args.entrypoint or _guess_entrypoint(folder),
        "plugin": {
            "schema_version": "1.0",
            "plugin_id": slug,
            "name": folder.name,
            "module_version": "0.1.0",
            "tools": [],
        },
    }
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {destination}")
    print()
    print("  This manifest records what you PERMIT this package to do. preflight")
    print("  did not read its code and has not checked whether the two agree.")
    print("  An empty `tools` list means it may expose none.")
    print()
    print("  Next:")
    print(f"      preflight check {folder}")
    return 0


_SANDBOX_PLUGIN = '''\
from preflight import PluginManifest

_MANIFEST = PluginManifest.model_validate({
    "plugin_id": "weather",
    "name": "Weather",
    "module_version": "1.0.0",
    "tools": [{"name": "weather.today", "risk": "read"}],
})


class Weather:
    @property
    def manifest(self):
        return _MANIFEST

    def today(self):
        return "18C and raining"


def create_plugin():
    return Weather()
'''

_SANDBOX_HOST = '''\
import sys

# You are meant to edit these plugins and rerun this within seconds, and Python
# decides a cached .pyc is still current from the source's size and its mtime *to
# the second*. Undoing one of the breaks rewrites the same number of bytes inside
# that same second, so a normal run would reuse the stale bytecode and refuse a
# file that is already correct on disk. Your real host should not carry this line.
sys.dont_write_bytecode = True

from pathlib import Path

from preflight import load_plugins

PLUGINS = Path(__file__).resolve().parent / "plugins"
sys.path.insert(0, str(PLUGINS))          # preflight will not do this for you

result = load_plugins(PLUGINS, allow=["local.weather"])
print(result)

weather = result.get("weather")           # .get, not [...] -- refusals are data
if weather is not None:
    print("\\ntoday:", weather.today())
'''

_SANDBOX_MANIFEST = {
    "schema_version": "1.0",
    "package_id": "local.weather",
    "core_api_version": "1.0",
    "visibility": "public",
    "release_ring": "stable",
    "entrypoint": "weather.plugin:create_plugin",
    "plugin": {
        "schema_version": "1.0",
        "plugin_id": "weather",
        "name": "Weather",
        "module_version": "1.0.0",
        "tools": [{"name": "weather.today", "risk": "read"}],
    },
}


_BREAK_TITLES = (
    "delete the __init__.py that makes it a package",
    "misspell the entrypoint in manifest.json",
    "bump module_version in plugin.py only, not in manifest.json",
)

_BREAKS_POSIX = (
    (
        "rm plugins/weather/__init__.py",
        "touch plugins/weather/__init__.py",
    ),
    (
        "sed -i 's/weather\\.plugin/wether.plugin/' plugins/weather/manifest.json",
        "sed -i 's/wether\\.plugin/weather.plugin/' plugins/weather/manifest.json",
    ),
    (
        "sed -i 's/\"1\\.0\\.0\"/\"2.0.0\"/' plugins/weather/plugin.py",
        "sed -i 's/\"2\\.0\\.0\"/\"1.0.0\"/' plugins/weather/plugin.py",
    ),
)

_BREAKS_WINDOWS = (
    (
        "Remove-Item plugins\\weather\\__init__.py",
        "New-Item -ItemType File plugins\\weather\\__init__.py",
    ),
    (
        "(Get-Content plugins\\weather\\manifest.json) -replace 'weather\\.plugin','wether.plugin' | Set-Content plugins\\weather\\manifest.json",
        "(Get-Content plugins\\weather\\manifest.json) -replace 'wether\\.plugin','weather.plugin' | Set-Content plugins\\weather\\manifest.json",
    ),
    (
        "(Get-Content plugins\\weather\\plugin.py) -replace '\"1\\.0\\.0\"','\"2.0.0\"' | Set-Content plugins\\weather\\plugin.py",
        "(Get-Content plugins\\weather\\plugin.py) -replace '\"2\\.0\\.0\"','\"1.0.0\"' | Set-Content plugins\\weather\\plugin.py",
    ),
)


def _is_sandbox(root: Path) -> bool:
    """Whether this folder is one ``try`` wrote, rather than somebody's own work.

    Both files, because either alone is something a person could plausibly have
    of their own: ``host.py`` is an ordinary name, and a ``plugins/weather/``
    package is the shape this command exists to teach.
    """
    return (root / "host.py").is_file() and (
        root / "plugins" / "weather" / MANIFEST_NAME
    ).is_file()


def _try(args: argparse.Namespace) -> int:
    """Write a working host and one plugin, so there is something to break.

    ``create`` will not do this. It writes a manifest for code you wrote and
    refuses to invent the code, because a manifest records what *you* permit and
    preflight guessing at that would defeat the point. This command is not that:
    it is a sandbox to take apart, and it says so in what it prints.
    """
    root = Path(args.path).resolve()
    if root.exists() and any(root.iterdir()) and not args.force:
        # The exercises below leave the sandbox broken on purpose, and undoing
        # them is a manual step somebody can skip or mistype. A returning reader
        # then meets a folder in a state nothing on screen explains -- and
        # "write into it anyway" reads as an override to be avoided rather than
        # as the reset it would be. Say which of the two situations this is.
        if _is_sandbox(root):
            print(
                f"preflight: '{root}' is already a preflight sandbox.\n"
                f"It may have been left part-way through one of the exercises. Pass\n"
                f"--force to reset it to the working state.",
                file=sys.stderr,
            )
        else:
            print(
                f"preflight: '{root}' already exists and is not empty. Pass --force to\n"
                f"write into it anyway, or name a folder that does not exist yet.",
                file=sys.stderr,
            )
        return 2

    package = root / "plugins" / "weather"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "plugin.py").write_text(_SANDBOX_PLUGIN, encoding="utf-8")
    (package / MANIFEST_NAME).write_text(
        json.dumps(_SANDBOX_MANIFEST, indent=2) + "\n", encoding="utf-8"
    )
    (root / "host.py").write_text(_SANDBOX_HOST, encoding="utf-8")

    print(f"wrote {root}")
    print("      host.py                          the gate, 12 lines")
    print("      plugins/weather/__init__.py      empty, and load-bearing")
    print("      plugins/weather/plugin.py        the plugin")
    print(f"      {f'plugins/weather/{MANIFEST_NAME}':<33}what it is permitted to do")
    print()
    print("  This one loads. Nothing is wrong with it, which is the least")
    print("  interesting state it can be in.")
    print()
    print("  Run it:")
    print(f"      cd {root}")
    print("      python host.py")
    print()
    print("  Then break it, three times. Read the refusal before you read the fix.")
    breaks = _BREAKS_WINDOWS if os.name == "nt" else _BREAKS_POSIX
    for number, (title, (break_it, undo)) in enumerate(zip(_BREAK_TITLES, breaks), 1):
        print()
        print(f"  {number}. {title}")
        print(f"       {break_it}")
        print("       python host.py")
        print(f"       {undo}   # undo")
    print()
    print("  The first two are refused from the manifest alone -- the plugin's")
    print("  code never runs. The third is caught after importing it, and the")
    print("  report tells you which of the two happened.")
    return 0


def _example_plugins() -> Path | None:
    """The bundled example packages, wherever this copy of preflight was installed from.

    A wheel carries them at ``preflight/_examples``; a source checkout keeps
    them at the repository root, which is also where an editable install finds
    them. Neither location depends on the working directory, so ``demo`` runs
    the same from anywhere.
    """
    here = Path(__file__).resolve().parent
    candidates = (
        here / "_examples" / "plugins",
        here.parent.parent / "examples" / "plugins",
    )
    return next((path for path in candidates if path.is_dir()), None)


def _demo(args: argparse.Namespace) -> int:
    """Run the five bundled example plugins. Three of them deserve refusing."""
    examples = _example_plugins()
    if examples is None:
        print(
            "preflight: this build carries no example packages. Clone the\n"
            "repository and run `preflight demo` from inside it.",
            file=sys.stderr,
        )
        return 2

    from dataclasses import replace

    from preflight.load import load_plugins

    # The bundled examples are preflight's own, so there is no inspected folder
    # to guard against here -- but the settings still apply, because `demo` is a
    # command a person types and this is their standing rule.
    #
    # All of the settings, not just `refuse`. A settings file can set edition,
    # platform and max_manifest_bytes; `preflight settings` prints all four as
    # being in force and `--as-python` emits all four, so a demo honouring one of
    # them would be the display telling a lie. The flag still beats the file.
    settings = _settings_for(args)
    refuse = _refused_risks(args, settings)
    policy = replace(settings.as_policy(), refuse_tool_risks=refuse)

    # The demo has to play the host, and a host puts its plugin folder on
    # sys.path -- but it puts it back. This function is reachable as
    # `preflight.cli.main(["demo"])` from inside somebody else's program, and a
    # library whose documented promise is that it never touches sys.path does not
    # get to leave an entry behind. Anything already imported stays imported;
    # sys.modules is not what is being restored here.
    entry = str(examples)
    sys.path.insert(0, entry)
    try:
        result = load_plugins(
            examples,
            allow=[
                "example.greeter",
                "example.trespasser",
                "example.collider",
                "example.impostor",
                "example.janitor",
            ],
            policy=policy,
        )
    finally:
        if sys.path and sys.path[0] == entry:
            del sys.path[0]
    print()
    print(result)
    print()

    ran = sum(1 for outcome in result.outcomes if outcome.code_ran)
    refused = result.refused
    inert = sum(1 for outcome in refused if not outcome.code_ran)
    print(f"  The {ran} lines above reading `top-level plugin code is executing` are")
    print(
        f"  tripwires: the first statement in a plugin package. "
        f"{inert} of the {len(refused)} refused"
    )
    print("  plugins never printed one, because they never got an import.")

    if ToolRisk.DESTRUCTIVE in refuse:
        print()
        print("  Two of those refusals are worth comparing. janitor declared its")
        print("  destructive tool in its manifest, so --refuse stopped it while it")
        print("  was still inert on disk. impostor declares two read-only tools and")
        print("  produces a destructive third one only once loaded, where no")
        print("  declaration-based gate can see it -- it was caught afterwards, by")
        print("  comparing what it reported against what it had declared.")
        print()
        print("  preflight enforces declarations. It does not detect concealment.")
    return 0


#: Printed on every settings screen, without exception.
#:
#: A settings command makes preflight *look* like a scanner you configure and
#: point at downloads. It is a gate that lives inside your host. Without these
#: two lines the feature teaches the wrong model, and someone ships an
#: application believing a JSON file is guarding it.
_SCOPE_NOTE = (
    "  This applies to the preflight commands you type. It does not apply to a\n"
    "  running host -- see 'preflight settings --as-python'."
)


def _describe(settings: Settings) -> str:
    """The effective settings and where each one came from.

    Modelled on ``git config --list --show-origin``. A value with no source
    cannot answer the only question anyone actually has, which is why this is
    refusing something.
    """
    rows = [
        ("refuse", ", ".join(sorted(risk.value for risk in settings.refuse)) or "(nothing)"),
        ("edition", settings.edition.value),
        ("platform", (settings.platform or host_platform()).value),
        ("max_manifest_bytes", str(settings.max_manifest_bytes)),
    ]
    # ASCII only -- see the note in preflight.load.LoadReport.text.
    lines = ["preflight | settings", ""]
    name_width = max(len(name) for name, _ in rows)
    value_width = max(len(value) for _, value in rows)
    for name, value in rows:
        origin = settings.origins.get(name, Origin("default"))
        where = origin.scope
        if origin.path is not None:
            where = f"{where:<8} {origin.path}"
        elif origin.note:
            where = f"{where:<8} ({origin.note})"
        lines.append(f"  {name:<{name_width}}  {value:<{value_width}}  {where}".rstrip())

    lines.append("")
    if settings.profiles:
        lines.append(f"  profiles  {', '.join(settings.profiles)}")
        lines.append("  use one with: preflight check <path> --profile <name>")
    else:
        lines.append("  no profiles defined")
    lines += ["", _SCOPE_NOTE]
    return "\n".join(lines)


def _as_python(settings: Settings) -> str:
    """The ``Policy`` line to paste into a host, and the reason it is a paste.

    This is the bridge and the point of the whole command. A terminal experiment
    becomes a production gate by an explicit human act, in the host's own source
    where it can be reviewed -- rather than by a file preflight reads behind
    everyone's back.
    """
    parts = []
    if settings.refuse:
        parts.append(f"refuse_tool_risks={risk_set_literal(settings.refuse)}")
    if settings.edition is not Edition.PUBLIC:
        parts.append(f"edition=Edition.{settings.edition.name}")
    if settings.platform is not None:
        parts.append(f"platform=Platform.{settings.platform.name}")
    if settings.max_manifest_bytes != PluginRegistry.MAX_MANIFEST_BYTES:
        parts.append(f"max_manifest_bytes={settings.max_manifest_bytes}")

    imports = ["load_plugins"]
    if parts:
        imports.append("Policy")
    if settings.refuse:
        imports.append("ToolRisk")
    if settings.edition is not Edition.PUBLIC:
        imports.append("Edition")
    if settings.platform is not None:
        imports.append("Platform")

    policy = f"Policy({', '.join(parts)})" if parts else None
    lines = [
        f"from preflight import {', '.join(sorted(imports))}",
        "",
        "result = load_plugins(",
        '    "plugins",',
        '    allow=["acme.weather"],       # required, and there is no wildcard',
    ]
    if policy is not None:
        lines.append(f"    policy={policy},")
    lines.append(")")

    if policy is None:
        lines += [
            "",
            "# Your settings are all at their defaults, which are the strictest",
            "# values available, so no Policy is needed. Passing none at all is the",
            "# safest thing you can do.",
        ]
    return "\n".join(lines)


def _settings(args: argparse.Namespace) -> int:
    """Show, locate, or change the preferences the command line remembers."""
    scope = "user" if args.user else "project"

    if args.where:
        user = user_settings_path()
        project = find_project_settings()
        print("preflight | settings files")
        print()
        print(f"  user     {user}")
        print(f"           {'exists' if user.is_file() else 'not created yet'}")
        print()
        if project is not None:
            print(f"  project  {project}")
            print("           exists")
        else:
            print(f"  project  {settings_path_for('project')}")
            print(f"           not created yet -- no {SETTINGS_NAME} here or above")
        print()
        print(_SCOPE_NOTE)
        return 0

    if args.field is not None:
        # Only `refuse` is settable from the command line today. The file format
        # carries the other Policy fields and load_settings reads them, but a
        # flag for each would be surface nobody has asked for.
        if args.clear:
            value = None
        elif args.value is None:
            print(
                f"preflight: `settings {args.field}` needs a value, "
                f"or --clear to remove it.\n"
                f"    preflight settings refuse financial,write\n"
                f"    preflight settings refuse --clear",
                file=sys.stderr,
            )
            return 2
        else:
            risks = parse_risks(
                [name.strip() for name in args.value.split(",") if name.strip()],
                where="--refuse",
            )
            value = sorted(risk.value for risk in risks)
        path = save_setting(
            args.field, value, scope=scope, profile=args.profile, cwd=None
        )
        where = f"profile '{args.profile}' in {path}" if args.profile else str(path)
        action = "cleared" if value is None else f"set to {', '.join(value) or '(nothing)'}"
        print(f"{args.field} {action}")
        print(f"  in {where}")
        print()
        print(_SCOPE_NOTE)
        return 0

    settings = load_settings(profile=args.profile)
    if args.as_python:
        print(_as_python(settings))
        return 0
    print(_describe(settings))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Decide whether a plugin may load from its manifest alone, "
            "before any of its code runs."
        ),
        epilog=(
            "These commands are for the moment you adopt a package you did not\n"
            "write. They are not the product, and running one protects nothing\n"
            "later -- none of this is running when your application is.\n"
            "\n"
            "The gate itself goes inside your program and runs at every startup:\n"
            "\n"
            "    from preflight import load_plugins\n"
            "    result = load_plugins('plugins', allow=['acme.weather'])\n"
            "\n"
            "Packages in that folder but missing from allow are never imported."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"preflight {__version__}",
        help="print the installed version and exit",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser(
        "check",
        help="read a package's manifest and declared tools. Executes nothing.",
        description=(
            "Reads the manifest, resolves the entrypoint against the filesystem, "
            "and lists every tool the package claims. Nothing is imported, so this "
            "is safe to run on code you have not read. It cannot tell you whether "
            "the package does what it says. With --refuse it exits non-zero on a "
            "package your host would turn away, which suits a pre-commit hook."
        ),
    )
    check.add_argument("path", help="a plugin package, or a folder of them")
    _add_refuse_flag(check)
    _add_profile_flag(check)
    check.set_defaults(handler=_check)

    create = commands.add_parser(
        "create",
        help="write a manifest for a package that has none",
        description=(
            "Writes a manifest.json recording what you permit this package to do. "
            "preflight does not read the package's code to fill it in."
        ),
    )
    create.add_argument("path", help="the plugin package directory")
    create.add_argument("--entrypoint", help="module:attribute to call, e.g. pkg.plugin:build")
    create.add_argument("--package-id", help="dotted package id, e.g. acme.weather")
    create.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    create.set_defaults(handler=_create)

    sandbox = commands.add_parser(
        "try",
        help="write a working host and plugin you can break on purpose",
        description=(
            "Writes a folder containing a 12-line host, one plugin that loads, "
            "and its manifest. Unlike `create`, this invents the code as well as "
            "the paperwork -- it is a sandbox, not a starting point for something "
            "you intend to ship. Break the files it writes and rerun the host: "
            "the refusals are the part worth reading."
        ),
    )
    sandbox.add_argument(
        "path",
        nargs="?",
        default="preflight-sandbox",
        help="folder to write into (default: preflight-sandbox)",
    )
    sandbox.add_argument(
        "--force", action="store_true", help="write into a folder that is not empty"
    )
    sandbox.set_defaults(handler=_try)

    demo = commands.add_parser(
        "demo",
        help="load five example plugins; three of them get refused",
        description=(
            "Loads the bundled examples through the real gate. Pass "
            "--refuse destructive to watch a fourth one get refused for a tool "
            "it declared honestly -- and to see the one that lied slip past the "
            "flag entirely, because it never declared anything."
        ),
    )
    _add_refuse_flag(demo)
    _add_profile_flag(demo)
    demo.set_defaults(handler=_demo)

    settings = commands.add_parser(
        "settings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="save the rules you would otherwise retype on every command",
        description=(
            "Remembers the --refuse rules you would otherwise retype, per project "
            "and per agent. With no arguments it prints the effective settings and "
            "where each one came from."
        ),
        epilog=(
            "This configures the commands you type. It does not configure a running\n"
            "host: a host states its policy in its own source, where it is\n"
            "reviewable and nothing on disk can move it. `--as-python` prints the\n"
            "line to paste there, which is the only way the two are ever connected.\n"
            "\n"
            "Settings are read from your working directory and your user config\n"
            "directory only. A settings file inside a package being inspected is\n"
            "ignored, because preflight is not configured by the thing it judges."
        ),
    )
    settings.add_argument(
        "field",
        nargs="?",
        choices=["refuse"],
        help="the setting to change. Omit to show everything.",
    )
    settings.add_argument(
        "value",
        nargs="?",
        metavar="RISK[,RISK...]",
        help="the new value, e.g. financial,write",
    )
    settings.add_argument(
        "--clear", action="store_true", help="remove the setting from this scope"
    )
    settings.add_argument(
        "--user",
        action="store_true",
        help="read or write your user-wide file instead of this project's",
    )
    settings.add_argument(
        "--profile",
        metavar="NAME",
        help="a named set of rules, one per agent, kept in the same file",
    )
    settings.add_argument(
        "--where",
        action="store_true",
        help="print the settings file paths, whether they exist or not",
    )
    settings.add_argument(
        "--as-python",
        dest="as_python",
        action="store_true",
        help="print the Policy(...) call to paste into your host",
    )
    settings.set_defaults(handler=_settings)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except SettingsError as problem:
        # Exit 2, never 1. On `check`, 1 already means "would be refused", and a
        # script acting on the answer cannot tell two meanings apart.
        print(f"preflight: {problem}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
