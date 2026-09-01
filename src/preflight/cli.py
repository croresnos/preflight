"""``preflight`` on the command line.

The stable 0.7 admission-gate commands are::

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
import hashlib
import json
import keyword
import re
import sys
from pathlib import Path

from preflight import __version__
from preflight.inspect import (
    MANIFEST_NAME,
    format_inspection,
    inspect_directory,
    module_defines,
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

#: The name every generated entrypoint uses. A convention, not a rule -- the
#: manifest may name any public attribute -- but the one that has to be spelled
#: identically by the guesser, the stub it writes, and the docs quoting both.
ENTRYPOINT_ATTRIBUTE = "create_plugin"


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


def _settings_for(
    args: argparse.Namespace, *, inspected: Path | None = None
) -> Settings:
    """Load saved settings for a command that consults them.

    ``inspected`` is the folder the command is about to read, and is passed so
    :func:`~preflight.settings.load_settings` can drop -- loudly -- a settings
    file sitting inside it.
    """
    resolved = load_settings(
        profile=getattr(args, "profile", None), inspected=inspected
    )
    for item in resolved.ignored:
        print(
            f"preflight: ignoring {item.path}\n"
            f"           {item.reason}.\n"
            f"           {item.remedy}",
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
            "tighten. Valid: " + ", ".join(risk.value for risk in ToolRisk)
        ),
    )


def _slug(name: str) -> str:
    """A folder name turned into something a Python module could be called."""
    cleaned = _NOT_IDENTIFIER.sub("_", name).strip("_").lower()
    if not cleaned:
        return "plugin"
    if cleaned[0].isdigit() or keyword.iskeyword(cleaned):
        return f"plugin_{cleaned}"
    return cleaned


def _guess_entrypoint(folder: Path) -> str:
    """Propose an entrypoint from what is on disk. ``check`` verifies it after.

    Two shapes come out of this, and which one depends on whether the package
    already has a ``create_plugin`` to point at. Naming one that is not there
    used to be the default, and it produced a manifest that passed ``check`` and
    was refused at startup. A package that has never heard of preflight gets the
    bare form instead, which loads: preflight adapts the module using the
    manifest, and says so wherever it reports on the package.
    """
    module = _slug(folder.name)
    if not (folder / "__init__.py").is_file():
        # Not a package at all yet. `check` reports that, and no entrypoint this
        # function invents is more true than another -- so keep the shape the
        # sandbox and every worked example use.
        return f"{module}.plugin:create_plugin"

    if (folder / "plugin.py").is_file():
        candidate, dotted = folder / "plugin.py", f"{module}.plugin"
    else:
        candidate, dotted = folder / "__init__.py", module
    if module_defines(candidate, ENTRYPOINT_ATTRIBUTE):
        return f"{dotted}:{ENTRYPOINT_ATTRIBUTE}"
    return dotted


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
        # A refusal the host only reaches after importing is still a refusal, and
        # a worse one. The report keeps the two apart because the difference is
        # what ran; the exit code does not, because the caller's question is
        # whether this loads.
        and not item.late_refusals()
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

    adapter_path = folder / "plugin.py"
    if args.adapter:
        if adapter_path.exists():
            print(
                f"preflight: {adapter_path} already exists, and --adapter writes\n"
                f"that file. preflight will not overwrite your Python. Point the\n"
                f"entrypoint at what is already in there:\n"
                f"    preflight create {folder} "
                f"--entrypoint {slug}.plugin:{ENTRYPOINT_ATTRIBUTE}",
                file=sys.stderr,
            )
            return 2
        if not (folder / "__init__.py").is_file():
            print(
                f"preflight: '{folder.name}' has no __init__.py, so it is not a\n"
                f"package and nothing inside it can be imported by name. Create\n"
                f"that file first, then run this again.",
                file=sys.stderr,
            )
            return 2

    entrypoint = args.entrypoint or (
        f"{slug}.plugin:{ENTRYPOINT_ATTRIBUTE}"
        if args.adapter
        else _guess_entrypoint(folder)
    )
    manifest = {
        "schema_version": "1.0",
        "package_id": args.package_id or f"local.{slug}",
        "core_api_version": "1.0",
        "visibility": "public",
        "release_ring": "stable",
        "entrypoint": entrypoint,
        "plugin": {
            "schema_version": "1.0",
            "plugin_id": slug,
            "name": folder.name,
            "module_version": "0.1.0",
            "tools": [],
        },
    }
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    written = [destination]
    if args.adapter:
        adapter_path.write_text(
            _adapter_source(slug=slug, name=folder.name), encoding="utf-8"
        )
        written.append(adapter_path)

    for path in written:
        print(f"wrote {path}")
    print()
    print("  This manifest records what you PERMIT this package to do. preflight")
    print("  did not read its code and has not checked whether the two agree.")
    print("  An empty `tools` list means it may expose none.")
    print()
    if args.adapter:
        print("  The adapter states the same thing in Python, and the gate requires")
        print("  the two to agree. That is the check you are buying with the")
        print("  duplication -- edit both together, or they stop agreeing.")
    elif ":" not in entrypoint:
        # The quiet case, and the one worth saying out loud: nothing in this
        # package points back at preflight, so there is no second statement for
        # the gate to check this file against.
        print("  This package does not report its own manifest, so preflight will")
        print("  adapt it using this file. Everything else is checked as usual.")
        print("  To have the package state its own manifest and be checked against")
        print("  it, run again with --adapter.")
    print()
    print("  Next:")
    print(f"      preflight check {folder}")
    return 0


def _adapter_source(*, slug: str, name: str) -> str:
    """The stub ``--adapter`` writes, matching the manifest written beside it."""
    return f'''\
"""What this package reports about itself, for preflight to check.

Every value below must equal the matching field in manifest.json. The registry
validates that file first, then requires this object to report the same thing --
so a version bumped here and not there is a refusal, which is the point.
"""

from preflight import PluginManifest

_MANIFEST = PluginManifest.model_validate({{
    "plugin_id": "{slug}",
    "name": "{name}",
    "module_version": "0.1.0",
    "tools": [],
}})


class {_class_name(slug)}:
    @property
    def manifest(self) -> PluginManifest:
        return _MANIFEST

    # Your package's own methods go here. preflight never calls them.


def {ENTRYPOINT_ATTRIBUTE}() -> {_class_name(slug)}:
    return {_class_name(slug)}()
'''


def _class_name(slug: str) -> str:
    """A class name from a package slug: ``my_notes`` -> ``MyNotes``."""
    return "".join(part.title() for part in slug.split("_") if part) or "PluginAdapter"


_SANDBOX_PLUGIN = """\
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
"""

_SANDBOX_HOST = """\
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

# A refusal is data, not an exception, so nothing above this line stopped the
# program. What a refusal means is the host's decision and it differs: an editor
# carries on without the plugin, a build fails. This one fails, so a break is
# visible to a script and not only to your eyes.
sys.exit(1 if result.refused else 0)
"""

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

#: Written into the sandbox, so that breaking it is one short command that is
#: the same everywhere. It used to be a table of shell one-liners chosen by
#: `os.name`, which picks an operating system and not a shell -- so a reader in
#: Git Bash on Windows got PowerShell and `bash: Remove-Item: command not
#: found`. `python` is the one interpreter every reader here demonstrably has:
#: the next line of every exercise is `python host.py`.
_SANDBOX_BREAK = '''\
"""The three breaks from `preflight try`, so each one is a single command.

Every break below is two lines you could type yourself. They live in a file so
the instruction is identical in bash, PowerShell, zsh and cmd -- and so that
running one prints what it changed, which a shell one-liner does not.

    python break.py 2          # misspell the entrypoint
    python host.py             # read the refusal
    python break.py 2 --undo   # put it back
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE / "plugins" / "weather"


def _swap(path, old, new):
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return f"{path.relative_to(HERE)} does not contain {old} -- nothing to do"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return f"{path.relative_to(HERE)}: {old} -> {new}"


def missing_init(undo):
    """The __init__.py that makes the folder a package, and not a namespace."""
    target = PACKAGE / "__init__.py"
    if undo:
        target.touch()
        return f"created {target.relative_to(HERE)}"
    if not target.exists():
        return f"{target.relative_to(HERE)} is already gone -- nothing to do"
    target.unlink()
    return f"deleted {target.relative_to(HERE)}"


def wrong_entrypoint(undo):
    """A one-letter typo in the manifest's entrypoint."""
    old, new = ("wether.plugin", "weather.plugin") if undo else ("weather.plugin", "wether.plugin")
    return _swap(PACKAGE / "manifest.json", old, new)


def version_drift(undo):
    """A version bumped in the code and not in the manifest beside it."""
    old, new = ('"2.0.0"', '"1.0.0"') if undo else ('"1.0.0"', '"2.0.0"')
    return _swap(PACKAGE / "plugin.py", old, new)


BREAKS = {
    "1": ("delete the __init__.py that makes it a package", missing_init),
    "2": ("misspell the entrypoint in manifest.json", wrong_entrypoint),
    "3": ("bump module_version in plugin.py only, not in manifest.json", version_drift),
}


def main(argv):
    undo = "--undo" in argv
    chosen = [arg for arg in argv if arg != "--undo"]
    if len(chosen) != 1 or chosen[0] not in BREAKS:
        print("usage: python break.py <1|2|3> [--undo]\\n")
        for number, (title, _) in BREAKS.items():
            print(f"  {number}. {title}")
        return 2
    title, apply = BREAKS[chosen[0]]
    print(("undoing: " if undo else "breaking: ") + title)
    print("  " + apply(undo))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


_SANDBOX_MARKER = ".preflight-sandbox.json"
_SANDBOX_GENERATED = frozenset(
    {
        _SANDBOX_MARKER,
        "host.py",
        "break.py",
        "plugins/weather/__init__.py",
        "plugins/weather/plugin.py",
        f"plugins/weather/{MANIFEST_NAME}",
    }
)


def _sandbox_file_hashes() -> dict[str, str]:
    payloads = {
        "host.py": _SANDBOX_HOST,
        "break.py": _SANDBOX_BREAK,
        "plugins/weather/__init__.py": "",
        "plugins/weather/plugin.py": _SANDBOX_PLUGIN,
        f"plugins/weather/{MANIFEST_NAME}": (
            json.dumps(_SANDBOX_MANIFEST, indent=2) + "\n"
        ),
    }
    return {
        name: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for name, value in payloads.items()
    }


def _is_sandbox(root: Path) -> bool:
    """Whether this folder is one ``try`` wrote, rather than somebody's own work.

    Both files, because either alone is something a person could plausibly have
    of their own: ``host.py`` is an ordinary name, and a ``plugins/weather/``
    package is the shape this command exists to teach.
    """
    marker = root / _SANDBOX_MARKER
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        hashes = data["initial_sha256"]
        if (
            data.get("format") != 1
            or set(hashes) != _SANDBOX_GENERATED - {_SANDBOX_MARKER}
            or not all(
                isinstance(value, str)
                and len(value) == 64
                and all(char in "0123456789abcdef" for char in value)
                for value in hashes.values()
            )
        ):
            return False
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        }
        if actual != _SANDBOX_GENERATED:
            return False
        return not any(path.is_symlink() for path in root.rglob("*"))
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return False


def _try(args: argparse.Namespace) -> int:
    """Write a working host and one plugin, so there is something to break.

    ``create`` will not do this. It writes a manifest for code you wrote and
    refuses to invent the code, because a manifest records what *you* permit and
    preflight guessing at that would defeat the point. This command is not that:
    it is a sandbox to take apart, and it says so in what it prints.
    """
    requested_root = Path(args.path)
    if requested_root.is_symlink():
        print(
            f"preflight: '{requested_root}' is a symlink; try will not write "
            "through it.",
            file=sys.stderr,
        )
        return 2
    root = requested_root.resolve()
    if root.exists() and any(root.iterdir()):
        # Two situations, and only one of them has a way forward. The exercises
        # below leave the sandbox broken on purpose, and undoing them is a manual
        # step somebody can skip or mistype -- so a returning reader meets a
        # folder in a state nothing on screen explains, and `--force` is the
        # reset for it. A folder preflight did not write is the other situation,
        # and there is no flag for it: this command writes `host.py` and
        # `plugins/`, and overwriting somebody's own `host.py` is the one
        # irreversible thing it could do.
        if not _is_sandbox(root):
            print(
                f"preflight: '{root}' has files preflight did not write.\n"
                f"`try` writes host.py and plugins/, and it will not overwrite your\n"
                f"work to do it -- --force resets a sandbox, it does not take a\n"
                f"folder over. Name a folder that does not exist yet.",
                file=sys.stderr,
            )
            return 2
        if not args.force:
            print(
                f"preflight: '{root}' is already a preflight sandbox.\n"
                f"It may have been left part-way through one of the exercises. Pass\n"
                f"--force to reset it to the working state.",
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
    (root / "break.py").write_text(_SANDBOX_BREAK, encoding="utf-8")
    (root / _SANDBOX_MARKER).write_text(
        json.dumps(
            {"format": 1, "initial_sha256": _sandbox_file_hashes()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"wrote {root}")
    print("      host.py                          the gate, 12 lines")
    print("      break.py                         the three exercises below")
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
    for number, title in enumerate(_BREAK_TITLES, 1):
        print()
        print(f"  {number}. {title}")
        print(f"       python break.py {number}")
        print("       python host.py")
        print(f"       python break.py {number} --undo")
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
    else:
        # The plain run is the one a first-timer does, and it is the one that
        # leaves out the sharpest thing this demo can show. Point at it rather
        # than print five more lines nobody asked for.
        print()
        print("  Try `preflight demo --refuse destructive` to watch a fourth")
        print("  plugin refused for a tool it declared honestly -- and the one")
        print("  that lied slip past the flag, because it declared nothing.")
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
        (
            "refuse",
            ", ".join(sorted(risk.value for risk in settings.refuse)) or "(nothing)",
        ),
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
        lines.append(
            f"  {name:<{name_width}}  {value:<{value_width}}  {where}".rstrip()
        )

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
        '    allow=["acme.weather"],  # required, and there is no wildcard',
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
        action = (
            "cleared" if value is None else f"set to {', '.join(value) or '(nothing)'}"
        )
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
    create_shape = create.add_mutually_exclusive_group()
    create_shape.add_argument(
        "--entrypoint",
        help=(
            "module:attribute to call, e.g. pkg.plugin:build -- or a bare module, "
            "e.g. pkg, to have preflight adapt it using the manifest"
        ),
    )
    create.add_argument("--package-id", help="dotted package id, e.g. acme.weather")
    create_shape.add_argument(
        "--adapter",
        action="store_true",
        help=(
            "also write a plugin.py stating this manifest in Python, so the gate "
            "can require the two to agree"
        ),
    )
    create.add_argument(
        "--force", action="store_true", help="overwrite an existing manifest"
    )
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
        "--force",
        action="store_true",
        help="reset a sandbox left part-way through an exercise",
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
