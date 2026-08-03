"""``preflight`` on the command line.

Three commands, and the important one is the first::

    preflight check ./some-plugin      # read its paperwork. Executes nothing.
    preflight init  ./some-plugin      # write down what you will permit it to do
    preflight demo                     # watch three plugins get refused

``check`` is the command you run on something you downloaded and have not read.
It is safe to point at untrusted code because it never imports it -- see
:mod:`preflight.inspect`. It is *not* a malware scanner, does not read the
package's code, and cannot tell you whether a package does what it says. It
tells you what the package **claims**, and whether those claims are coherent.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from preflight.inspect import MANIFEST_NAME, format_inspection, inspect_directory

_NOT_IDENTIFIER = re.compile(r"[^0-9a-zA-Z_]+")


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


def _check(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.is_dir():
        print(f"preflight: '{target}' is not a directory", file=sys.stderr)
        return 2

    inspections = inspect_directory(target)
    for index, inspection in enumerate(inspections):
        if index:
            print()
        print(format_inspection(inspection))
    return 0 if all(item.consistent for item in inspections) else 1


def _init(args: argparse.Namespace) -> int:
    folder = Path(args.path)
    if not folder.is_dir():
        print(f"preflight: '{folder}' is not a directory", file=sys.stderr)
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


def _demo(_args: argparse.Namespace) -> int:
    """Run the four bundled example plugins. Three of them deserve refusing."""
    examples = Path(__file__).resolve().parent.parent.parent / "examples" / "plugins"
    if not examples.is_dir():
        print(
            "preflight: the demo ships with the source. Clone the repository and\n"
            "run `preflight demo` from inside it.",
            file=sys.stderr,
        )
        return 2

    from preflight.load import load_plugins

    sys.path.insert(0, str(examples))
    result = load_plugins(
        examples,
        allow=[
            "example.greeter",
            "example.trespasser",
            "example.collider",
            "example.impostor",
        ],
    )
    print()
    print(result)
    print()
    print("  The two lines above reading `top-level plugin code is executing` are")
    print("  tripwires: the first statement in a plugin package. Two of the three")
    print("  refused plugins never printed one, because they never got an import.")
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
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser(
        "check",
        help="read a package's manifest and declared tools. Executes nothing.",
        description=(
            "Reads the manifest, resolves the entrypoint against the filesystem, "
            "and lists every tool the package claims. Nothing is imported, so this "
            "is safe to run on code you have not read. It cannot tell you whether "
            "the package does what it says."
        ),
    )
    check.add_argument("path", help="a plugin package, or a folder of them")
    check.set_defaults(handler=_check)

    init = commands.add_parser(
        "init",
        help="write a manifest for a package that has none",
        description=(
            "Writes a manifest.json recording what you permit this package to do. "
            "preflight does not read the package's code to fill it in."
        ),
    )
    init.add_argument("path", help="the plugin package directory")
    init.add_argument("--entrypoint", help="module:attribute to call, e.g. pkg.plugin:build")
    init.add_argument("--package-id", help="dotted package id, e.g. acme.weather")
    init.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    init.set_defaults(handler=_init)

    demo = commands.add_parser(
        "demo", help="load four example plugins; three of them get refused"
    )
    demo.set_defaults(handler=_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
