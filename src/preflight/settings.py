"""Saved preferences for the command line -- and nothing else.

    preflight settings refuse financial,write

Retyping ``--refuse financial,write,destructive`` on every invocation is the
only way to state a standing rule at a terminal, and there is nowhere to write
down "in this project, I never accept financial tools". This module is that
place.

It is deliberately not wired into the gate. Read
:class:`~preflight.load.Policy`: a host states its policy in its own source,
where it is reviewable and nothing on disk can move it. ``load_plugins`` does
not import this module and must never learn how -- the import runs the other
way, from here into :mod:`preflight.load`, so a cycle is what any attempt would
produce. What is saved here changes the commands *a person types*, and stops
there.

Two rules hold the rest of it up.

**Discovery starts at the working directory, never at the thing being
inspected.** Walking up from an inspected folder would let anyone who can place
a directory place a settings file above it saying "refuse nothing" -- the gate
would then be configured by the party it is judging. So the search anchors to
the cwd and to the user's own config directory, and a file found *inside* the
directory under inspection is ignored out loud.

**There is no ``allow`` field.** The allowlist is required, has no wildcard, and
lives in host code on purpose. A file that can add package ids to an allowlist
is precisely the attack the paragraph above exists to prevent, so writing one is
an error with its own message rather than a key that is quietly dropped.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

from preflight.load import Policy
from preflight.manifest import Platform, ToolRisk
from preflight.registry import Edition, PluginRegistry

#: The filename preflight looks for, in the cwd and its ancestors. Never inside
#: a plugin package -- see the module docstring.
SETTINGS_NAME = "preflight.settings.json"

#: Bumped only if the file's shape changes incompatibly. A reader that does not
#: recognise the value refuses the file rather than guessing at it.
SETTINGS_VERSION = 1

#: What marks a directory as one a person deliberately made, rather than one that
#: arrived in an archive. A settings file may only reach *down* onto a package
#: being inspected from a directory carrying one of these.
#:
#: Be exact about what this is worth. Every name here is a file or folder an
#: archive can contain, so a package that ships its own ``pyproject.toml`` beside
#: its own settings file defeats the check -- see :func:`load_settings`. It stops
#: the realistic case, which is an unpacked folder that carries a settings file
#: and nothing else, and it is not a lock. The only anchor an attacker cannot
#: forge is the user-scope file, because it lives outside every directory a
#: package is ever unpacked into.
PROJECT_MARKERS = (".git", ".hg", "pyproject.toml", ".preflight-root")

#: Everything a settings file may set. These are the :class:`Policy` fields and
#: nothing more; ``allow`` is absent by design and rejected by name below.
SETTABLE = ("refuse", "edition", "platform", "max_manifest_bytes")

_TOP_LEVEL = frozenset({"version", "profiles", *SETTABLE})


class SettingsError(Exception):
    """A settings file could not be used, with a sentence saying why.

    The command line turns this into exit ``2`` -- "you gave me something I
    cannot work with" -- never ``1``, which already means "would be refused"
    and must not come to mean two things.
    """


@dataclass(frozen=True)
class Origin:
    """Where one effective value came from, so a person can go change it.

    ``git config --list --show-origin`` is the model. "Why is this refusing?" is
    the only question anyone actually has, and a value without a source cannot
    answer it.
    """

    #: One of ``default``, ``user``, ``project``, ``profile``, ``flag``.
    scope: str
    path: Path | None = None
    #: A short parenthetical for the display, e.g. "the running OS".
    note: str = ""


@dataclass(frozen=True)
class Ignored:
    """A settings file that was found and deliberately not used."""

    path: Path
    reason: str
    #: What the reader can do about it. Carried per rejection rather than
    #: appended by the caller, because the two rejections have different
    #: remedies: a file *inside* the inspected folder has to move, and a file
    #: *above* it is already where it belongs and needs the directory marked.
    #: One shared tail could only ever be right about one of them.
    remedy: str = (
        "preflight is not configured by the thing it is inspecting.\n"
        "           Move it to your project root to have it apply."
    )


@dataclass(frozen=True)
class Settings:
    """The effective preferences, and the provenance of each one."""

    refuse: frozenset[ToolRisk] = frozenset()
    edition: Edition = Edition.PUBLIC
    platform: Platform | None = None
    max_manifest_bytes: int = PluginRegistry.MAX_MANIFEST_BYTES
    origins: Mapping[str, Origin] = field(default_factory=dict)
    #: Profile names available, from both scopes, sorted.
    profiles: tuple[str, ...] = ()
    #: Files that were found and deliberately not used. The CLI reports these on
    #: stderr, because a person who put one there needs to learn why it did
    #: nothing rather than assume it worked.
    ignored: tuple[Ignored, ...] = ()

    def as_policy(self) -> Policy:
        """The :class:`Policy` these settings describe.

        This is the only bridge between a file on disk and the gate's own type,
        and it is crossed by the command line alone.
        """
        return Policy(
            edition=self.edition,
            platform=self.platform,
            refuse_tool_risks=self.refuse,
            max_manifest_bytes=self.max_manifest_bytes,
        )


# --- where files live -----------------------------------------------------


def user_settings_path() -> Path:
    """The per-user settings file, in the operator's own config directory.

    ``%APPDATA%`` on Windows, ``$XDG_CONFIG_HOME`` (default ``~/.config``)
    elsewhere. Both are places a plugin has no business writing to, which is the
    only property that matters here.
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Roaming"
    else:
        base = os.environ.get("XDG_CONFIG_HOME")
        root = Path(base) if base else Path.home() / ".config"
    return root / "preflight" / "settings.json"


def is_project_root(directory: Path) -> bool:
    """Does this directory look like one a person deliberately made?

    See :data:`PROJECT_MARKERS` for what this is worth, and what it is not.
    """
    return any((directory / marker).exists() for marker in PROJECT_MARKERS)


def _project_candidates(cwd: Path | str | None = None) -> Iterator[Path]:
    """Every settings file at or above ``cwd``, nearest first, to a repo boundary.

    ``cwd`` -- the working directory, and never a directory being inspected.
    The distinction is the whole security argument: see the module docstring.

    The walk stops at the first directory containing ``.git``, because that is
    where a person's idea of "this project" ends. Without the stop, a file in a
    shared parent -- a home directory, ``C:\\Code`` -- would silently govern
    every unrelated project underneath it.

    This yields rather than returning the first hit so that a caller rejecting a
    candidate can keep climbing. That matters: a rejected file must not take the
    project scope down with it, or planting one inside a package would suppress
    the rules a person actually wrote, which is an attack on the gate by another
    route.
    """
    start = Path(cwd).resolve() if cwd is not None else Path.cwd().resolve()
    for directory in (start, *start.parents):
        candidate = directory / SETTINGS_NAME
        if candidate.is_file():
            yield candidate
        if is_project_root(directory):
            return


def find_project_settings(cwd: Path | str | None = None) -> Path | None:
    """The nearest settings file at or above ``cwd``, if there is one."""
    return next(_project_candidates(cwd), None)


def _is_inside(path: Path, directory: Path) -> bool:
    """Is ``path`` at or under ``directory``? Case-insensitively on Windows.

    ``os.path.normcase`` is what makes this true on a filesystem where
    ``C:\\Plugins`` and ``c:\\plugins`` are one directory. Comparing raw strings
    would let a difference in capitalisation walk straight through the check
    below, which is the check the feature's safety rests on.
    """
    try:
        resolved = path.resolve()
        root = directory.resolve()
    except OSError:  # pragma: no cover - unreadable path is not ours to explain
        return False
    normalised = os.path.normcase(str(resolved))
    prefix = os.path.normcase(str(root))
    return normalised == prefix or normalised.startswith(prefix + os.sep)


# --- reading --------------------------------------------------------------


def _read(path: Path) -> dict[str, Any]:
    """Parse one settings file, or raise :class:`SettingsError` saying why not.

    Every failure here is a sentence, not a traceback. A person who has just
    hand-edited JSON needs to know which file and which key, and gets no help
    from a stack.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise SettingsError(
            f"{path} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from None

    if not isinstance(payload, dict):
        raise SettingsError(
            f"{path} must contain a JSON object, not {type(payload).__name__}. "
            f'The simplest valid file is:  {{"version": 1, "refuse": []}}'
        )

    version = payload.get("version", SETTINGS_VERSION)
    if version != SETTINGS_VERSION:
        raise SettingsError(
            f"{path} declares version {version!r}, and this preflight understands "
            f"version {SETTINGS_VERSION}."
        )

    if "allow" in payload:
        raise SettingsError(
            f"{path} sets 'allow', and a settings file may not.\n"
            f"The allowlist is the one thing that decides whether a package is "
            f"imported at all.\nIt lives in your host's source, where it is "
            f"reviewable -- not in a file on disk that\nsomething else might come "
            f"to write. Remove the key."
        )

    unknown = sorted(set(payload) - _TOP_LEVEL)
    if unknown:
        raise SettingsError(
            f"{path} has unrecognised key{'' if len(unknown) == 1 else 's'}: "
            f"{', '.join(unknown)}.\nValid keys: {', '.join(sorted(_TOP_LEVEL))}.\n"
            f"preflight refuses a file it cannot fully understand rather than "
            f"ignoring the parts it does not recognise."
        )

    profiles = payload.get("profiles", {})
    if not isinstance(profiles, dict):
        raise SettingsError(f"{path}: 'profiles' must be an object of name -> settings")
    for name, block in profiles.items():
        if not isinstance(block, dict):
            raise SettingsError(f"{path}: profile '{name}' must be an object")
        extra = sorted(set(block) - set(SETTABLE))
        if extra:
            raise SettingsError(
                f"{path}: profile '{name}' has unrecognised key"
                f"{'' if len(extra) == 1 else 's'}: {', '.join(extra)}.\n"
                f"A profile may set: {', '.join(SETTABLE)}."
            )
    return payload


def parse_risks(names: Any, *, where: str) -> frozenset[ToolRisk]:
    """Turn a list of risk names into ``ToolRisk`` values, or say what is wrong."""
    if isinstance(names, str) or not isinstance(names, (list, tuple)):
        raise SettingsError(
            f"{where}: 'refuse' must be a list of risk names, "
            f'e.g. ["financial", "write"]'
        )
    risks = set()
    for name in names:
        try:
            risks.add(ToolRisk(str(name).lower()))
        except ValueError:
            valid = ", ".join(risk.value for risk in ToolRisk)
            raise SettingsError(
                f"{where}: unknown risk '{name}'. Valid risks: {valid}"
            ) from None
    return frozenset(risks)


def _apply(
    block: Mapping[str, Any],
    values: dict[str, Any],
    origins: dict[str, Origin],
    origin: Origin,
    *,
    where: str,
) -> None:
    """Overlay one block of settings, recording where each value came from."""
    if "refuse" in block:
        values["refuse"] = parse_risks(block["refuse"], where=where)
        origins["refuse"] = origin
    if "edition" in block:
        try:
            values["edition"] = Edition(str(block["edition"]).lower())
        except ValueError:
            valid = ", ".join(item.value for item in Edition)
            raise SettingsError(
                f"{where}: unknown edition '{block['edition']}'. Valid: {valid}"
            ) from None
        origins["edition"] = origin
    if "platform" in block:
        try:
            values["platform"] = Platform(str(block["platform"]).lower())
        except ValueError:
            valid = ", ".join(item.value for item in Platform)
            raise SettingsError(
                f"{where}: unknown platform '{block['platform']}'. Valid: {valid}"
            ) from None
        origins["platform"] = origin
    if "max_manifest_bytes" in block:
        size = block["max_manifest_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise SettingsError(
                f"{where}: 'max_manifest_bytes' must be a positive whole number"
            )
        values["max_manifest_bytes"] = size
        origins["max_manifest_bytes"] = origin


def load_settings(
    *,
    cwd: Path | str | None = None,
    profile: str | None = None,
    inspected: Path | str | None = None,
) -> Settings:
    """Resolve the effective settings, lowest precedence first.

    ``default`` -> ``user`` -> ``project`` -> ``profile``. The command line adds
    the last and highest layer itself, because a flag has to beat a file:
    someone reaching for one is usually trying to get *out* of what the file
    says, and an override that only narrows is not an override.

    ``inspected`` is the directory a command is about to read. A settings file
    found inside it is dropped and reported in :attr:`Settings.ignored` -- the
    file is in the hands of whatever wrote that folder, and preflight will not
    be configured by the thing it is inspecting.
    """
    values: dict[str, Any] = {
        "refuse": frozenset(),
        "edition": Edition.PUBLIC,
        "platform": None,
        "max_manifest_bytes": PluginRegistry.MAX_MANIFEST_BYTES,
    }
    origins: dict[str, Origin] = {
        "refuse": Origin("default"),
        "edition": Origin("default"),
        "platform": Origin("default", note="the running OS"),
        "max_manifest_bytes": Origin("default"),
    }
    ignored: list[Ignored] = []
    profiles: dict[str, Mapping[str, Any]] = {}

    target = Path(inspected).resolve() if inspected is not None else None

    def usable(path: Path) -> bool:
        """The hard rule, in the one place every scope passes through.

        Two rejections, and they are different attacks.

        A file *inside* the folder being inspected is in the hands of whatever
        wrote that folder. A file *above* it is more interesting: dropping a
        settings file beside an unpacked package reaches down onto it, and
        beats the first check because the file is not inside anything. So a file
        may only govern a package beneath it from a directory that looks
        deliberately made -- see :data:`PROJECT_MARKERS`, including the sentence
        about what that is not worth.

        Neither rejection ends the search: see :func:`_project_candidates`. A
        rejected file must not take the rules a person actually wrote down with
        it, or planting one would suppress them, which is as good an outcome for
        an attacker as choosing them.
        """
        if target is None:
            return True
        if _is_inside(path, target):
            ignored.append(
                Ignored(
                    path,
                    "it is inside the folder being inspected, so it is in the "
                    "hands of\n           whatever put it there",
                )
            )
            return False
        if _is_inside(target, path.parent) and not is_project_root(path.parent):
            # Naming the markers rather than alluding to them. "No sign of
            # having been set up by hand" is true and unactionable: the reader
            # is holding a file they wrote on purpose, being told it looks
            # accidental, with nothing to do about it. The remedy is one
            # `touch`, and it belongs on the screen where the problem is.
            markers = ", ".join(PROJECT_MARKERS)
            ignored.append(
                Ignored(
                    path,
                    "it sits above the folder being inspected, in a directory "
                    "nothing\n           marks as a project root",
                    remedy=(
                        f"A project root here is any of: {markers}.\n"
                        f"           Create one of those and this file applies."
                    ),
                )
            )
            return False
        return True

    user = user_settings_path()
    chosen: list[tuple[str, Path]] = []
    if user.is_file() and usable(user):
        chosen.append(("user", user))
    project = next((path for path in _project_candidates(cwd) if usable(path)), None)
    if project is not None:
        chosen.append(("project", project))

    for scope, path in chosen:
        document = _read(path)
        profiles.update(document.get("profiles", {}))
        _apply(document, values, origins, Origin(scope, path), where=str(path))

    if profile is not None:
        block = profiles.get(profile)
        if block is None:
            known = ", ".join(sorted(profiles)) or "none are defined"
            raise SettingsError(f"no profile named '{profile}'. Available: {known}")
        _apply(
            block,
            values,
            origins,
            Origin("profile", note=profile),
            where=f"profile '{profile}'",
        )

    return Settings(
        **values,
        origins=origins,
        profiles=tuple(sorted(profiles)),
        ignored=tuple(ignored),
    )


# --- writing --------------------------------------------------------------


def settings_path_for(scope: str, *, cwd: Path | str | None = None) -> Path:
    """Where a write to ``scope`` would land.

    The project file is created in the working directory when none exists yet.
    It is never placed by searching -- writing into a file some ancestor happens
    to own is not what "save this here" means.
    """
    if scope == "user":
        return user_settings_path()
    found = find_project_settings(cwd)
    if found is not None:
        return found
    base = Path(cwd).resolve() if cwd is not None else Path.cwd().resolve()
    return base / SETTINGS_NAME


def save_setting(
    name: str,
    value: Any,
    *,
    scope: str = "project",
    profile: str | None = None,
    cwd: Path | str | None = None,
) -> Path:
    """Write one field into a settings file, creating it if needed.

    ``value`` of ``None`` removes the key, which is what ``--clear`` means: the
    field falls back to whatever the next layer down says, rather than being
    pinned to an empty value that would shadow it.
    """
    if name not in SETTABLE:
        raise SettingsError(
            f"'{name}' is not a setting. Settable: {', '.join(SETTABLE)}"
        )

    path = settings_path_for(scope, cwd=cwd)
    document: dict[str, Any] = (
        _read(path) if path.is_file() else {"version": SETTINGS_VERSION}
    )
    document.setdefault("version", SETTINGS_VERSION)

    if profile is not None:
        block = dict(document.get("profiles", {}).get(profile, {}))
        if value is None:
            block.pop(name, None)
        else:
            block[name] = value
        document.setdefault("profiles", {})[profile] = block
    elif value is None:
        document.pop(name, None)
    else:
        document[name] = value

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written beside the target and moved into place, so an interrupted run
        # cannot leave a half-written file that the next read would reject.
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        raise SettingsError(f"cannot write {path}: {exc.strerror or exc}") from None
    return path
