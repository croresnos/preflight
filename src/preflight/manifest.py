"""The contracts a plugin must satisfy on paper, before it may run.

Every model here is closed (``extra="forbid"``). A manifest that carries a field
this module does not know about is rejected rather than ignored, because an
unknown field is either a typo or an attempt to smuggle something past the gate,
and neither should load.

Nothing in this module imports, executes, or inspects plugin code. It reads
inert JSON. That separation is the point: :mod:`preflight.registry` makes every
decision using only what is here.
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from enum import Enum
from typing import Literal, Protocol, runtime_checkable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Platform(str, Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    IOS = "ios"
    ANDROID = "android"


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STALE = "stale"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    UNKNOWN = "unknown"


class ToolRisk(str, Enum):
    """What the worst case looks like if a tool is called.

    The registry does not act on this. It exists so a host can require
    confirmation, apply a policy, or refuse a tier of tool without having to
    guess from the tool's name.
    """

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    CREDENTIAL = "credential"
    SECURITY = "security"
    PUBLIC_POSTING = "public_posting"
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"


class ToolSurface(str, Enum):
    BACKEND = "backend"
    CLIENT = "client"


class Tool(ContractModel):
    name: str = Field(min_length=1)
    risk: ToolRisk = ToolRisk.READ
    surface: ToolSurface = ToolSurface.BACKEND
    description: str | None = None


class UIContribution(ContractModel):
    surface: str = Field(min_length=1)
    entry: str = Field(min_length=1)
    minimum_schema_version: str = "1.0"


class Migration(ContractModel):
    migration_id: str = Field(min_length=1)
    from_version: str
    to_version: str
    reversible: bool = False


class Health(ContractModel):
    state: HealthState = HealthState.UNKNOWN
    checked_at: datetime | None = None
    detail: str | None = None


class PluginManifest(ContractModel):
    """What the plugin says it is.

    The registry gates on ``plugin_id``, ``supported_platforms``, and ``tools``.
    The remaining fields are carried through untouched for the host to read
    after a successful load; this module neither interprets nor enforces them.
    """

    schema_version: Literal["1.0"] = "1.0"
    plugin_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    module_version: str = Field(min_length=1)
    supported_platforms: list[Platform] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    data_classes: list[str] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    ui_contributions: list[UIContribution] = Field(default_factory=list)
    migrations: list[Migration] = Field(default_factory=list)
    health: Health = Field(default_factory=Health)


class Visibility(str, Enum):
    """Who a plugin is for."""

    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class ReleaseRing(str, Enum):
    """How ready a plugin is."""

    STABLE = "stable"
    BETA = "beta"
    EXPERIMENTAL = "experimental"


def _is_public_identifier(part: str) -> bool:
    return part.isidentifier() and not part.startswith("_")


class PluginPackageManifest(ContractModel):
    """Import-free metadata checked before a plugin may execute code.

    This is the whole of what the manifest file contains. Everything the
    registry decides, it decides from an instance of this model.
    """

    schema_version: Literal["1.0"] = "1.0"
    package_id: str = Field(min_length=3, max_length=128)
    core_api_version: Literal["1.0"] = "1.0"
    visibility: Visibility
    release_ring: ReleaseRing
    entrypoint: str = Field(min_length=3, max_length=256)
    plugin: PluginManifest

    @field_validator("package_id")
    @classmethod
    def package_id_is_canonical(cls, value: str) -> str:
        parts = value.split(".")
        if len(parts) < 2 or any(not part.replace("_", "").isalnum() for part in parts):
            raise ValueError("package_id must be a canonical dotted identifier")
        return value

    @field_validator("entrypoint")
    @classmethod
    def entrypoint_is_module_attribute(cls, value: str) -> str:
        """Check the entrypoint's shape only.

        Shape is not location. Nothing here constrains *where* the named module
        lives; see ``preflight.registry._import_entrypoint`` for that.
        """
        module_name, separator, attribute = value.partition(":")
        module_parts = module_name.split(".")
        if (
            separator != ":"
            or not module_name
            or not attribute
            or not _is_public_identifier(attribute)
            or any(not _is_public_identifier(part) for part in module_parts)
        ):
            raise ValueError("entrypoint must use public.module:attribute syntax")
        return value

    @model_validator(mode="after")
    def restricted_plugins_cannot_claim_the_stable_ring(self):
        """A restricted plugin may not label itself with the ring public builds accept.

        Without this, a plugin could be marked restricted and still be dressed
        in the one ring that a public build is willing to load.
        """
        if (
            self.visibility is Visibility.RESTRICTED
            and self.release_ring is ReleaseRing.STABLE
        ):
            raise ValueError("restricted plugins cannot declare the stable release ring")
        return self


#: How many individual field errors are worth printing before the list stops
#: being read. Past this a person is scrolling, not deciding.
_MAX_REPORTED_ERRORS = 6

#: Prose in an explanation is wrapped to this. The field tables below are not
#: wrapped -- a column that moves is worse to read than one that runs long.
_LINE = 68


def _required_fields() -> tuple[str, ...]:
    """The manifest fields with no default, in declaration order.

    Derived from the model rather than listed here, so it stays true if the
    schema gains or loses one.
    """
    return tuple(
        name
        for name, field in PluginPackageManifest.model_fields.items()
        if field.is_required()
    )


def _where(error: dict) -> str:
    """The dotted path to the field an error is about."""
    return ".".join(str(part) for part in error["loc"]) or "(the file itself)"


def explain_manifest_error(
    exc: Exception, *, from_file: bool = True
) -> tuple[str, bool]:
    """Why the manifest did not parse, in words, and whether it is even ours.

    ``str(ValidationError)`` is a per-error dump with a documentation URL and an
    echo of the input under every entry -- upwards of fifty lines for a file
    whose only crime is belonging to a different tool. Plenty of systems keep a
    ``manifest.json``, so someone pointing preflight at a browser extension or a
    web app is not making a mistake, they are testing what this thing is. That
    is the moment they decide preflight is broken, and a wall of pydantic is how
    they decide it. Answer with the short true thing and the next command.

    This lives beside the model rather than beside either caller because both
    :mod:`preflight.inspect` and :mod:`preflight.registry` have to say the same
    thing about the same file, and a security core that reaches into a reporting
    module for its wording is a dependency pointing the wrong way.

    ``from_file=False`` says the errors came from an object a plugin handed back
    at runtime rather than from a file on disk. "This belongs to another system"
    is then not an available verdict, because there is no file to belong to
    anyone -- the caller validated something preflight's own loader produced.

    Returns the description, and whether the file is another system's manifest.
    """
    if not isinstance(exc, ValidationError):
        return str(exc), False

    errors = exc.errors()
    required = _required_fields()
    absent = {
        str(error["loc"][0])
        for error in errors
        if error["type"] == "missing" and len(error["loc"]) == 1
    }
    unknown = sum(1 for error in errors if error["type"] == "extra_forbidden")

    # Not one required field is present. A preflight manifest with a mistake in
    # it still looks like a preflight manifest; this does not look like one at
    # all, and calling it invalid would be a false claim about someone else's
    # perfectly good file.
    if from_file and absent >= set(required):
        return (
            textwrap.fill(
                f"This is a manifest.json, but not one of preflight's. It has "
                f"none of the fields preflight requires ({', '.join(required)}), "
                f"and {unknown} that preflight does not recognise.",
                width=_LINE,
            ),
            True,
        )

    shown = errors[:_MAX_REPORTED_ERRORS]
    count = len(errors)
    lines = [f"{count} problem{'' if count == 1 else 's'} with this manifest:"]
    width = max(len(_where(error)) for error in shown)
    lines += [f"  {_where(error):<{width}}  {error['msg']}" for error in shown]
    if count > len(shown):
        lines.append(f"  ... and {count - len(shown)} more")
    return "\n".join(lines), False


def manifest_error_message(prefix: str, exc: Exception, *, from_file: bool = True) -> str:
    """``prefix``, then the explanation -- on one line when it fits on one.

    The refusals this builds are read in two places with different shapes: raw,
    as ``str(PluginRejected)``, and indented under a folder name in a load
    report. Deciding the line break here keeps both callers from guessing.
    """
    detail, _ = explain_manifest_error(exc, from_file=from_file)
    separator = "\n" if "\n" in detail else " "
    return f"{prefix}:{separator}{detail}"


def _by_name(value: object) -> dict[str, object] | None:
    """A list of named entries indexed by name, or ``None`` if it is not one.

    ``tools`` is the field this exists for. Rendering two whole tool lists to
    show that one entry differs buries the answer in schema, and truncating them
    to fit a line cuts off the end -- which is exactly where an appended tool is.
    """
    if not isinstance(value, list):
        return None
    if not all(
        isinstance(item, dict) and isinstance(item.get("name"), str) for item in value
    ):
        return None
    return {str(item["name"]): item for item in value}  # type: ignore[index]


def _brief(value: object) -> str:
    """A value short enough to sit on one line of a refusal."""
    rendered = repr(value)
    return rendered if len(rendered) <= 60 else rendered[:57] + "..."


def _describe_difference(field: str, declared: object, reported: object) -> str:
    """One field's disagreement, in the fewest words somebody can act on."""
    declared_entries = _by_name(declared)
    reported_entries = _by_name(reported)
    if declared_entries is None or reported_entries is None:
        return f"{field}: manifest says {_brief(declared)}, plugin reports {_brief(reported)}"

    parts = []
    if undeclared := sorted(reported_entries.keys() - declared_entries.keys()):
        parts.append("undeclared in the manifest: " + ", ".join(undeclared))
    if unreported := sorted(declared_entries.keys() - reported_entries.keys()):
        parts.append("declared but not reported: " + ", ".join(unreported))
    # Same names, different content. Worth its own wording: a tool declared
    # `read` on paper and reported `destructive` under that name is the version
    # of this mismatch with teeth, and it changes neither list's membership.
    if altered := sorted(
        name
        for name in declared_entries.keys() & reported_entries.keys()
        if declared_entries[name] != reported_entries[name]
    ):
        parts.append("declared differently: " + ", ".join(altered))
    if not parts:
        return f"{field} differs"
    return f"{field} -- " + "; ".join(parts)


def manifest_differences(
    declared: PluginManifest, reported: PluginManifest
) -> tuple[str, ...]:
    """Which fields a loaded plugin reported differently from its manifest.

    The registry refuses a plugin whose reported manifest is not equal to the one
    validated off disk, and equality is deliberately the whole check. But "does
    not match" is a useless thing to tell somebody holding two files: the cause
    is almost always one field updated in one place and not the other, and
    finding it by eye means reading a manifest against a source file line by
    line. Both objects are in hand at the point of refusal, so name the field.

    One entry per differing field, for a caller that puts each on its own line.
    Empty only if the models compare unequal on something their JSON form does
    not carry, in which case the caller keeps its unqualified message.
    """
    was = declared.model_dump(mode="json")
    now = reported.model_dump(mode="json")
    return tuple(
        _describe_difference(field, was.get(field), now.get(field))
        for field in sorted(was.keys() | now.keys())
        if was.get(field) != now.get(field)
    )


@runtime_checkable
class Plugin(Protocol):
    """The entire plugin ABI: an object that reports its own manifest.

    ``runtime_checkable`` makes ``isinstance()`` usable here, but be clear about
    what that proves. It checks that the attribute is *present*, not that it
    holds a :class:`PluginManifest`. The registry does the real check separately:
    it validates the reported manifest and requires it to equal the declared one.
    """

    @property
    def manifest(self) -> PluginManifest: ...
