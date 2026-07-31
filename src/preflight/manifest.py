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

from datetime import datetime
from enum import Enum
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
