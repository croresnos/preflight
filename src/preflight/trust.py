"""Deterministic, serializable contracts for the Preflight trust boundary."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.json_schema import models_json_schema


def canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class TrustModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReasonCode(str, Enum):
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_REVOKED = "approval_revoked"
    ARTIFACT_CHANGED = "artifact_changed"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    CAPABILITY_DENIED = "capability_denied"
    DEPENDENCY_CHANGED = "dependency_changed"
    DOWNGRADE_REQUIRED = "downgrade_required"
    ENTRYPOINT_CHANGED = "entrypoint_changed"
    INVALID_POLICY = "invalid_policy"
    PROJECT_INACTIVE = "project_inactive"
    PROVENANCE_MISSING = "provenance_missing"
    RESOURCE_LIMIT = "resource_limit"
    UNSUPPORTED_INPUT = "unsupported_input"
    UNPROTECTED = "unprotected"


class IsolationTier(str, Enum):
    RESOURCE_ONLY = "resource-only"
    STANDARD = "standard"
    MAXIMUM = "maximum"
    UNPROTECTED = "unprotected"


class ArtifactKind(str, Enum):
    DIRECTORY = "directory"
    GIT = "git"
    SDIST = "sdist"
    WHEEL = "wheel"


class FileAccess(str, Enum):
    NONE = "none"
    READ_SELECTED = "read-selected"
    READ_WRITE_SELECTED = "read-write-selected"


class NetworkAccess(str, Enum):
    OFF = "off"
    APPROVED_DESTINATIONS = "approved-destinations"
    OPEN_INTERNET = "open-internet"


class AccountActions(str, Enum):
    DENY = "deny"
    EXACT_APPROVAL = "exact-approval"


class ProgramAccess(str, Enum):
    NONE = "none"
    BUNDLED = "bundled"
    APPROVED_HOST = "approved-host"


class DeviceAccess(str, Enum):
    NONE = "none"
    APPROVED = "approved"


class WorkloadProfile(str, Enum):
    STANDARD = "standard"
    HEAVY = "heavy"


class CapabilitySet(TrustModel):
    format: Literal[1] = 1
    files: FileAccess = FileAccess.NONE
    file_paths: tuple[str, ...] = ()
    network: NetworkAccess = NetworkAccess.OFF
    network_destinations: tuple[str, ...] = ()
    accounts_actions: AccountActions = AccountActions.DENY
    account_names: tuple[str, ...] = ()
    programs: ProgramAccess = ProgramAccess.NONE
    program_names: tuple[str, ...] = ()
    devices_ui: DeviceAccess = DeviceAccess.NONE
    device_names: tuple[str, ...] = ()
    workload: WorkloadProfile = WorkloadProfile.STANDARD

    @model_validator(mode="after")
    def selectors_match_grants(self):
        pairs = (
            (self.files is not FileAccess.NONE, self.file_paths, "file_paths"),
            (
                self.network is NetworkAccess.APPROVED_DESTINATIONS,
                self.network_destinations,
                "network_destinations",
            ),
            (
                self.accounts_actions is AccountActions.EXACT_APPROVAL,
                self.account_names,
                "account_names",
            ),
            (
                self.programs is ProgramAccess.APPROVED_HOST,
                self.program_names,
                "program_names",
            ),
            (
                self.devices_ui is DeviceAccess.APPROVED,
                self.device_names,
                "device_names",
            ),
        )
        for selector_required, values, field in pairs:
            if selector_required and not values:
                raise ValueError(f"{field} must name at least one approved value")
        return self

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self))


class ArtifactIdentity(TrustModel):
    format: Literal[1] = 1
    kind: ArtifactKind
    source: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    signature_verified: bool = False
    provenance: tuple[str, ...] = ()


class DependencyNode(TrustModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    artifact: ArtifactIdentity
    dependencies: tuple[str, ...] = ()


class DependencyGraph(TrustModel):
    format: Literal[1] = 1
    root: ArtifactIdentity
    nodes: tuple[DependencyNode, ...] = ()
    entrypoint: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self))

    @property
    def entrypoint_digest(self) -> str:
        return sha256_bytes(canonical_json({"argv": self.entrypoint}))


class DecisionReason(TrustModel):
    code: ReasonCode
    message: str = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(TrustModel):
    format: Literal[1] = 1
    allowed: bool
    requested_tier: IsolationTier
    achieved_tier: IsolationTier | None = None
    reasons: tuple[DecisionReason, ...] = ()

    @model_validator(mode="after")
    def allowed_decisions_name_the_achieved_tier(self):
        if self.allowed and self.achieved_tier is None:
            raise ValueError("an allowed decision must name the achieved tier")
        if not self.allowed and self.achieved_tier is not None:
            raise ValueError("a refused decision cannot claim an achieved tier")
        return self


class BackendCapabilities(TrustModel):
    format: Literal[1] = 1
    backend_id: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    available_tiers: tuple[IsolationTier, ...]
    filesystem_enforced: bool
    network_enforced: bool
    credential_isolation: bool
    process_isolation: bool
    resource_limits: bool
    independent_kernel: bool
    detail: tuple[str, ...] = ()

    def supports(self, tier: IsolationTier) -> bool:
        return tier in self.available_tiers


class ApprovalGrant(TrustModel):
    format: Literal[1] = 1
    approval_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    entrypoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: int = Field(ge=1)
    sandbox_version: str = Field(min_length=1)
    tier: IsolationTier
    granted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    revoked_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class ApprovalRequest(TrustModel):
    format: Literal[1] = 1
    request_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    entrypoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: int = Field(ge=1)
    sandbox_version: str = Field(min_length=1)
    requested_tier: IsolationTier
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ProvenanceRecord(TrustModel):
    format: Literal[1] = 1
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: str = Field(min_length=1)
    kind: Literal["hash", "signature", "attestation"]
    verified: bool
    signer_identity: str | None = None
    predicate_type: str | None = None
    statement_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    detail: tuple[str, ...] = ()


class EvidenceRecord(TrustModel):
    format: Literal[1] = 1
    sequence: int = Field(ge=1)
    event: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data: dict[str, Any] = Field(default_factory=dict)
    previous_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hmac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def trust_json_schema() -> dict[str, Any]:
    """Return the versioned JSON Schema bundle for trust-protocol records."""
    models = (
        ArtifactIdentity,
        DependencyGraph,
        CapabilitySet,
        PolicyDecision,
        EvidenceRecord,
        ApprovalGrant,
        ApprovalRequest,
        BackendCapabilities,
        ProvenanceRecord,
    )
    _, schema = models_json_schema(
        [(model, "validation") for model in models],
        title="Preflight deterministic trust protocol v1",
        description=(
            "Schemas are versioned data contracts, not evidence that a backend "
            "provides an isolation guarantee."
        ),
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://preflight.dev/schemas/trust-v1.json",
        "x-preflight-format": 1,
        **schema,
    }
