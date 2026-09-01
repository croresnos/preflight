"""Pure policy evaluation: the same inputs always produce the same verdict."""

from __future__ import annotations

from preflight.project import ProjectPolicy, matching_approval
from preflight.trust import (
    BackendCapabilities,
    DecisionReason,
    DependencyGraph,
    IsolationTier,
    PolicyDecision,
    ReasonCode,
)


def evaluate(
    policy: ProjectPolicy,
    graph: DependencyGraph,
    backend: BackendCapabilities,
    *,
    requested_tier: IsolationTier,
) -> PolicyDecision:
    reasons: list[DecisionReason] = []
    if not policy.active:
        reasons.append(
            DecisionReason(
                code=ReasonCode.PROJECT_INACTIVE,
                message="this project is not active in Preflight",
            )
        )
    if not backend.supports(requested_tier):
        reasons.append(
            DecisionReason(
                code=ReasonCode.BACKEND_UNAVAILABLE,
                message=(
                    f"backend '{backend.backend_id}' cannot provide "
                    f"'{requested_tier.value}' isolation"
                ),
                evidence={
                    "available_tiers": [tier.value for tier in backend.available_tiers]
                },
            )
        )
        if backend.available_tiers:
            reasons.append(
                DecisionReason(
                    code=ReasonCode.DOWNGRADE_REQUIRED,
                    message=(
                        "a lower tier requires a separate explicit approval; "
                        "Preflight will not downgrade this request"
                    ),
                )
            )
    if requested_tier is IsolationTier.STANDARD and not all(
        (
            backend.filesystem_enforced,
            backend.network_enforced,
            backend.credential_isolation,
            backend.process_isolation,
            backend.resource_limits,
        )
    ):
        reasons.append(
            DecisionReason(
                code=ReasonCode.BACKEND_UNAVAILABLE,
                message="the backend does not enforce every Standard boundary",
            )
        )
    if requested_tier is IsolationTier.MAXIMUM and not backend.independent_kernel:
        reasons.append(
            DecisionReason(
                code=ReasonCode.BACKEND_UNAVAILABLE,
                message="Maximum isolation requires an independent kernel",
            )
        )
    approval = matching_approval(policy, graph, requested_tier)
    if approval is None:
        reasons.append(
            DecisionReason(
                code=ReasonCode.APPROVAL_REQUIRED,
                message=(
                    "no active approval matches these exact artifact bytes, "
                    "dependencies, capabilities, policy, sandbox, project, and tier"
                ),
            )
        )
    if reasons:
        return PolicyDecision(
            allowed=False,
            requested_tier=requested_tier,
            reasons=tuple(reasons),
        )
    return PolicyDecision(
        allowed=True,
        requested_tier=requested_tier,
        achieved_tier=requested_tier,
    )
