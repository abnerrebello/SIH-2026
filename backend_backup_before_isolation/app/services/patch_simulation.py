from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine
from app.models import AssetVulnerability, Vulnerability


@dataclass
class PatchSimulationResult:
    vulnerability_id: int
    cve_id: str

    before_paths: int
    after_paths: int

    before_critical_paths: int
    after_critical_paths: int

    before_risk: float
    after_risk: float

    eliminated_paths: int
    eliminated_critical_paths: int

    path_reduction_percent: float
    critical_path_reduction_percent: float
    security_impact: float

    # Kept for frontend compatibility.
    risk_reduction: float


def simulate_patch(
    db: Session,
    vulnerability_id: int,
    asset_id: int | None = None,
) -> PatchSimulationResult:

    vulnerability = db.get(
        Vulnerability,
        vulnerability_id,
    )

    if vulnerability is None:
        raise ValueError(
            "Vulnerability not found."
        )

    mappings = db.scalars(
        select(AssetVulnerability).where(
            AssetVulnerability.vulnerability_id
            == vulnerability_id
        )
    ).all()

    affected_asset_ids = {
        mapping.asset_id
        for mapping in mappings
        if asset_id is None
        or mapping.asset_id == asset_id
    }

    if asset_id is not None and not affected_asset_ids:
        raise ValueError(
            "The selected asset is not affected by this vulnerability."
        )

    result = AttackGraphEngine(db).analyze()
    before_paths = result.paths

    before_critical = [
        path
        for path in before_paths
        if path.target_criticality == "CRITICAL"
    ]

    after_paths = [
        path
        for path in before_paths
        if not (
            vulnerability.cve_id in path.vulnerabilities
            and any(
                path_asset_id in affected_asset_ids
                for path_asset_id in path.asset_ids
            )
        )
    ]

    after_critical = [
        path
        for path in after_paths
        if path.target_criticality == "CRITICAL"
    ]

    before_risk = max(
        (
            path.risk_score
            for path in before_paths
        ),
        default=0.0,
    )

    after_risk = max(
        (
            path.risk_score
            for path in after_paths
        ),
        default=0.0,
    )

    eliminated_paths = (
        len(before_paths)
        - len(after_paths)
    )

    eliminated_critical_paths = (
        len(before_critical)
        - len(after_critical)
    )

    path_reduction_percent = (
        eliminated_paths
        / len(before_paths)
        * 100
        if before_paths
        else 0.0
    )

    critical_path_reduction_percent = (
        eliminated_critical_paths
        / len(before_critical)
        * 100
        if before_critical
        else 0.0
    )

    security_impact = min(
        (
            path_reduction_percent * 0.4
            + critical_path_reduction_percent * 0.6
        ),
        100.0,
    )

    return PatchSimulationResult(
        vulnerability_id=vulnerability.id,
        cve_id=vulnerability.cve_id,

        before_paths=len(before_paths),
        after_paths=len(after_paths),

        before_critical_paths=len(
            before_critical
        ),
        after_critical_paths=len(
            after_critical
        ),

        before_risk=round(
            before_risk,
            2,
        ),
        after_risk=round(
            after_risk,
            2,
        ),

        eliminated_paths=eliminated_paths,
        eliminated_critical_paths=(
            eliminated_critical_paths
        ),

        path_reduction_percent=round(
            path_reduction_percent,
            2,
        ),
        critical_path_reduction_percent=round(
            critical_path_reduction_percent,
            2,
        ),
        security_impact=round(
            security_impact,
            2,
        ),

        # Preserve the old frontend field.
        risk_reduction=round(
            security_impact,
            2,
        ),
    )
