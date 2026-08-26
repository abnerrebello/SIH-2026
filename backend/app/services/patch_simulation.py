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
    risk_reduction: float


def simulate_patch(
    db: Session,
    vulnerability_id: int,
) -> PatchSimulationResult:

    vulnerability = db.get(Vulnerability, vulnerability_id)

    if vulnerability is None:
        raise ValueError("Vulnerability not found.")

    mappings = db.scalars(
        select(AssetVulnerability).where(
            AssetVulnerability.vulnerability_id == vulnerability_id
        )
    ).all()

    affected_asset_ids = {
        mapping.asset_id
        for mapping in mappings
    }

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
                asset_id in affected_asset_ids
                for asset_id in path.asset_ids
            )
        )
    ]

    after_critical = [
        path
        for path in after_paths
        if path.target_criticality == "CRITICAL"
    ]

    before_risk = max(
        (path.risk_score for path in before_paths),
        default=0.0,
    )

    after_risk = max(
        (path.risk_score for path in after_paths),
        default=0.0,
    )

    return PatchSimulationResult(
        vulnerability_id=vulnerability.id,
        cve_id=vulnerability.cve_id,
        before_paths=len(before_paths),
        after_paths=len(after_paths),
        before_critical_paths=len(before_critical),
        after_critical_paths=len(after_critical),
        before_risk=round(before_risk, 2),
        after_risk=round(after_risk, 2),
        eliminated_paths=len(before_paths) - len(after_paths),
        eliminated_critical_paths=(
            len(before_critical) - len(after_critical)
        ),
        risk_reduction=round(
            max(before_risk - after_risk, 0.0),
            2,
        ),
    )
