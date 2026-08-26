from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetVulnerability, Vulnerability


@dataclass
class VulnerabilityRisk:
    vulnerability_id: int
    cve_id: str
    title: str
    asset_id: int
    asset_name: str
    risk_score: float
    priority: str
    reasons: list[str]
    attack_path_count: int
    critical_targets_reached: int


class RiskEngine:
    """
    Explainable contextual vulnerability prioritization engine.

    This is intentionally deterministic in the first version.
    ML will later be added as an enhancement layer.
    """

    CRITICALITY_WEIGHT = {
        "LOW": 10.0,
        "MEDIUM": 30.0,
        "HIGH": 60.0,
        "CRITICAL": 85.0,
    }

    def __init__(self, db: Session):
        self.db = db

    def _base_cvss(self, score: float) -> float:
        return min(max(score / 10.0, 0.0), 1.0) * 35.0

    def _exploitability(self, score: float | None) -> float:
        if score is None:
            return 0.0
        return min(max(score / 4.0, 0.0), 1.0) * 15.0

    def _calculate_for(
        self,
        vulnerability: Vulnerability,
        asset: Asset,
        attack_path_count: int,
        critical_targets_reached: int,
    ) -> VulnerabilityRisk:

        score = 0.0
        reasons: list[str] = []

        # 1. CVSS
        cvss_points = self._base_cvss(vulnerability.cvss_score)
        score += cvss_points

        if vulnerability.cvss_score >= 9.0:
            reasons.append(
                f"Very high CVSS score ({vulnerability.cvss_score:.1f})"
            )
        elif vulnerability.cvss_score >= 7.0:
            reasons.append(
                f"High CVSS score ({vulnerability.cvss_score:.1f})"
            )

        # 2. Exploitability
        exploit_points = self._exploitability(
            vulnerability.exploitability_score
        )
        score += exploit_points

        if vulnerability.exploitability_score is not None:
            if vulnerability.exploitability_score >= 3.0:
                reasons.append(
                    "High exploitability score"
                )

        # 3. Asset criticality
        criticality_points = (
            self.CRITICALITY_WEIGHT.get(
                asset.criticality.value,
                30.0,
            )
            * 0.25
        )

        score += criticality_points

        if asset.criticality.value in {"HIGH", "CRITICAL"}:
            reasons.append(
                f"{asset.criticality.value} asset criticality"
            )

        # 4. Internet exposure
        if asset.internet_exposed:
            score += 15.0
            reasons.append("Internet-facing asset")

        # 5. Active exploitation
        if vulnerability.actively_exploited:
            score += 15.0
            reasons.append("Known active exploitation")

        # 6. Known exploit
        if vulnerability.known_exploit:
            score += 10.0
            reasons.append("Known exploit available")

        # 7. Attack-path impact
        path_points = min(
            attack_path_count * 5.0,
            20.0,
        )

        if attack_path_count > 0:
            score += path_points
            reasons.append(
                f"Present on {attack_path_count} attack path(s)"
            )

        # 8. Critical targets reached
        target_points = min(
            critical_targets_reached * 8.0,
            16.0,
        )

        if critical_targets_reached > 0:
            score += target_points
            reasons.append(
                f"Can contribute to reaching {critical_targets_reached} critical asset(s)"
            )

        score = round(
            min(max(score, 0.0), 100.0),
            2,
        )

        if score >= 85:
            priority = "CRITICAL"
        elif score >= 70:
            priority = "HIGH"
        elif score >= 45:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return VulnerabilityRisk(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            title=vulnerability.title,
            asset_id=asset.id,
            asset_name=asset.name,
            risk_score=score,
            priority=priority,
            reasons=reasons,
            attack_path_count=attack_path_count,
            critical_targets_reached=critical_targets_reached,
        )

    def analyze(self) -> list[VulnerabilityRisk]:
        from app.engines.attack_graph import AttackGraphEngine

        graph_result = AttackGraphEngine(self.db).analyze()

        path_records = [
            path for path in graph_result.paths
        ]

        records = self.db.execute(
            select(
                AssetVulnerability,
                Asset,
                Vulnerability,
            )
            .join(
                Asset,
                Asset.id == AssetVulnerability.asset_id,
            )
            .join(
                Vulnerability,
                Vulnerability.id
                == AssetVulnerability.vulnerability_id,
            )
        ).all()

        results: list[VulnerabilityRisk] = []

        for mapping, asset, vulnerability in records:
            affected_paths = [
                path
                for path in path_records
                if vulnerability.cve_id in path.vulnerabilities
            ]

            critical_targets = {
                path.target_asset_id
                for path in affected_paths
                if path.target_criticality == "CRITICAL"
            }

            results.append(
                self._calculate_for(
                    vulnerability=vulnerability,
                    asset=asset,
                    attack_path_count=len(affected_paths),
                    critical_targets_reached=len(
                        critical_targets
                    ),
                )
            )

        results.sort(
            key=lambda result: result.risk_score,
            reverse=True,
        )

        return results
