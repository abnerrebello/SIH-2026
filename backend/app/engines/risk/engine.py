from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine
from app.models import Asset, AssetVulnerability, Vulnerability


@dataclass
class VulnerabilityRisk:
    vulnerability_id: int
    cve_id: str
    title: str
    asset_id: int
    asset_name: str

    cvss_score: float
    risk_score: float

    cvss_priority: str
    priority: str

    attack_path_count: int
    critical_targets_reached: int
    choke_point: bool

    reasons: list[str]
    score_breakdown: dict[str, float]


class RiskEngine:
    """
    Explainable contextual vulnerability prioritization.

    This is a deterministic baseline intended to be:
    - reproducible
    - explainable
    - easy to test
    - suitable for comparison against CVSS-only ranking

    ML can later learn from these contextual features.
    """

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _cvss_priority(cvss: float) -> str:
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _priority(score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _criticality_points(criticality: str) -> float:
        return {
            "LOW": 5.0,
            "MEDIUM": 12.0,
            "HIGH": 18.0,
            "CRITICAL": 25.0,
        }.get(criticality, 10.0)

    @staticmethod
    def _cvss_points(cvss: float) -> float:
        return min(max(cvss, 0.0), 10.0) * 3.0

    @staticmethod
    def _exploitability_points(score: float | None) -> float:
        if score is None:
            return 0.0

        normalized = min(max(score, 0.0), 4.0) / 4.0
        return normalized * 12.0

    def _calculate(
        self,
        vulnerability: Vulnerability,
        asset: Asset,
        attack_path_count: int,
        critical_targets_reached: int,
        choke_point: bool,
    ) -> VulnerabilityRisk:

        breakdown = {
            "cvss": self._cvss_points(vulnerability.cvss_score),
            "exploitability": self._exploitability_points(
                vulnerability.exploitability_score
            ),
            "asset_criticality": self._criticality_points(
                asset.criticality.value
            ),
            "internet_exposure": 12.0 if asset.internet_exposed else 0.0,
            "active_exploitation": 15.0 if vulnerability.actively_exploited else 0.0,
            "known_exploit": 8.0 if vulnerability.known_exploit else 0.0,
            "attack_path_impact": min(attack_path_count * 4.0, 12.0),
            "critical_target_impact": min(critical_targets_reached * 7.0, 14.0),
            "choke_point": 8.0 if choke_point else 0.0,
        }

        score = round(
            min(sum(breakdown.values()), 100.0),
            2,
        )

        reasons: list[str] = []

        if vulnerability.cvss_score >= 9.0:
            reasons.append(
                f"Very high CVSS score ({vulnerability.cvss_score:.1f})"
            )
        elif vulnerability.cvss_score >= 7.0:
            reasons.append(
                f"High CVSS score ({vulnerability.cvss_score:.1f})"
            )

        if vulnerability.exploitability_score is not None:
            if vulnerability.exploitability_score >= 3.0:
                reasons.append("High exploitability")

        if asset.criticality.value in {"HIGH", "CRITICAL"}:
            reasons.append(
                f"{asset.criticality.value} asset"
            )

        if asset.internet_exposed:
            reasons.append("Internet-facing asset")

        if vulnerability.actively_exploited:
            reasons.append("Active exploitation reported")

        if vulnerability.known_exploit:
            reasons.append("Known exploit available")

        if attack_path_count:
            reasons.append(
                f"Present on {attack_path_count} attack path(s)"
            )

        if critical_targets_reached:
            reasons.append(
                f"Can contribute to reaching {critical_targets_reached} critical asset(s)"
            )

        if choke_point:
            reasons.append(
                "Located at an attack-path choke point"
            )

        return VulnerabilityRisk(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            title=vulnerability.title,
            asset_id=asset.id,
            asset_name=asset.name,
            cvss_score=vulnerability.cvss_score,
            risk_score=score,
            cvss_priority=self._cvss_priority(
                vulnerability.cvss_score
            ),
            priority=self._priority(score),
            attack_path_count=attack_path_count,
            critical_targets_reached=critical_targets_reached,
            choke_point=choke_point,
            reasons=reasons,
            score_breakdown=breakdown,
        )

    def analyze(self) -> list[VulnerabilityRisk]:
        graph_result = AttackGraphEngine(self.db).analyze()

        # Map CVE → attack paths.
        paths_by_cve: dict[str, list] = {}

        for path in graph_result.paths:
            for cve in path.vulnerabilities:
                paths_by_cve.setdefault(cve, []).append(path)

        choke_point_assets = {
            item["asset_id"]
            for item in graph_result.choke_points
        }

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
                Vulnerability.id == AssetVulnerability.vulnerability_id,
            )
        ).all()

        results: list[VulnerabilityRisk] = []

        for _, asset, vulnerability in records:
            affected_paths = paths_by_cve.get(
                vulnerability.cve_id,
                [],
            )

            critical_targets = {
                path.target_asset_id
                for path in affected_paths
                if path.target_criticality == "CRITICAL"
            }

            results.append(
                self._calculate(
                    vulnerability=vulnerability,
                    asset=asset,
                    attack_path_count=len(affected_paths),
                    critical_targets_reached=len(critical_targets),
                    choke_point=asset.id in choke_point_assets,
                )
            )

        results.sort(
            key=lambda item: item.risk_score,
            reverse=True,
        )

        return results