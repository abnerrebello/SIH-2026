from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine
from app.engines.risk.signals import (
    build_reasons,
    build_score_breakdown,
    contextual_priority,
    cvss_priority,
)
from app.models import (
    Asset,
    AssetVulnerability,
    Vulnerability,
)


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

    Combines vulnerability, EPSS, asset and attack-path context
    into a deterministic risk score.
    """

    def __init__(self, db: Session):
        self.db = db

    def _calculate(
        self,
        vulnerability: Vulnerability,
        asset: Asset,
        attack_path_count: int,
        critical_targets_reached: int,
        choke_point: bool,
    ) -> VulnerabilityRisk:

        breakdown = build_score_breakdown(
            cvss_score=vulnerability.cvss_score,
            exploitability_score=vulnerability.exploitability_score,
            epss_score=vulnerability.epss_score,
            asset_criticality=asset.criticality.value,
            internet_exposed=asset.internet_exposed,
            actively_exploited=vulnerability.actively_exploited,
            known_exploit=vulnerability.known_exploit,
            attack_path_count=attack_path_count,
            critical_targets_reached=critical_targets_reached,
            choke_point=choke_point,
        )

        score = round(
            min(sum(breakdown.values()), 100.0),
            2,
        )

        reasons = build_reasons(
            cvss_score=vulnerability.cvss_score,
            exploitability_score=vulnerability.exploitability_score,
            epss_score=vulnerability.epss_score,
            asset_criticality=asset.criticality.value,
            internet_exposed=asset.internet_exposed,
            actively_exploited=vulnerability.actively_exploited,
            known_exploit=vulnerability.known_exploit,
            attack_path_count=attack_path_count,
            critical_targets_reached=critical_targets_reached,
            choke_point=choke_point,
        )

        return VulnerabilityRisk(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            title=vulnerability.title,
            asset_id=asset.id,
            asset_name=asset.name,
            cvss_score=vulnerability.cvss_score,
            risk_score=score,
            cvss_priority=cvss_priority(
                vulnerability.cvss_score
            ),
            priority=contextual_priority(score),
            attack_path_count=attack_path_count,
            critical_targets_reached=critical_targets_reached,
            choke_point=choke_point,
            reasons=reasons,
            score_breakdown=breakdown,
        )

    def analyze(self) -> list[VulnerabilityRisk]:
        graph_result = AttackGraphEngine(self.db).analyze()

        paths_by_cve: dict[str, list] = {}

        for path in graph_result.paths:
            for cve in path.vulnerabilities:
                paths_by_cve.setdefault(
                    cve,
                    [],
                ).append(path)

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
                Vulnerability.id
                == AssetVulnerability.vulnerability_id,
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
                    critical_targets_reached=len(
                        critical_targets
                    ),
                    choke_point=(
                        asset.id in choke_point_assets
                    ),
                )
            )

        results.sort(
            key=lambda item: item.risk_score,
            reverse=True,
        )

        return results
