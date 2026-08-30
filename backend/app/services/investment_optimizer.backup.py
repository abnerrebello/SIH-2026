from dataclasses import dataclass
from itertools import combinations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine
from app.engines.risk import RiskEngine
from app.models import Asset, AssetVulnerability, Vulnerability
from app.services.patch_simulation import simulate_patch


@dataclass(frozen=True)
class InvestmentAction:
    vulnerability_id: int
    asset_id: int
    cve_id: str
    title: str
    asset_name: str

    current_risk: float

    individual_security_impact: float
    eliminated_paths: int
    eliminated_critical_paths: int

    estimated_cost: float
    estimated_days: float
    estimated_engineers: int

    value_per_1000: float


class InvestmentOptimizer:
    """
    Deterministic security-investment optimizer.

    Optimizes asset-level remediation actions against:
      - budget
      - engineering capacity
      - remediation time

    The optimizer evaluates candidate combinations jointly against
    the attack graph so overlapping attack-path impact is not added
    twice.

    Organizational risk is kept separate from attack-path exposure.
    Eliminating every modeled attack path therefore does not imply
    that organizational cyber risk becomes zero.
    """

    def __init__(self, db: Session):
        self.db = db

    # =========================================================
    # COST / EFFORT ESTIMATION
    # =========================================================

    @staticmethod
    def _estimate_cost(
        vulnerability: Vulnerability,
        asset: Asset,
    ) -> float:

        base = 25000.0

        severity_multiplier = {
            "LOW": 0.8,
            "MEDIUM": 1.0,
            "HIGH": 1.6,
            "CRITICAL": 2.2,
        }.get(
            vulnerability.severity.value,
            1.0,
        )

        exposure_multiplier = (
            1.25
            if asset.internet_exposed
            else 1.0
        )

        exploit_multiplier = (
            1.2
            if (
                vulnerability.actively_exploited
                or vulnerability.kev_status
            )
            else 1.0
        )

        critical_asset_multiplier = {
            "LOW": 0.9,
            "MEDIUM": 1.0,
            "HIGH": 1.25,
            "CRITICAL": 1.5,
        }.get(
            asset.criticality.value,
            1.0,
        )

        return round(
            base
            * severity_multiplier
            * exposure_multiplier
            * exploit_multiplier
            * critical_asset_multiplier,
            -3,
        )

    @staticmethod
    def _estimate_days(
        vulnerability: Vulnerability,
        asset: Asset,
    ) -> float:

        days = {
            "LOW": 0.5,
            "MEDIUM": 1.0,
            "HIGH": 2.0,
            "CRITICAL": 3.0,
        }.get(
            vulnerability.severity.value,
            1.0,
        )

        if asset.internet_exposed:
            days += 0.5

        if vulnerability.actively_exploited:
            days += 0.5

        if vulnerability.kev_status:
            days += 0.5

        return round(
            days,
            1,
        )

    @staticmethod
    def _estimate_engineers(
        vulnerability: Vulnerability,
        asset: Asset,
    ) -> int:

        if (
            vulnerability.severity.value == "CRITICAL"
            or asset.criticality.value == "CRITICAL"
        ):
            return 2

        return 1

    # =========================================================
    # ATTACK GRAPH EXPOSURE
    # =========================================================

    @staticmethod
    def _path_matches_action(
        path,
        action: InvestmentAction,
    ) -> bool:

        return (
            action.cve_id
            in path.vulnerabilities
            and action.asset_id
            in path.asset_ids
        )

    @staticmethod
    def _attack_exposure(paths) -> float:

        total = 0.0

        for path in paths:
            weight = (
                2.0
                if path.target_criticality == "CRITICAL"
                else 1.0
            )

            total += (
                float(path.risk_score)
                * weight
            )

        return total

    @classmethod
    def _joint_impact(
        cls,
        all_paths,
        actions: list[InvestmentAction],
    ) -> dict:

        before_paths = list(
            all_paths
        )

        before_exposure = (
            cls._attack_exposure(
                before_paths
            )
        )

        after_paths = [
            path
            for path in before_paths
            if not any(
                cls._path_matches_action(
                    path,
                    action,
                )
                for action in actions
            )
        ]

        after_exposure = (
            cls._attack_exposure(
                after_paths
            )
        )

        eliminated_paths = (
            len(before_paths)
            - len(after_paths)
        )

        before_critical = sum(
            path.target_criticality == "CRITICAL"
            for path in before_paths
        )

        after_critical = sum(
            path.target_criticality == "CRITICAL"
            for path in after_paths
        )

        eliminated_critical = (
            before_critical
            - after_critical
        )

        if before_exposure > 0:
            exposure_reduction = (
                (
                    before_exposure
                    - after_exposure
                )
                / before_exposure
                * 100.0
            )
        else:
            exposure_reduction = 0.0

        return {
            "before_exposure": round(
                before_exposure,
                2,
            ),
            "after_exposure": round(
                after_exposure,
                2,
            ),
            "security_impact": round(
                max(
                    min(
                        exposure_reduction,
                        100.0,
                    ),
                    0.0,
                ),
                2,
            ),
            "eliminated_paths": (
                eliminated_paths
            ),
            "eliminated_critical_paths": (
                eliminated_critical
            ),
            "remaining_paths": len(
                after_paths
            ),
            "remaining_critical_paths": (
                after_critical
            ),
        }

    # =========================================================
    # ORGANIZATIONAL RISK
    # =========================================================

    @staticmethod
    def _vulnerability_exposure(
        risk_results,
        excluded_actions: set[tuple[int, int]],
    ) -> float:
        """
        Weighted vulnerability exposure.

        Each asset-vulnerability mapping contributes its
        contextual risk. Removed remediation actions are excluded.
        """

        remaining = [
            item
            for item in risk_results
            if (
                item.vulnerability_id,
                item.asset_id,
            ) not in excluded_actions
        ]

        if not remaining:
            return 0.0

        # Higher-risk records count more heavily without letting
        # one record completely dominate the score.
        total_weight = sum(
            max(
                item.risk_score,
                1.0,
            )
            for item in remaining
        )

        if total_weight <= 0:
            return 0.0

        weighted_value = sum(
            item.risk_score
            * max(
                item.risk_score,
                1.0,
            )
            for item in remaining
        )

        return (
            weighted_value
            / total_weight
        )

    @classmethod
    def _organizational_risk(
        cls,
        risk_results,
        all_paths,
        excluded_actions: set[tuple[int, int]],
        baseline_attack_exposure: float,
    ) -> float:
        """
        Combine vulnerability exposure and attack exposure.

        60% vulnerability/asset exposure
        40% attack-graph exposure

        Attack exposure is normalized relative to the current
        environment, while vulnerability exposure remains based on
        the surviving asset-vulnerability landscape.
        """

        vulnerability_exposure = (
            cls._vulnerability_exposure(
                risk_results,
                excluded_actions,
            )
        )

        if baseline_attack_exposure > 0:
            attack_exposure = (
                cls._attack_exposure(
                    all_paths
                )
                / baseline_attack_exposure
                * 100.0
            )
        else:
            attack_exposure = 0.0

        score = (
            vulnerability_exposure * 0.6
            + attack_exposure * 0.4
        )

        return round(
            max(
                min(score, 100.0),
                0.0,
            ),
            2,
        )

    def _organizational_risk_after(
        self,
        risk_results,
        all_paths,
        selected_actions,
        baseline_attack_exposure,
    ) -> float:

        excluded_actions = {
            (
                action.vulnerability_id,
                action.asset_id,
            )
            for action in selected_actions
        }

        remaining_paths = [
            path
            for path in all_paths
            if not any(
                self._path_matches_action(
                    path,
                    action,
                )
                for action in selected_actions
            )
        ]

        vulnerability_exposure = (
            self._vulnerability_exposure(
                risk_results,
                excluded_actions,
            )
        )

        if baseline_attack_exposure > 0:
            attack_exposure = (
                self._attack_exposure(
                    remaining_paths
                )
                / baseline_attack_exposure
                * 100.0
            )
        else:
            attack_exposure = 0.0

        return round(
            max(
                min(
                    vulnerability_exposure * 0.6
                    + attack_exposure * 0.4,
                    100.0,
                ),
                0.0,
            ),
            2,
        )

    # =========================================================
    # ACTION GENERATION
    # =========================================================

    def generate_actions(
        self,
    ) -> list[InvestmentAction]:

        risk_results = RiskEngine(
            self.db
        ).analyze()

        risk_by_mapping = {
            (
                item.vulnerability_id,
                item.asset_id,
            ): item
            for item in risk_results
        }

        mappings = self.db.execute(
            select(
                AssetVulnerability,
                Asset,
                Vulnerability,
            )
            .join(
                Asset,
                Asset.id
                == AssetVulnerability.asset_id,
            )
            .join(
                Vulnerability,
                Vulnerability.id
                == AssetVulnerability.vulnerability_id,
            )
            .where(
                AssetVulnerability.status
                == "OPEN",
            )
        ).all()

        actions: list[
            InvestmentAction
        ] = []

        for (
            mapping,
            asset,
            vulnerability,
        ) in mappings:

            risk = risk_by_mapping.get(
                (
                    vulnerability.id,
                    asset.id,
                )
            )

            if risk is None:
                continue

            try:
                simulation = simulate_patch(
                    self.db,
                    vulnerability.id,
                    asset.id,
                )
            except ValueError:
                continue

            cost = self._estimate_cost(
                vulnerability,
                asset,
            )

            days = self._estimate_days(
                vulnerability,
                asset,
            )

            engineers = self._estimate_engineers(
                vulnerability,
                asset,
            )

            impact = (
                simulation.security_impact
            )

            value_per_1000 = (
                impact
                / cost
                * 1000
                if cost > 0
                else 0.0
            )

            actions.append(
                InvestmentAction(
                    vulnerability_id=(
                        vulnerability.id
                    ),
                    asset_id=asset.id,
                    cve_id=(
                        vulnerability.cve_id
                    ),
                    title=(
                        vulnerability.title
                    ),
                    asset_name=asset.name,
                    current_risk=(
                        risk.risk_score
                    ),
                    individual_security_impact=(
                        impact
                    ),
                    eliminated_paths=(
                        simulation.eliminated_paths
                    ),
                    eliminated_critical_paths=(
                        simulation.eliminated_critical_paths
                    ),
                    estimated_cost=cost,
                    estimated_days=days,
                    estimated_engineers=(
                        engineers
                    ),
                    value_per_1000=round(
                        value_per_1000,
                        2,
                    ),
                )
            )

        actions.sort(
            key=lambda item: (
                item.value_per_1000,
                item.individual_security_impact,
                item.eliminated_critical_paths,
            ),
            reverse=True,
        )

        return actions

    # =========================================================
    # OPTIMIZATION
    # =========================================================

    def optimize(
        self,
        budget: float,
        engineers: int,
        days: float,
    ) -> dict:

        if budget <= 0:
            raise ValueError(
                "Budget must be greater than zero."
            )

        if engineers <= 0:
            raise ValueError(
                "Engineers must be greater than zero."
            )

        if days <= 0:
            raise ValueError(
                "Time window must be greater than zero."
            )

        actions = self.generate_actions()

        risk_results = RiskEngine(
            self.db
        ).analyze()

        graph_result = AttackGraphEngine(
            self.db
        ).analyze()

        all_paths = graph_result.paths

        baseline_attack_exposure = (
            self._attack_exposure(
                all_paths
            )
        )

        current_risk = (
            self._organizational_risk(
                risk_results=risk_results,
                all_paths=all_paths,
                excluded_actions=set(),
                baseline_attack_exposure=(
                    baseline_attack_exposure
                ),
            )
        )

        if not actions:
            return {
                "current_risk": current_risk,
                "optimized_risk": current_risk,
                "risk_reduction": 0.0,
                "investment": 0.0,
                "budget_remaining": budget,
                "engineers_used": 0,
                "days_used": 0.0,
                "security_impact": 0.0,
                "attack_paths_before": len(
                    all_paths
                ),
                "attack_paths_after": len(
                    all_paths
                ),
                "critical_paths_before": sum(
                    path.target_criticality
                    == "CRITICAL"
                    for path in all_paths
                ),
                "critical_paths_after": sum(
                    path.target_criticality
                    == "CRITICAL"
                    for path in all_paths
                ),
                "exposure_before": round(
                    baseline_attack_exposure,
                    2,
                ),
                "exposure_after": round(
                    baseline_attack_exposure,
                    2,
                ),
                "actions": [],
                "alternatives": [],
            }

        max_candidates = min(
            len(actions),
            18,
        )

        candidates = actions[
            :max_candidates
        ]

        best_actions: list[
            InvestmentAction
        ] = []

        best_risk = current_risk
        best_joint = None

        for size in range(
            1,
            len(candidates) + 1,
        ):
            for subset in combinations(
                candidates,
                size,
            ):

                total_cost = sum(
                    item.estimated_cost
                    for item in subset
                )

                if total_cost > budget:
                    continue

                total_days = sum(
                    item.estimated_days
                    for item in subset
                )

                if total_days > days:
                    continue

                total_engineers = sum(
                    item.estimated_engineers
                    for item in subset
                )

                if total_engineers > engineers:
                    continue

                joint = self._joint_impact(
                    all_paths,
                    list(subset),
                )

                residual_risk = (
                    self._organizational_risk_after(
                        risk_results=risk_results,
                        all_paths=all_paths,
                        selected_actions=list(
                            subset
                        ),
                        baseline_attack_exposure=(
                            baseline_attack_exposure
                        ),
                    )
                )

                # Prefer lower residual risk.
                # If tied, prefer greater critical-path
                # elimination and lower investment.
                current_signature = (
                    residual_risk,
                    -joint[
                        "eliminated_critical_paths"
                    ],
                    total_cost,
                )

                best_signature = (
                    best_risk,
                    -(
                        best_joint[
                            "eliminated_critical_paths"
                        ]
                        if best_joint
                        else 0
                    ),
                    sum(
                        item.estimated_cost
                        for item in best_actions
                    ),
                )

                if current_signature < best_signature:
                    best_risk = residual_risk
                    best_actions = list(
                        subset
                    )
                    best_joint = joint

        if best_joint is None:
            return {
                "current_risk": current_risk,
                "optimized_risk": current_risk,
                "risk_reduction": 0.0,
                "investment": 0.0,
                "budget_remaining": budget,
                "engineers_used": 0,
                "days_used": 0.0,
                "security_impact": 0.0,
                "attack_paths_before": len(
                    all_paths
                ),
                "attack_paths_after": len(
                    all_paths
                ),
                "critical_paths_before": sum(
                    path.target_criticality
                    == "CRITICAL"
                    for path in all_paths
                ),
                "critical_paths_after": sum(
                    path.target_criticality
                    == "CRITICAL"
                    for path in all_paths
                ),
                "exposure_before": round(
                    baseline_attack_exposure,
                    2,
                ),
                "exposure_after": round(
                    baseline_attack_exposure,
                    2,
                ),
                "actions": [],
                "alternatives": [
                    self._action_dict(
                        action
                    )
                    for action in candidates[:5]
                ],
            }

        investment = sum(
            item.estimated_cost
            for item in best_actions
        )

        engineers_used = sum(
            item.estimated_engineers
            for item in best_actions
        )

        days_used = sum(
            item.estimated_days
            for item in best_actions
        )

        optimized_risk = (
            self._organizational_risk_after(
                risk_results=risk_results,
                all_paths=all_paths,
                selected_actions=best_actions,
                baseline_attack_exposure=(
                    baseline_attack_exposure
                ),
            )
        )

        attack_impact = self._joint_impact(
            all_paths,
            best_actions,
        )

        risk_reduction = max(
            current_risk
            - optimized_risk,
            0.0,
        )

        alternatives = [
            action
            for action in candidates
            if action not in best_actions
        ]

        alternatives.sort(
            key=lambda item: (
                item.value_per_1000,
                item.individual_security_impact,
            ),
            reverse=True,
        )

        return {
            "current_risk": round(
                current_risk,
                2,
            ),
            "optimized_risk": round(
                optimized_risk,
                2,
            ),
            "risk_reduction": round(
                risk_reduction,
                2,
            ),
            "investment": round(
                investment,
                2,
            ),
            "budget_remaining": round(
                budget - investment,
                2,
            ),
            "engineers_used": engineers_used,
            "days_used": round(
                days_used,
                1,
            ),
            "security_impact": (
                attack_impact[
                    "security_impact"
                ]
            ),
            "attack_paths_before": len(
                all_paths
            ),
            "attack_paths_after": (
                attack_impact[
                    "remaining_paths"
                ]
            ),
            "critical_paths_before": sum(
                path.target_criticality
                == "CRITICAL"
                for path in all_paths
            ),
            "critical_paths_after": (
                attack_impact[
                    "remaining_critical_paths"
                ]
            ),
            "exposure_before": round(
                attack_impact[
                    "before_exposure"
                ],
                2,
            ),
            "exposure_after": round(
                attack_impact[
                    "after_exposure"
                ],
                2,
            ),
            "actions": [
                self._action_dict(
                    action
                )
                for action in best_actions
            ],
            "alternatives": [
                {
                    "vulnerability_id": (
                        action.vulnerability_id
                    ),
                    "asset_id": action.asset_id,
                    "cve_id": action.cve_id,
                    "asset_name": (
                        action.asset_name
                    ),
                    "security_impact": (
                        action.individual_security_impact
                    ),
                    "estimated_cost": (
                        action.estimated_cost
                    ),
                    "estimated_days": (
                        action.estimated_days
                    ),
                    "value_per_1000": (
                        action.value_per_1000
                    ),
                }
                for action in alternatives[:5]
            ],
        }

    # =========================================================
    # SERIALIZATION
    # =========================================================

    @staticmethod
    def _action_dict(
        action: InvestmentAction,
    ) -> dict:

        return {
            "vulnerability_id": (
                action.vulnerability_id
            ),
            "asset_id": action.asset_id,
            "cve_id": action.cve_id,
            "title": action.title,
            "asset_name": action.asset_name,
            "current_risk": (
                action.current_risk
            ),
            "security_impact": (
                action.individual_security_impact
            ),
            "eliminated_paths": (
                action.eliminated_paths
            ),
            "eliminated_critical_paths": (
                action.eliminated_critical_paths
            ),
            "estimated_cost": (
                action.estimated_cost
            ),
            "estimated_days": (
                action.estimated_days
            ),
            "estimated_engineers": (
                action.estimated_engineers
            ),
            "value_per_1000": (
                action.value_per_1000
            ),
        }
