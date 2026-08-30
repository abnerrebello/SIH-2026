from dataclasses import dataclass
from itertools import combinations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine
from app.engines.risk import RiskEngine
from app.models import (
    Asset,
    AssetRelationship,
    AssetVulnerability,
    Vulnerability,
)
from app.services.control_simulation import simulate_segmentation
from app.services.patch_simulation import simulate_patch


@dataclass(frozen=True)
class InvestmentAction:
    action_id: str
    action_type: str

    vulnerability_id: int | None
    asset_id: int | None

    source_asset_id: int | None
    target_asset_id: int | None

    cve_id: str | None
    title: str
    asset_name: str

    current_risk: float
    security_impact: float

    eliminated_paths: int
    eliminated_critical_paths: int

    estimated_cost: float
    estimated_days: float
    estimated_engineers: int

    value_per_1000: float


class InvestmentOptimizer:
    """
    Security investment portfolio optimizer.

    Supported actions:
      - Vulnerability patching
      - Network segmentation

    The optimizer evaluates combinations jointly against the
    attack graph and remaining vulnerability landscape instead
    of simply adding individual action percentages together.
    """

    def __init__(self, db: Session):
        self.db = db

    # =========================================================
    # PATCH COST / EFFORT
    # =========================================================

    @staticmethod
    def _patch_cost(
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

        threat_multiplier = (
            1.2
            if (
                vulnerability.actively_exploited
                or vulnerability.kev_status
            )
            else 1.0
        )

        criticality_multiplier = {
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
            * threat_multiplier
            * criticality_multiplier,
            -3,
        )

    @staticmethod
    def _patch_days(
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

        return round(days, 1)

    @staticmethod
    def _patch_engineers(
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
    # SEGMENTATION COST / EFFORT
    # =========================================================

    @staticmethod
    def _segmentation_cost(
        relationship: AssetRelationship,
        source: Asset,
        target: Asset,
    ) -> float:

        base = 35000.0

        relationship_multiplier = {
            "NETWORK_ACCESS": 1.0,
            "LATERAL_MOVEMENT": 1.15,
            "APPLICATION_ACCESS": 1.1,
            "DATABASE_ACCESS": 1.35,
            "IDENTITY_ACCESS": 1.45,
        }.get(
            relationship.relationship_type,
            1.1,
        )

        trust_multiplier = {
            "LOW": 0.9,
            "MEDIUM": 1.0,
            "HIGH": 1.25,
        }.get(
            relationship.trust_level,
            1.0,
        )

        target_multiplier = {
            "LOW": 0.9,
            "MEDIUM": 1.0,
            "HIGH": 1.25,
            "CRITICAL": 1.5,
        }.get(
            target.criticality.value,
            1.0,
        )

        return round(
            base
            * relationship_multiplier
            * trust_multiplier
            * target_multiplier,
            -3,
        )

    @staticmethod
    def _segmentation_days(
        relationship: AssetRelationship,
        source: Asset,
        target: Asset,
    ) -> float:

        days = 2.0

        if relationship.relationship_type in {
            "DATABASE_ACCESS",
            "IDENTITY_ACCESS",
        }:
            days += 1.0

        if relationship.trust_level == "HIGH":
            days += 1.0

        if target.criticality.value == "CRITICAL":
            days += 0.5

        return round(days, 1)

    @staticmethod
    def _segmentation_engineers(
        relationship: AssetRelationship,
        source: Asset,
        target: Asset,
    ) -> int:

        if (
            relationship.trust_level == "HIGH"
            or target.criticality.value == "CRITICAL"
        ):
            return 2

        return 1

    # =========================================================
    # GRAPH HELPERS
    # =========================================================

    @staticmethod
    def _path_matches_action(
        path,
        action: InvestmentAction,
    ) -> bool:

        if action.action_type == "PATCH":
            return (
                action.cve_id in path.vulnerabilities
                and action.asset_id in path.asset_ids
            )

        if action.action_type == "SEGMENT":
            if (
                action.source_asset_id is None
                or action.target_asset_id is None
            ):
                return False

            return any(
                path.asset_ids[index]
                == action.source_asset_id
                and path.asset_ids[index + 1]
                == action.target_asset_id
                for index in range(
                    len(path.asset_ids) - 1
                )
            )

        return False

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
    def _joint_attack_impact(
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
            path.target_criticality
            == "CRITICAL"
            for path in before_paths
        )

        after_critical = sum(
            path.target_criticality
            == "CRITICAL"
            for path in after_paths
        )

        eliminated_critical = (
            before_critical
            - after_critical
        )

        reduction = (
            (
                before_exposure
                - after_exposure
            )
            / before_exposure
            * 100.0
            if before_exposure > 0
            else 0.0
        )

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
                    min(reduction, 100.0),
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
    # VULNERABILITY EXPOSURE
    # =========================================================

    @staticmethod
    def _vulnerability_exposure(
        risk_results,
        removed_actions: set[tuple[int, int]],
    ) -> float:

        remaining = [
            item
            for item in risk_results
            if (
                item.vulnerability_id,
                item.asset_id,
            ) not in removed_actions
        ]

        if not remaining:
            return 0.0

        # Risk-weighted average. The maximum remains bounded by 100.
        weighted_total = sum(
            item.risk_score
            * max(item.risk_score, 1.0)
            for item in remaining
        )

        total_weight = sum(
            max(item.risk_score, 1.0)
            for item in remaining
        )

        if total_weight == 0:
            return 0.0

        return weighted_total / total_weight

    @classmethod
    def _organizational_risk(
        cls,
        risk_results,
        remaining_paths,
        baseline_attack_exposure: float,
        removed_actions: set[tuple[int, int]],
    ) -> float:

        vulnerability_component = (
            cls._vulnerability_exposure(
                risk_results,
                removed_actions,
            )
        )

        if baseline_attack_exposure > 0:
            attack_component = (
                cls._attack_exposure(
                    remaining_paths
                )
                / baseline_attack_exposure
                * 100.0
            )
        else:
            attack_component = 0.0

        return round(
            max(
                min(
                    vulnerability_component * 0.6
                    + attack_component * 0.4,
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

        actions: list[InvestmentAction] = []

        # -----------------------------------------------------
        # PATCH ACTIONS
        # -----------------------------------------------------

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

            cost = self._patch_cost(
                vulnerability,
                asset,
            )

            days = self._patch_days(
                vulnerability,
                asset,
            )

            engineers = self._patch_engineers(
                vulnerability,
                asset,
            )

            impact = simulation.security_impact

            value = (
                impact
                / cost
                * 1000
                if cost > 0
                else 0.0
            )

            actions.append(
                InvestmentAction(
                    action_id=(
                        f"PATCH:{vulnerability.id}:{asset.id}"
                    ),
                    action_type="PATCH",
                    vulnerability_id=(
                        vulnerability.id
                    ),
                    asset_id=asset.id,
                    source_asset_id=None,
                    target_asset_id=None,
                    cve_id=vulnerability.cve_id,
                    title=(
                        f"Patch {vulnerability.cve_id}"
                    ),
                    asset_name=asset.name,
                    current_risk=risk.risk_score,
                    security_impact=impact,
                    eliminated_paths=(
                        simulation.eliminated_paths
                    ),
                    eliminated_critical_paths=(
                        simulation.eliminated_critical_paths
                    ),
                    estimated_cost=cost,
                    estimated_days=days,
                    estimated_engineers=engineers,
                    value_per_1000=round(
                        value,
                        2,
                    ),
                )
            )

        # -----------------------------------------------------
        # SEGMENTATION ACTIONS
        # -----------------------------------------------------

        relationships = self.db.scalars(
            select(
                AssetRelationship
            )
        ).all()

        assets = {
            asset.id: asset
            for asset in self.db.scalars(
                select(Asset)
            ).all()
        }

        for relationship in relationships:

            source = assets.get(
                relationship.source_asset_id
            )

            target = assets.get(
                relationship.target_asset_id
            )

            if source is None or target is None:
                continue

            try:
                simulation = (
                    simulate_segmentation(
                        self.db,
                        relationship.source_asset_id,
                        relationship.target_asset_id,
                    )
                )
            except ValueError:
                continue

            if simulation.eliminated_paths <= 0:
                continue

            cost = self._segmentation_cost(
                relationship,
                source,
                target,
            )

            days = self._segmentation_days(
                relationship,
                source,
                target,
            )

            engineers = (
                self._segmentation_engineers(
                    relationship,
                    source,
                    target,
                )
            )

            impact = simulation.security_impact

            value = (
                impact
                / cost
                * 1000
                if cost > 0
                else 0.0
            )

            actions.append(
                InvestmentAction(
                    action_id=(
                        "SEGMENT:"
                        f"{relationship.source_asset_id}:"
                        f"{relationship.target_asset_id}:"
                        f"{relationship.id}"
                    ),
                    action_type="SEGMENT",
                    vulnerability_id=None,
                    asset_id=None,
                    source_asset_id=(
                        relationship.source_asset_id
                    ),
                    target_asset_id=(
                        relationship.target_asset_id
                    ),
                    cve_id=None,
                    title=(
                        "Segment network trust boundary"
                    ),
                    asset_name=(
                        f"{source.name} → {target.name}"
                    ),
                    current_risk=round(
                        simulation.security_impact,
                        2,
                    ),
                    security_impact=impact,
                    eliminated_paths=(
                        simulation.eliminated_paths
                    ),
                    eliminated_critical_paths=(
                        simulation.eliminated_critical_paths
                    ),
                    estimated_cost=cost,
                    estimated_days=days,
                    estimated_engineers=engineers,
                    value_per_1000=round(
                        value,
                        2,
                    ),
                )
            )

        actions.sort(
            key=lambda action: (
                action.value_per_1000,
                action.security_impact,
                action.eliminated_critical_paths,
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
                remaining_paths=all_paths,
                baseline_attack_exposure=(
                    baseline_attack_exposure
                ),
                removed_actions=set(),
            )
        )

        if not actions:
            return self._empty_result(
                current_risk,
                budget,
                all_paths,
                baseline_attack_exposure,
            )

        candidates = actions[
            : min(len(actions), 18)
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
                    action.estimated_cost
                    for action in subset
                )

                if total_cost > budget:
                    continue

                total_days = sum(
                    action.estimated_days
                    for action in subset
                )

                if total_days > days:
                    continue

                total_engineers = sum(
                    action.estimated_engineers
                    for action in subset
                )

                if total_engineers > engineers:
                    continue

                remaining_paths = [
                    path
                    for path in all_paths
                    if not any(
                        self._path_matches_action(
                            path,
                            action,
                        )
                        for action in subset
                    )
                ]

                removed_patch_actions = {
                    (
                        action.vulnerability_id,
                        action.asset_id,
                    )
                    for action in subset
                    if (
                        action.action_type
                        == "PATCH"
                    )
                    and action.vulnerability_id
                    is not None
                    and action.asset_id
                    is not None
                }

                residual_risk = (
                    self._organizational_risk(
                        risk_results=risk_results,
                        remaining_paths=(
                            remaining_paths
                        ),
                        baseline_attack_exposure=(
                            baseline_attack_exposure
                        ),
                        removed_actions=(
                            removed_patch_actions
                        ),
                    )
                )

                joint = (
                    self._joint_attack_impact(
                        all_paths,
                        list(subset),
                    )
                )

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
                        action.estimated_cost
                        for action in best_actions
                    ),
                )

                if current_signature < best_signature:
                    best_risk = residual_risk
                    best_actions = list(
                        subset
                    )
                    best_joint = joint

        if best_joint is None:
            return self._empty_result(
                current_risk,
                budget,
                all_paths,
                baseline_attack_exposure,
                candidates,
            )

        investment = sum(
            action.estimated_cost
            for action in best_actions
        )

        engineers_used = sum(
            action.estimated_engineers
            for action in best_actions
        )

        days_used = sum(
            action.estimated_days
            for action in best_actions
        )

        optimized_risk = self._organizational_risk_after(
            risk_results=risk_results,
            all_paths=all_paths,
            actions=best_actions,
            baseline_attack_exposure=(
                baseline_attack_exposure
            ),
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
            key=lambda action: (
                action.value_per_1000,
                action.security_impact,
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
                best_joint[
                    "security_impact"
                ]
            ),
            "attack_paths_before": len(
                all_paths
            ),
            "attack_paths_after": (
                best_joint[
                    "remaining_paths"
                ]
            ),
            "critical_paths_before": sum(
                path.target_criticality
                == "CRITICAL"
                for path in all_paths
            ),
            "critical_paths_after": (
                best_joint[
                    "remaining_critical_paths"
                ]
            ),
            "exposure_before": round(
                best_joint[
                    "before_exposure"
                ],
                2,
            ),
            "exposure_after": round(
                best_joint[
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
                self._action_dict(
                    action
                )
                for action in alternatives[:5]
            ],
        }

    # =========================================================
    # RESIDUAL RISK AFTER SELECTED ACTIONS
    # =========================================================

    def _organizational_risk_after(
        self,
        risk_results,
        all_paths,
        actions,
        baseline_attack_exposure,
    ) -> float:

        removed_patch_actions = {
            (
                action.vulnerability_id,
                action.asset_id,
            )
            for action in actions
            if (
                action.action_type
                == "PATCH"
            )
            and action.vulnerability_id
            is not None
            and action.asset_id
            is not None
        }

        remaining_paths = [
            path
            for path in all_paths
            if not any(
                self._path_matches_action(
                    path,
                    action,
                )
                for action in actions
            )
        ]

        return self._organizational_risk(
            risk_results=risk_results,
            remaining_paths=remaining_paths,
            baseline_attack_exposure=(
                baseline_attack_exposure
            ),
            removed_actions=(
                removed_patch_actions
            ),
        )

    # =========================================================
    # EMPTY RESULT
    # =========================================================

    def _empty_result(
        self,
        current_risk,
        budget,
        all_paths,
        baseline_attack_exposure,
        candidates=None,
    ) -> dict:

        critical_paths = sum(
            path.target_criticality
            == "CRITICAL"
            for path in all_paths
        )

        return {
            "current_risk": round(
                current_risk,
                2,
            ),
            "optimized_risk": round(
                current_risk,
                2,
            ),
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
            "critical_paths_before": critical_paths,
            "critical_paths_after": critical_paths,
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
                for action in (
                    candidates or []
                )[:5]
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
            "action_id": action.action_id,
            "action_type": action.action_type,

            "vulnerability_id": (
                action.vulnerability_id
            ),
            "asset_id": action.asset_id,

            "source_asset_id": (
                action.source_asset_id
            ),
            "target_asset_id": (
                action.target_asset_id
            ),

            "cve_id": action.cve_id,
            "title": action.title,
            "asset_name": action.asset_name,

            "current_risk": (
                action.current_risk
            ),
            "security_impact": (
                action.security_impact
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
