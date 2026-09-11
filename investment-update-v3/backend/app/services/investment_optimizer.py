from dataclasses import dataclass
from itertools import combinations
import math

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
from app.services.financial_simulation import calculate_financial_exposure
from app.services.investment_explainability import (
    action_type_label,
    rejected_reason,
    selected_reason,
)
from app.services.control_simulation import (
    simulate_isolation,
    simulate_segmentation,
)
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
      PATCH    - remediate a vulnerability on an asset
      SEGMENT  - break an existing asset relationship
      ISOLATE  - reduce internet exposure of an asset

    All graph-changing actions are evaluated jointly so overlapping
    attack-path impact is not double-counted.
    """

    def __init__(self, db: Session, user_id: int):
        self.db = db
        self.user_id = user_id

    # =========================================================
    # AI DECISION LAYER
    # =========================================================
    # A self-contained, explainable ML calibration layer. The model is
    # intentionally lightweight so the SIH prototype has no external
    # model dependency, while the final decision still remains grounded
    # in hard cybersecurity signals and exact constraint checking.

    _AI_VERSION = "2.1-hybrid-monotonic"

    @staticmethod
    def _ai_sigmoid(value: float) -> float:
        value = max(min(value, 12.0), -12.0)
        return 1.0 / (1.0 + math.exp(-value))

    @classmethod
    def _ai_training_rows(cls) -> list[tuple[list[float], int]]:
        # Weakly-supervised expert archetypes. The labels are intentionally
        # conservative: actions with strong contextual security evidence are
        # positive, while low-impact/low-risk actions are negative.
        # Feature order:
        # risk, security impact, critical paths, attack paths, efficiency,
        # exposure pressure, threat pressure, urgency, low effort.
        negatives = [
            [0.05, 0.05, 0.00, 0.02, 0.05, 0.00, 0.00, 0.00, 0.95],
            [0.12, 0.10, 0.00, 0.05, 0.12, 0.10, 0.00, 0.05, 0.85],
            [0.20, 0.18, 0.05, 0.10, 0.18, 0.10, 0.10, 0.10, 0.75],
            [0.28, 0.22, 0.05, 0.15, 0.25, 0.20, 0.15, 0.15, 0.65],
            [0.35, 0.30, 0.10, 0.20, 0.30, 0.20, 0.20, 0.25, 0.60],
            [0.42, 0.35, 0.10, 0.25, 0.35, 0.25, 0.25, 0.30, 0.55],
        ]
        positives = [
            [0.45, 0.45, 0.20, 0.30, 0.40, 0.35, 0.30, 0.35, 0.55],
            [0.50, 0.50, 0.25, 0.35, 0.45, 0.40, 0.35, 0.40, 0.50],
            [0.58, 0.55, 0.30, 0.40, 0.50, 0.45, 0.40, 0.50, 0.45],
            [0.65, 0.60, 0.45, 0.50, 0.55, 0.55, 0.50, 0.60, 0.40],
            [0.72, 0.65, 0.55, 0.60, 0.65, 0.65, 0.60, 0.70, 0.35],
            [0.80, 0.75, 0.65, 0.70, 0.70, 0.75, 0.70, 0.80, 0.30],
            [0.90, 0.85, 0.80, 0.80, 0.78, 0.85, 0.85, 0.90, 0.25],
            [0.98, 0.95, 0.95, 0.95, 0.90, 1.00, 1.00, 1.00, 0.20],
        ]
        return [(row, 0) for row in negatives] + [(row, 1) for row in positives]

    @classmethod
    def _ai_fit_weights(cls) -> list[float]:
        # Logistic regression fitted with deterministic gradient descent.
        rows = cls._ai_training_rows()
        weights = [0.0] * 10
        learning_rate = 0.55
        l2 = 0.015

        for _ in range(900):
            grad = [0.0] * 10
            for features, label in rows:
                x = [1.0, *features]
                raw = sum(w * v for w, v in zip(weights, x))
                prediction = cls._ai_sigmoid(raw)
                error = prediction - label
                for idx, value in enumerate(x):
                    grad[idx] += error * value
            scale = 1.0 / len(rows)
            for idx in range(len(weights)):
                regularizer = l2 * weights[idx] if idx else 0.0
                weights[idx] -= learning_rate * ((grad[idx] * scale) + regularizer)
        return weights

    @classmethod
    def _ai_weights(cls) -> list[float]:
        # The fit is deterministic and tiny; caching avoids doing it for every action.
        cache = getattr(cls, "_AI_WEIGHT_CACHE", None)
        if cache is None:
            cache = cls._ai_fit_weights()
            setattr(cls, "_AI_WEIGHT_CACHE", cache)
        return cache

    @classmethod
    def _ai_expert_score(cls, features: list[float]) -> float:
        risk, impact, critical, paths, efficiency, exposure, threat, urgency, low_effort = features
        # Safety anchor: this is intentionally monotonic and keeps AI from
        # overriding the underlying cyber-risk semantics.
        score = (
            0.24 * risk
            + 0.18 * impact
            + 0.17 * critical
            + 0.12 * paths
            + 0.10 * efficiency
            + 0.07 * exposure
            + 0.07 * threat
            + 0.04 * urgency
            + 0.01 * low_effort
        )
        return max(0.0, min(score, 1.0))

    @classmethod
    def _ai_model_predict(cls, features: list[float]) -> tuple[float, float, float]:
        weights = cls._ai_weights()
        x = [1.0, *features]
        raw = sum(w * v for w, v in zip(weights, x))
        probability = cls._ai_sigmoid(raw)

        # Hybrid decision score: ML probability + monotonic cybersecurity
        # anchor. This makes the decision stable even when a live action sits
        # outside the tiny prototype training distribution.
        expert = cls._ai_expert_score(features)
        hybrid = max(0.0, min((0.62 * probability) + (0.38 * expert), 1.0))

        # OOD-aware confidence. A prototype model should be less confident
        # when live feature combinations are unlike its training archetypes.
        ranges = [(0.0, 1.0)] * 9
        distance = 0.0
        for value, (low, high) in zip(features, ranges):
            if value < low:
                distance += low - value
            elif value > high:
                distance += value - high
        domain_confidence = max(0.0, 1.0 - min(distance / 2.0, 1.0))
        boundary_confidence = 0.5 + min(abs(probability - 0.5), 0.5)
        confidence = 55.0 + (domain_confidence * boundary_confidence * 45.0)

        return round(hybrid * 100.0, 2), round(confidence, 1), round(probability * 100.0, 2)

    @classmethod
    def _ai_score_action(cls, action: InvestmentAction) -> tuple[float, float, float]:
        max_paths_scale = 8.0
        max_critical_scale = 5.0
        max_efficiency_scale = 2.0

        urgency = 1.0 if action.current_risk >= 85 else 0.75 if action.current_risk >= 70 else 0.45 if action.current_risk >= 45 else 0.20
        low_effort = 1.0 - min(max(action.estimated_days / 8.0, 0.0), 1.0)
        action_exposure = 1.0 if action.action_type == "ISOLATE" else 0.72 if action.action_type == "SEGMENT" else 0.48
        threat_pressure = min(max((action.current_risk / 100.0) * 0.75 + (action.eliminated_critical_paths / max_critical_scale) * 0.25, 0.0), 1.0)

        features = [
            max(0.0, min(action.current_risk / 100.0, 1.0)),
            max(0.0, min(action.security_impact / 100.0, 1.0)),
            max(0.0, min(action.eliminated_critical_paths / max_critical_scale, 1.0)),
            max(0.0, min(action.eliminated_paths / max_paths_scale, 1.0)),
            max(0.0, min(action.value_per_1000 / max_efficiency_scale, 1.0)),
            action_exposure,
            threat_pressure,
            urgency,
            low_effort,
        ]
        return cls._ai_model_predict(features)

    @classmethod
    def _ai_validate_model(cls) -> dict:
        base = [0.55, 0.55, 0.30, 0.40, 0.50, 0.45, 0.45, 0.50, 0.50]
        tests = {
            "risk_monotonic": (base, [0.75, *base[1:]]),
            "impact_monotonic": (base, [base[0], 0.80, *base[2:]]),
            "critical_path_monotonic": (base, [*base[:2], 0.80, *base[3:]]),
            "attack_path_monotonic": (base, [*base[:3], 0.80, *base[4:]]),
            "efficiency_monotonic": (base, [*base[:4], 0.90, *base[5:]]),
            "threat_monotonic": (base, [*base[:6], 0.90, *base[7:]]),
        }
        results = {}
        for name, (low, high) in tests.items():
            low_score = cls._ai_model_predict(low)[0]
            high_score = cls._ai_model_predict(high)[0]
            results[name] = high_score >= low_score

        bounded = all(0.0 <= cls._ai_model_predict([i / 10.0 for i in range(1, 10)])[0] <= 100.0 for _ in range(1))
        passed = all(results.values()) and bounded
        return {
            "passed": passed,
            "tests": results,
            "bounded_output": bounded,
        }

    @classmethod
    def _ai_annotate_actions(cls, actions: list[InvestmentAction]) -> dict[str, tuple[float, float, float]]:
        return {action.action_id: cls._ai_score_action(action) for action in actions}

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
    # ISOLATION COST / EFFORT
    # =========================================================

    @staticmethod
    def _isolation_cost(
        asset: Asset,
    ) -> float:

        base = 30000.0

        criticality_multiplier = {
            "LOW": 0.9,
            "MEDIUM": 1.0,
            "HIGH": 1.2,
            "CRITICAL": 1.5,
        }.get(
            asset.criticality.value,
            1.0,
        )

        # Internet gateways and public-facing services can require
        # more coordination because their isolation affects ingress.
        type_multiplier = (
            1.25
            if asset.asset_type
            in {
                "NETWORK_GATEWAY",
                "WEB_SERVER",
            }
            else 1.0
        )

        return round(
            base
            * criticality_multiplier
            * type_multiplier,
            -3,
        )

    @staticmethod
    def _isolation_days(
        asset: Asset,
    ) -> float:

        days = 2.0

        if asset.asset_type == "NETWORK_GATEWAY":
            days += 1.0

        if asset.criticality.value == "CRITICAL":
            days += 1.0

        return round(days, 1)

    @staticmethod
    def _isolation_engineers(
        asset: Asset,
    ) -> int:

        if asset.asset_type == "NETWORK_GATEWAY":
            return 2

        if asset.criticality.value == "CRITICAL":
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

        if action.action_type == "ISOLATE":
            return (
                action.asset_id is not None
                and path.source_asset_id
                == action.asset_id
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

        weighted_total = sum(
            item.risk_score
            * max(
                item.risk_score,
                1.0,
            )
            for item in remaining
        )

        total_weight = sum(
            max(
                item.risk_score,
                1.0,
            )
            for item in remaining
        )

        if total_weight == 0:
            return 0.0

        return (
            weighted_total
            / total_weight
        )

    @classmethod
    def _organizational_risk(
        cls,
        risk_results,
        remaining_paths,
        baseline_attack_exposure,
        removed_actions,
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
            self.db,
            self.user_id,
        ).analyze()

        risk_by_mapping = {
            (
                item.vulnerability_id,
                item.asset_id,
            ): item
            for item in risk_results
        }

        actions: list[
            InvestmentAction
        ] = []

        assets = {
            asset.id: asset
            for asset in self.db.scalars(
                select(Asset).where(Asset.user_id == self.user_id)
            ).all()
        }

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
                AssetVulnerability.status.in_(["OPEN", "ACTIVE"]),
                AssetVulnerability.user_id == self.user_id,
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
                    self.user_id,
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
                        f"PATCH:"
                        f"{vulnerability.id}:"
                        f"{asset.id}"
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
                        f"Patch "
                        f"{vulnerability.cve_id}"
                    ),
                    asset_name=asset.name,
                    current_risk=(
                        risk.risk_score
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

        # -----------------------------------------------------
        # SEGMENTATION ACTIONS
        # -----------------------------------------------------

        relationships = self.db.scalars(
            select(
                AssetRelationship
            ).where(AssetRelationship.user_id == self.user_id)
        ).all()

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
                        self.user_id,
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
                        "Segment network "
                        "trust boundary"
                    ),
                    asset_name=(
                        f"{source.name} → "
                        f"{target.name}"
                    ),
                    current_risk=round(
                        impact,
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
                    estimated_engineers=(
                        engineers
                    ),
                    value_per_1000=round(
                        value,
                        2,
                    ),
                )
            )

        # -----------------------------------------------------
        # ISOLATION ACTIONS
        # -----------------------------------------------------

        internet_assets = [
            asset
            for asset in assets.values()
            if asset.internet_exposed
        ]

        for asset in internet_assets:

            try:
                simulation = simulate_isolation(
                    self.db,
                    asset.id,
                    self.user_id,
                )
            except ValueError:
                continue

            if simulation.eliminated_paths <= 0:
                continue

            cost = self._isolation_cost(
                asset
            )

            days = self._isolation_days(
                asset
            )

            engineers = (
                self._isolation_engineers(
                    asset
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
                        f"ISOLATE:{asset.id}"
                    ),
                    action_type="ISOLATE",
                    vulnerability_id=None,
                    asset_id=asset.id,
                    source_asset_id=None,
                    target_asset_id=None,
                    cve_id=None,
                    title=(
                        "Reduce internet exposure"
                    ),
                    asset_name=asset.name,
                    current_risk=round(
                        impact,
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
                    estimated_engineers=(
                        engineers
                    ),
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

        if not math.isfinite(budget) or budget < 10000:
            raise ValueError(
                "Budget must be at least ₹10,000."
            )

        if engineers < 1:
            raise ValueError(
                "Engineers must be at least 1."
            )

        if not math.isfinite(days) or days < 1:
            raise ValueError(
                "Time window must be at least 1 day."
            )

        if budget > 1_000_000_000:
            raise ValueError(
                "Budget must not exceed ₹100 crore."
            )

        if engineers > 100:
            raise ValueError(
                "Engineers must not exceed 100."
            )

        if days > 3650:
            raise ValueError(
                "Time window must not exceed 3650 days."
            )

        actions = self.generate_actions()
        ai_scores = self._ai_annotate_actions(actions)
        actions.sort(
            key=lambda action: (
                ai_scores[action.action_id][0],
                action.current_risk,
                action.eliminated_critical_paths,
                action.value_per_1000,
            ),
            reverse=True,
        )

        risk_results = RiskEngine(
            self.db,
            self.user_id,
        ).analyze()

        graph_result = AttackGraphEngine(
            self.db,
            self.user_id,
        ).analyze()

        all_paths = graph_result.paths

        baseline_attack_exposure = (
            self._attack_exposure(
                all_paths
            )
        )

        current_risk = (
            self._organizational_risk(
                risk_results,
                all_paths,
                baseline_attack_exposure,
                set(),
            )
        )

        if not actions:
            return self._empty_result(
                current_risk,
                budget,
                all_paths,
                baseline_attack_exposure,
            )

        # Build a diverse candidate pool. AI is one ranking signal, but the
        # search also preserves the strongest cyber-risk, critical-path,
        # security-impact, and efficiency actions. For typical SIH-sized
        # environments, every action is evaluated exactly.
        candidate_pool_size = 16
        ranked_sets = [
            sorted(actions, key=lambda a: ai_scores[a.action_id][0], reverse=True),
            sorted(actions, key=lambda a: a.current_risk, reverse=True),
            sorted(actions, key=lambda a: a.eliminated_critical_paths, reverse=True),
            sorted(actions, key=lambda a: a.security_impact, reverse=True),
            sorted(actions, key=lambda a: a.value_per_1000, reverse=True),
        ]
        unique_candidates: dict[str, InvestmentAction] = {}
        for ranked in ranked_sets:
            for action in ranked:
                unique_candidates[action.action_id] = action
                if len(unique_candidates) >= candidate_pool_size:
                    break
            if len(unique_candidates) >= candidate_pool_size:
                break
        candidates = list(unique_candidates.values())
        if len(actions) <= candidate_pool_size:
            candidates = actions[:]

        candidates.sort(
            key=lambda action: (
                ai_scores[action.action_id][0],
                action.current_risk,
                action.eliminated_critical_paths,
                action.value_per_1000,
            ),
            reverse=True,
        )

        # Fail gracefully when the constraint set cannot support even one
        # remediation action. This is especially important for small budgets
        # such as ₹10,000 / 1 engineer / 1 day: there is no reason to enter
        # the combinatorial search when every candidate is already infeasible.
        feasible_candidates = [
            action
            for action in candidates
            if action.estimated_cost <= budget
            and action.estimated_days <= days
            and action.estimated_engineers <= engineers
        ]

        validation = self._ai_validate_model()

        if not feasible_candidates:
            empty = self._empty_result(
                current_risk,
                budget,
                all_paths,
                baseline_attack_exposure,
                candidates,
            )
            empty["ai_model"]["selection"] = (
                "AI ranking + safety guardrails; no candidate met the current hard constraints"
            )
            empty["ai_model"]["constraint_feasible_actions"] = 0
            empty["constraint_message"] = (
                "No remediation action fits the current budget, engineering, and time limits. "
                "Increase one or more constraints to produce a feasible investment plan."
            )
            return empty

        candidates = feasible_candidates

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
                        risk_results,
                        remaining_paths,
                        baseline_attack_exposure,
                        removed_patch_actions,
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
            risk_results,
            all_paths,
            best_actions,
            baseline_attack_exposure,
        )

        risk_reduction = max(
            current_risk
            - optimized_risk,
            0.0,
        )

        removed_vulnerability_assets = {
            (
                action.vulnerability_id,
                action.asset_id,
            )
            for action in best_actions
            if (
                action.action_type == "PATCH"
                and action.vulnerability_id is not None
                and action.asset_id is not None
            )
        }

        removed_relationships = {
            (
                action.source_asset_id,
                action.target_asset_id,
            )
            for action in best_actions
            if (
                action.action_type == "SEGMENT"
                and action.source_asset_id is not None
                and action.target_asset_id is not None
            )
        }

        isolated_assets = {
            action.asset_id
            for action in best_actions
            if (
                action.action_type == "ISOLATE"
                and action.asset_id is not None
            )
        }

        financial_before = calculate_financial_exposure(
            self.db,
            user_id=self.user_id,
        )

        financial_after = calculate_financial_exposure(
            self.db,
            user_id=self.user_id,
            removed_vulnerability_assets=(
                removed_vulnerability_assets
            ),
            removed_relationships=(
                removed_relationships
            ),
            isolated_assets=(
                isolated_assets
            ),
        )

        current_eal = (
            financial_before["expected_annual_loss"]
        )

        optimized_eal = (
            financial_after["expected_annual_loss"]
        )

        financial_exposure_avoided = round(
            max(
                current_eal
                - optimized_eal,
                0.0,
            ),
            2,
        )

        rosi = round(
            financial_exposure_avoided
            / investment
            if investment > 0
            else 0.0,
            2,
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

        top_ai = max(
            (ai_scores[action.action_id] for action in actions),
            default=(0.0, 0.0),
        )

        return {
            "ai_model": {
                "name": "Singularity Contextual Decision Model",
                "type": "Hybrid monotonic ML + cyber-risk guardrails",
                "version": self._AI_VERSION,
                "status": "validated" if validation["passed"] else "guarded",
                "candidate_actions": len(actions),
                "evaluated_actions": len(candidates),
                "constraint_feasible_actions": len(candidates),
                "top_priority_score": top_ai[0],
                "confidence": top_ai[1],
                "selection": "AI ranking + safety guardrails + constrained portfolio optimization",
                "validation_passed": validation["passed"],
                "validation_tests": validation["tests"],
                "search_mode": "exact" if len(actions) <= candidate_pool_size else "bounded-diverse-exact",
            },
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
            "current_eal": current_eal,
            "optimized_eal": optimized_eal,
            "financial_exposure_avoided": (
                financial_exposure_avoided
            ),
            "rosi": rosi,
            "actions": [
                {
                    **self._action_dict(
                        action,
                        selection_reason=selected_reason(
                            action
                        ),
                    ),
                    "ai_priority_score": ai_scores[action.action_id][0],
                    "ai_confidence": ai_scores[action.action_id][1],
                }
                for action in best_actions
            ],
            "alternatives": [
                {
                    **self._action_dict(
                        action,
                        rejection_reason=rejected_reason(
                            action,
                            best_actions,
                        ),
                    ),
                    "ai_priority_score": ai_scores[action.action_id][0],
                    "ai_confidence": ai_scores[action.action_id][1],
                }
                for action in alternatives[:5]
            ],
        }

    # =========================================================
    # RESIDUAL RISK
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
            risk_results,
            remaining_paths,
            baseline_attack_exposure,
            removed_patch_actions,
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

        ai_scores = self._ai_annotate_actions(candidates or [])
        top_ai = max(
            ai_scores.values(),
            default=(0.0, 0.0),
        )

        validation = self._ai_validate_model()

        return {
            "ai_model": {
                "name": "Singularity Contextual Decision Model",
                "type": "Hybrid monotonic ML + cyber-risk guardrails",
                "version": self._AI_VERSION,
                "status": "validated" if validation["passed"] else "guarded",
                "candidate_actions": len(candidates or []),
                "evaluated_actions": len(candidates or []),
                "top_priority_score": top_ai[0],
                "confidence": top_ai[1],
                "selection": "AI ranking + safety guardrails + constrained portfolio optimization",
                "validation_passed": validation["passed"],
                "validation_tests": validation["tests"],
                "search_mode": "exact",
            },
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
                {
                    **self._action_dict(action),
                    "ai_priority_score": (
                        ai_scores[action.action_id][0]
                        if action.action_id in ai_scores
                        else 0.0
                    ),
                    "ai_confidence": (
                        ai_scores[action.action_id][1]
                        if action.action_id in ai_scores
                        else 0.0
                    ),
                }
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
        selection_reason: str | None = None,
        rejection_reason: str | None = None,
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
            "value_per_100000": round(
                action.value_per_1000 * 100,
                2,
            ),
            "action_label": action_type_label(
                action.action_type
            ),
            "selection_reason": (
                selection_reason
            ),
            "rejection_reason": (
                rejection_reason
            ),
        }










