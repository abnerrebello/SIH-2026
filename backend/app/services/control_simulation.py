from dataclasses import dataclass

from app.engines.attack_graph import AttackGraphEngine


@dataclass
class SegmentationSimulationResult:
    source_asset_id: int
    target_asset_id: int

    before_paths: int
    after_paths: int

    before_critical_paths: int
    after_critical_paths: int

    eliminated_paths: int
    eliminated_critical_paths: int

    security_impact: float


@dataclass
class IsolationSimulationResult:
    asset_id: int

    before_paths: int
    after_paths: int

    before_critical_paths: int
    after_critical_paths: int

    eliminated_paths: int
    eliminated_critical_paths: int

    security_impact: float


def _impact(
    before_paths: list,
    after_paths: list,
) -> tuple[int, int, float]:

    before_critical = [
        path
        for path in before_paths
        if path.target_criticality == "CRITICAL"
    ]

    after_critical = [
        path
        for path in after_paths
        if path.target_criticality == "CRITICAL"
    ]

    eliminated_paths = (
        len(before_paths)
        - len(after_paths)
    )

    eliminated_critical_paths = (
        len(before_critical)
        - len(after_critical)
    )

    path_reduction = (
        eliminated_paths
        / len(before_paths)
        * 100.0
        if before_paths
        else 0.0
    )

    critical_reduction = (
        eliminated_critical_paths
        / len(before_critical)
        * 100.0
        if before_critical
        else 0.0
    )

    security_impact = min(
        (
            path_reduction * 0.4
            + critical_reduction * 0.6
        ),
        100.0,
    )

    return (
        eliminated_paths,
        eliminated_critical_paths,
        round(security_impact, 2),
    )


def simulate_segmentation(
    db,
    source_asset_id: int,
    target_asset_id: int,
    user_id: int,
) -> SegmentationSimulationResult:

    graph_result = AttackGraphEngine(db, user_id).analyze()

    before_paths = list(
        graph_result.paths
    )

    remaining_paths = [
        path
        for path in before_paths
        if not any(
            path.asset_ids[index]
            == source_asset_id
            and path.asset_ids[index + 1]
            == target_asset_id
            for index in range(
                len(path.asset_ids) - 1
            )
        )
    ]

    before_critical = sum(
        path.target_criticality == "CRITICAL"
        for path in before_paths
    )

    after_critical = sum(
        path.target_criticality == "CRITICAL"
        for path in remaining_paths
    )

    (
        eliminated_paths,
        eliminated_critical_paths,
        security_impact,
    ) = _impact(
        before_paths,
        remaining_paths,
    )

    return SegmentationSimulationResult(
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        before_paths=len(before_paths),
        after_paths=len(remaining_paths),
        before_critical_paths=before_critical,
        after_critical_paths=after_critical,
        eliminated_paths=eliminated_paths,
        eliminated_critical_paths=(
            eliminated_critical_paths
        ),
        security_impact=security_impact,
    )


def simulate_isolation(
    db,
    asset_id: int,
    user_id: int,
) -> IsolationSimulationResult:

    graph_result = AttackGraphEngine(db, user_id).analyze()

    before_paths = list(
        graph_result.paths
    )

    asset = graph_result.nodes

    remaining_paths = [
        path
        for path in before_paths
        if path.source_asset_id != asset_id
    ]

    before_critical = sum(
        path.target_criticality == "CRITICAL"
        for path in before_paths
    )

    after_critical = sum(
        path.target_criticality == "CRITICAL"
        for path in remaining_paths
    )

    (
        eliminated_paths,
        eliminated_critical_paths,
        security_impact,
    ) = _impact(
        before_paths,
        remaining_paths,
    )

    return IsolationSimulationResult(
        asset_id=asset_id,
        before_paths=len(before_paths),
        after_paths=len(remaining_paths),
        before_critical_paths=before_critical,
        after_critical_paths=after_critical,
        eliminated_paths=eliminated_paths,
        eliminated_critical_paths=(
            eliminated_critical_paths
        ),
        security_impact=security_impact,
    )
