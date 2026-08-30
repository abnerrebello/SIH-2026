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


def simulate_segmentation(
    db,
    source_asset_id: int,
    target_asset_id: int,
) -> SegmentationSimulationResult:

    graph_result = AttackGraphEngine(db).analyze()

    before_paths = list(
        graph_result.paths
    )

    before_critical = [
        path
        for path in before_paths
        if path.target_criticality == "CRITICAL"
    ]

    remaining_paths = [
        path
        for path in before_paths
        if not any(
            path.asset_ids[index] == source_asset_id
            and path.asset_ids[index + 1] == target_asset_id
            for index in range(
                len(path.asset_ids) - 1
            )
        )
    ]

    after_critical = [
        path
        for path in remaining_paths
        if path.target_criticality == "CRITICAL"
    ]

    eliminated_paths = (
        len(before_paths)
        - len(remaining_paths)
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

    return SegmentationSimulationResult(
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        before_paths=len(before_paths),
        after_paths=len(remaining_paths),
        before_critical_paths=len(
            before_critical
        ),
        after_critical_paths=len(
            after_critical
        ),
        eliminated_paths=eliminated_paths,
        eliminated_critical_paths=(
            eliminated_critical_paths
        ),
        security_impact=round(
            security_impact,
            2,
        ),
    )
