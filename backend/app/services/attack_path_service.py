from sqlalchemy.orm import Session

from app.engines.attack_graph import AttackGraphEngine


def get_attack_paths_payload(db: Session) -> dict:
    result = AttackGraphEngine(db).analyze()

    return {
        "paths": [
            {
                "source_asset_id": path.source_asset_id,
                "target_asset_id": path.target_asset_id,
                "asset_ids": path.asset_ids,
                "asset_names": path.asset_names,
                "vulnerabilities": path.vulnerabilities,
                "path_length": path.path_length,
                "target_criticality": path.target_criticality,
                "risk_score": path.risk_score,
                "choke_points": path.choke_points,
            }
            for path in result.paths
        ],
        "choke_points": result.choke_points,
        "path_count": len(result.paths),
    }


def get_attack_path_detail_payload(db: Session, path_id: int) -> dict | None:
    result = AttackGraphEngine(db).analyze()

    if path_id < 0 or path_id >= len(result.paths):
        return None

    path = result.paths[path_id]

    return {
        "id": path_id,
        "source_asset_id": path.source_asset_id,
        "target_asset_id": path.target_asset_id,
        "asset_ids": path.asset_ids,
        "asset_names": path.asset_names,
        "vulnerabilities": path.vulnerabilities,
        "path_length": path.path_length,
        "target_criticality": path.target_criticality,
        "risk_score": path.risk_score,
        "choke_points": path.choke_points,
    }


def get_network_graph_payload(db: Session) -> dict:
    result = AttackGraphEngine(db).analyze()

    return {
        "nodes": result.nodes,
        "edges": result.edges,
        "choke_points": result.choke_points,
    }
    