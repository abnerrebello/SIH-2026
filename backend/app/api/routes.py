from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.engines.attack_graph import AttackGraphEngine
from app.engines.risk import RiskEngine
from app.models import Vulnerability
from app.schemas import (
    AssetCreate,
    AssetResponse,
    RelationshipCreate,
    RelationshipResponse,
    VulnerabilityCreate,
    VulnerabilityResponse,
)
from app.services import (
    asset_service,
    attack_path_service,
    network_service,
    vulnerability_service,
)
from app.services.exceptions import (
    AssetNotFoundError,
    DuplicateAssetError,
    DuplicateVulnerabilityError,
)
from app.services.patch_simulation import simulate_patch

router = APIRouter(prefix="/api/v1", tags=["Security Data"])


@router.get("/assets", response_model=list[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    return asset_service.list_assets(db)


@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    try:
        return asset_service.create_asset(db, payload)
    except DuplicateAssetError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/vulnerabilities", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(db: Session = Depends(get_db)):
    return vulnerability_service.list_vulnerabilities(db)


@router.post(
    "/vulnerabilities", response_model=VulnerabilityResponse, status_code=201
)
def create_vulnerability(
    payload: VulnerabilityCreate, db: Session = Depends(get_db)
):
    try:
        return vulnerability_service.create_vulnerability(db, payload)
    except DuplicateVulnerabilityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/network", response_model=list[RelationshipResponse])
def list_network_relationships(db: Session = Depends(get_db)):
    return network_service.list_relationships(db)


@router.post("/network", response_model=RelationshipResponse, status_code=201)
def create_network_relationship(
    payload: RelationshipCreate, db: Session = Depends(get_db)
):
    try:
        return network_service.create_relationship(db, payload)
    except AssetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/attack-paths")
def get_attack_paths(db: Session = Depends(get_db)):
    return attack_path_service.get_attack_paths_payload(db)


@router.get("/attack-paths/{path_id}")
def get_attack_path_detail(path_id: int, db: Session = Depends(get_db)):
    payload = attack_path_service.get_attack_path_detail_payload(db, path_id)

    if payload is None:
        raise HTTPException(status_code=404, detail="Attack path not found.")

    return payload


@router.get("/network/graph")
def get_network_graph(db: Session = Depends(get_db)):
    return attack_path_service.get_network_graph_payload(db)


# ---------------------------------------------------------------------------
# UNCHANGED BELOW — owned by RiskEngine / patch_simulation, not touched here
# ---------------------------------------------------------------------------


@router.get("/priorities")
def get_priorities(
    db: Session = Depends(get_db),
):
    results = RiskEngine(db).analyze()

    return {
        "count": len(results),
        "results": [
            {
                "rank": index,
                "vulnerability_id": item.vulnerability_id,
                "cve_id": item.cve_id,
                "title": item.title,
                "asset_id": item.asset_id,
                "asset_name": item.asset_name,
                "cvss_score": item.cvss_score,
                "cvss_priority": item.cvss_priority,
                "risk_score": item.risk_score,
                "priority": item.priority,
                "attack_path_count": item.attack_path_count,
                "critical_targets_reached": item.critical_targets_reached,
                "choke_point": item.choke_point,
                "reasons": item.reasons,
                "score_breakdown": item.score_breakdown,
            }
            for index, item in enumerate(results, start=1)
        ],
    }


@router.get("/risk-summary")
def get_risk_summary(
    db: Session = Depends(get_db),
):
    results = RiskEngine(db).analyze()

    critical = sum(item.priority == "CRITICAL" for item in results)
    high = sum(item.priority == "HIGH" for item in results)
    medium = sum(item.priority == "MEDIUM" for item in results)
    low = sum(item.priority == "LOW" for item in results)

    average_score = (
        round(sum(item.risk_score for item in results) / len(results), 2)
        if results
        else 0.0
    )

    maximum_score = round(
        max((item.risk_score for item in results), default=0.0),
        2,
    )

    return {
        "overall_risk_score": maximum_score,
        "average_risk_score": average_score,
        "total_vulnerabilities": len(results),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# IMPORTANT:
# Static route MUST come before /priorities/{vulnerability_id}

@router.get("/priorities/comparison")
def compare_prioritization(
    db: Session = Depends(get_db),
):
    results = RiskEngine(db).analyze()

    cvss_ranked = sorted(
        results, key=lambda item: item.cvss_score, reverse=True
    )

    contextual_ranked = sorted(
        results, key=lambda item: item.risk_score, reverse=True
    )

    cvss_rank = {
        item.vulnerability_id: rank
        for rank, item in enumerate(cvss_ranked, start=1)
    }

    contextual_rank = {
        item.vulnerability_id: rank
        for rank, item in enumerate(contextual_ranked, start=1)
    }

    return {
        "cvss_ranking": [
            {
                "rank": rank,
                "cve_id": item.cve_id,
                "cvss_score": item.cvss_score,
                "asset_name": item.asset_name,
            }
            for rank, item in enumerate(cvss_ranked, start=1)
        ],
        "aegispath_ranking": [
            {
                "rank": rank,
                "cve_id": item.cve_id,
                "risk_score": item.risk_score,
                "priority": item.priority,
                "asset_name": item.asset_name,
            }
            for rank, item in enumerate(contextual_ranked, start=1)
        ],
        "ranking_changes": [
            {
                "cve_id": item.cve_id,
                "cvss_rank": cvss_rank[item.vulnerability_id],
                "aegispath_rank": contextual_rank[item.vulnerability_id],
                "rank_change": (
                    cvss_rank[item.vulnerability_id]
                    - contextual_rank[item.vulnerability_id]
                ),
            }
            for item in contextual_ranked
        ],
    }


@router.get("/priorities/{vulnerability_id}")
def get_priority_detail(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    results = RiskEngine(db).analyze()

    item = next(
        (
            result
            for result in results
            if result.vulnerability_id == vulnerability_id
        ),
        None,
    )

    if item is None:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability priority record not found.",
        )

    paths = AttackGraphEngine(db).analyze().paths

    relevant_paths = [
        {
            "source_asset_id": path.source_asset_id,
            "target_asset_id": path.target_asset_id,
            "asset_names": path.asset_names,
            "risk_score": path.risk_score,
            "path_length": path.path_length,
            "target_criticality": path.target_criticality,
            "choke_points": path.choke_points,
        }
        for path in paths
        if item.cve_id in path.vulnerabilities
    ]

    vulnerability = db.get(Vulnerability, vulnerability_id)

    return {
        "vulnerability_id": item.vulnerability_id,
        "cve_id": item.cve_id,
        "title": item.title,
        "description": (
            vulnerability.description if vulnerability else None
        ),
        "remediation": (
            vulnerability.remediation if vulnerability else None
        ),
        "asset_id": item.asset_id,
        "asset_name": item.asset_name,
        "cvss_score": item.cvss_score,
        "risk_score": item.risk_score,
        "priority": item.priority,
        "cvss_priority": item.cvss_priority,
        "attack_path_count": item.attack_path_count,
        "critical_targets_reached": item.critical_targets_reached,
        "choke_point": item.choke_point,
        "reasons": item.reasons,
        "score_breakdown": item.score_breakdown,
        "attack_paths": relevant_paths,
    }


@router.post("/simulations/patch-impact/{vulnerability_id}")
def get_patch_impact(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    try:
        result = simulate_patch(db, vulnerability_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {
        "vulnerability_id": result.vulnerability_id,
        "cve_id": result.cve_id,
        "before": {
            "attack_paths": result.before_paths,
            "critical_attack_paths": result.before_critical_paths,
            "risk_score": result.before_risk,
        },
        "after": {
            "attack_paths": result.after_paths,
            "critical_attack_paths": result.after_critical_paths,
            "risk_score": result.after_risk,
        },
        "impact": {
            "eliminated_paths": result.eliminated_paths,
            "eliminated_critical_paths": result.eliminated_critical_paths,
            "risk_reduction": result.risk_reduction,
        },
    }