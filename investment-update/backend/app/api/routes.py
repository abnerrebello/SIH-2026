from datetime import datetime

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_user
from app.engines.attack_graph import AttackGraphEngine
from app.engines.risk import RiskEngine
from app.models import Asset, AssetRelationship, Vulnerability, User
from app.schemas import (
    AssetCreate,
    AssetResponse,
    RelationshipCreate,
    RelationshipResponse,
    VulnerabilityCreate,
    VulnerabilityResponse,
)
from app.services.patch_simulation import simulate_patch
from app.services.nvd_service import NVDService
from app.services.epss_service import EPSSService
from app.services.environment_import import EnvironmentImportService
from app.services.investment_optimizer import InvestmentOptimizer

router = APIRouter(prefix="/api/v1", tags=["Security Data"])
@router.get("/threat-intel/{cve_id}")
def get_threat_intelligence(cve_id: str):
    try:
        return NVDService().get_cve(cve_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve vulnerability intelligence from NVD.",
        )



@router.post("/threat-intel/enrich/{vulnerability_id}")
def enrich_vulnerability_epss(
    vulnerability_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vulnerability = db.scalar(
        select(Vulnerability).where(
            Vulnerability.id == vulnerability_id,
            Vulnerability.user_id == current_user.id,
        )
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found.",
        )

    try:
        result = EPSSService().get_score(
            vulnerability.cve_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve EPSS data.",
        ) from exc

    vulnerability.epss_score = result["epss_score"]
    vulnerability.epss_percentile = result["epss_percentile"]

    epss_date = result.get("date")
    if epss_date:
        try:
            vulnerability.epss_updated_at = datetime.fromisoformat(
                epss_date
            )
        except ValueError:
            vulnerability.epss_updated_at = datetime.utcnow()
    else:
        vulnerability.epss_updated_at = datetime.utcnow()

    db.commit()
    db.refresh(vulnerability)

    return {
        "vulnerability_id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "epss_score": vulnerability.epss_score,
        "epss_percentile": vulnerability.epss_percentile,
        "epss_updated_at": vulnerability.epss_updated_at,
    }


@router.post("/threat-intel/enrich-all")
def enrich_all_vulnerabilities_epss(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vulnerabilities = db.scalars(
        select(Vulnerability).where(Vulnerability.user_id == current_user.id).order_by(Vulnerability.id)
    ).all()

    updated = []
    skipped = []

    service = EPSSService()

    for vulnerability in vulnerabilities:
        try:
            result = service.get_score(
                vulnerability.cve_id
            )

            vulnerability.epss_score = result["epss_score"]
            vulnerability.epss_percentile = result[
                "epss_percentile"
            ]

            epss_date = result.get("date")

            if epss_date:
                try:
                    vulnerability.epss_updated_at = (
                        datetime.fromisoformat(epss_date)
                    )
                except ValueError:
                    vulnerability.epss_updated_at = (
                        datetime.utcnow()
                    )
            else:
                vulnerability.epss_updated_at = (
                    datetime.utcnow()
                )

            updated.append({
                "vulnerability_id": vulnerability.id,
                "cve_id": vulnerability.cve_id,
                "epss_score": vulnerability.epss_score,
                "epss_percentile": vulnerability.epss_percentile,
            })

        except ValueError as exc:
            skipped.append({
                "vulnerability_id": vulnerability.id,
                "cve_id": vulnerability.cve_id,
                "reason": str(exc),
            })

        except Exception as exc:
            skipped.append({
                "vulnerability_id": vulnerability.id,
                "cve_id": vulnerability.cve_id,
                "reason": (
                    "EPSS request failed: "
                    f"{type(exc).__name__}"
                ),
            })

    db.commit()

    return {
        "total": len(vulnerabilities),
        "updated": len(updated),
        "skipped": len(skipped),
        "results": updated,
        "skipped_records": skipped,
    }


@router.post("/import/environment")
def import_environment(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="A file is required.",
        )

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are supported.",
        )

    content = file.file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV is empty.",
        )

    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="CSV file must be smaller than 5 MB.",
        )

    service = EnvironmentImportService()

    result = service.import_csv(
        db,
        content,
        current_user.id,
    )

    intelligence = service.enrich_imported_vulnerabilities(
        db,
        result.imported_cves,
        current_user.id,
    )

    return {
        "filename": file.filename,
        **result.to_dict(),
        "intelligence": intelligence,
    }

@router.post("/investment/optimize")
def optimize_investment(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        budget = float(payload.get("budget", 0))
        engineers = int(payload.get("engineers", 0))
        days = float(payload.get("days", 0))

        return InvestmentOptimizer(db, current_user.id).optimize(
            budget=budget,
            engineers=engineers,
            days=days,
        )

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

@router.get("/assets", response_model=list[AssetResponse])
def list_assets(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Asset).where(Asset.user_id == current_user.id).order_by(Asset.id)
    ).all()


@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_asset(
    payload: AssetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.scalar(
        select(Asset).where(Asset.name == payload.name, Asset.user_id == current_user.id)
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Asset name already exists.",
        )

    asset = Asset(user_id=current_user.id, **payload.model_dump())

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilityResponse],
)
def list_vulnerabilities(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Vulnerability).where(Vulnerability.user_id == current_user.id).order_by(
            Vulnerability.cvss_score.desc()
        )
    ).all()


@router.post(
    "/vulnerabilities",
    response_model=VulnerabilityResponse,
    status_code=201,
)
def create_vulnerability(
    payload: VulnerabilityCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id == payload.cve_id,
            Vulnerability.user_id == current_user.id,
        )
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="CVE already exists.",
        )

    vulnerability = Vulnerability(
        user_id=current_user.id,
        **payload.model_dump()
    )

    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    return vulnerability


@router.get(
    "/network",
    response_model=list[RelationshipResponse],
)
def list_network_relationships(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.scalars(
        select(AssetRelationship).where(AssetRelationship.user_id == current_user.id).order_by(
            AssetRelationship.id
        )
    ).all()


@router.post(
    "/network",
    response_model=RelationshipResponse,
    status_code=201,
)
def create_network_relationship(
    payload: RelationshipCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.scalar(select(Asset).where(Asset.id == payload.source_asset_id, Asset.user_id == current_user.id)) is None:
        raise HTTPException(
            status_code=404,
            detail="Source asset not found.",
        )

    if db.scalar(select(Asset).where(Asset.id == payload.target_asset_id, Asset.user_id == current_user.id)) is None:
        raise HTTPException(
            status_code=404,
            detail="Target asset not found.",
        )

    relationship = AssetRelationship(
        user_id=current_user.id,
        **payload.model_dump()
    )

    db.add(relationship)
    db.commit()
    db.refresh(relationship)

    return relationship


@router.get("/attack-paths")
def get_attack_paths(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = AttackGraphEngine(db, current_user.id).analyze()

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


@router.get("/network/graph")
def get_network_graph(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = AttackGraphEngine(db, current_user.id).analyze()

    return {
        "nodes": result.nodes,
        "edges": result.edges,
        "choke_points": result.choke_points,
    }


@router.get("/priorities")
def get_priorities(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    results = RiskEngine(db, current_user.id).analyze()

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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    results = RiskEngine(db, current_user.id).analyze()

    critical = sum(
        item.priority == "CRITICAL"
        for item in results
    )

    high = sum(
        item.priority == "HIGH"
        for item in results
    )

    medium = sum(
        item.priority == "MEDIUM"
        for item in results
    )

    low = sum(
        item.priority == "LOW"
        for item in results
    )

    average_score = (
        round(
            sum(item.risk_score for item in results)
            / len(results),
            2,
        )
        if results
        else 0.0
    )

    maximum_score = round(
        max(
            (item.risk_score for item in results),
            default=0.0,
        ),
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    results = RiskEngine(db, current_user.id).analyze()

    cvss_ranked = sorted(
        results,
        key=lambda item: item.cvss_score,
        reverse=True,
    )

    contextual_ranked = sorted(
        results,
        key=lambda item: item.risk_score,
        reverse=True,
    )

    cvss_rank = {
        item.vulnerability_id: rank
        for rank, item in enumerate(
            cvss_ranked,
            start=1,
        )
    }

    contextual_rank = {
        item.vulnerability_id: rank
        for rank, item in enumerate(
            contextual_ranked,
            start=1,
        )
    }

    return {
        "cvss_ranking": [
            {
                "rank": rank,
                "cve_id": item.cve_id,
                "cvss_score": item.cvss_score,
                "asset_name": item.asset_name,
            }
            for rank, item in enumerate(
                cvss_ranked,
                start=1,
            )
        ],
        "singularity_ranking": [
            {
                "rank": rank,
                "cve_id": item.cve_id,
                "risk_score": item.risk_score,
                "priority": item.priority,
                "asset_name": item.asset_name,
            }
            for rank, item in enumerate(
                contextual_ranked,
                start=1,
            )
        ],
        "ranking_changes": [
            {
                "cve_id": item.cve_id,
                "cvss_rank": cvss_rank[
                    item.vulnerability_id
                ],
                "singularity_rank": contextual_rank[
                    item.vulnerability_id
                ],
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
    asset_id: int | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    results = RiskEngine(db, current_user.id).analyze()

    matching = [
        result
        for result in results
        if result.vulnerability_id == vulnerability_id
    ]

    if asset_id is not None:
        matching = [
            result
            for result in matching
            if result.asset_id == asset_id
        ]

    item = matching[0] if matching else None

    if item is None:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability priority record not found.",
        )

    paths = AttackGraphEngine(db, current_user.id).analyze().paths

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

    vulnerability = db.scalar(
        select(Vulnerability).where(
            Vulnerability.id == vulnerability_id,
            Vulnerability.user_id == current_user.id,
        )
    )

    return {
        "vulnerability_id": item.vulnerability_id,
        "cve_id": item.cve_id,
        "title": item.title,
        "description": (
            vulnerability.description
            if vulnerability
            else None
        ),
        "remediation": (
            vulnerability.remediation
            if vulnerability
            else None
        ),
        "asset_id": item.asset_id,
        "asset_name": item.asset_name,
        "cvss_score": item.cvss_score,
        "risk_score": item.risk_score,
        "priority": item.priority,
        "cvss_priority": item.cvss_priority,
        "attack_path_count": item.attack_path_count,
        "critical_targets_reached": (
            item.critical_targets_reached
        ),
        "choke_point": item.choke_point,
        "reasons": item.reasons,
        "score_breakdown": item.score_breakdown,
        "attack_paths": relevant_paths,
    }


@router.post(
    "/simulations/patch-impact/{vulnerability_id}"
)
def get_patch_impact(
    vulnerability_id: int,
    asset_id: int | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        result = simulate_patch(
            db,
            vulnerability_id,
            asset_id,
            current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    return {
        "vulnerability_id": result.vulnerability_id,
        "cve_id": result.cve_id,
        "asset_id": asset_id,
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
            "path_reduction_percent": result.path_reduction_percent,
            "critical_path_reduction_percent": result.critical_path_reduction_percent,
            "security_impact": result.security_impact,
        },
    }


