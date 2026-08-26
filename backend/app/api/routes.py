from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.engines.attack_graph import AttackGraphEngine
from app.models import Asset, AssetRelationship, Vulnerability
from app.schemas import (
    AssetCreate,
    AssetResponse,
    RelationshipCreate,
    RelationshipResponse,
    VulnerabilityCreate,
    VulnerabilityResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Security Data"])


@router.get("/assets", response_model=list[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    return db.scalars(select(Asset).order_by(Asset.id)).all()


@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    existing = db.scalar(select(Asset).where(Asset.name == payload.name))

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Asset name already exists.",
        )

    asset = Asset(**payload.model_dump())

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilityResponse],
)
def list_vulnerabilities(db: Session = Depends(get_db)):
    return db.scalars(
        select(Vulnerability).order_by(
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
    db: Session = Depends(get_db),
):
    existing = db.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id == payload.cve_id
        )
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="CVE already exists.",
        )

    vulnerability = Vulnerability(**payload.model_dump())

    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    return vulnerability


@router.get(
    "/network",
    response_model=list[RelationshipResponse],
)
def list_network_relationships(
    db: Session = Depends(get_db),
):
    return db.scalars(
        select(AssetRelationship).order_by(
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
    db: Session = Depends(get_db),
):
    if db.get(Asset, payload.source_asset_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Source asset not found.",
        )

    if db.get(Asset, payload.target_asset_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Target asset not found.",
        )

    relationship = AssetRelationship(
        **payload.model_dump()
    )

    db.add(relationship)
    db.commit()
    db.refresh(relationship)

    return relationship


@router.get("/attack-paths")
def get_attack_paths(
    db: Session = Depends(get_db),
):
    engine = AttackGraphEngine(db)
    result = engine.analyze()

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
    db: Session = Depends(get_db),
):
    engine = AttackGraphEngine(db)
    result = engine.analyze()

    return {
        "nodes": result.nodes,
        "edges": result.edges,
        "choke_points": result.choke_points,
    }