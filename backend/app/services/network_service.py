from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetRelationship
from app.schemas import RelationshipCreate
from app.services.exceptions import AssetNotFoundError


def list_relationships(db: Session) -> list[AssetRelationship]:
    return db.scalars(
        select(AssetRelationship).order_by(AssetRelationship.id)
    ).all()


def create_relationship(
    db: Session, payload: RelationshipCreate
) -> AssetRelationship:
    if db.get(Asset, payload.source_asset_id) is None:
        raise AssetNotFoundError("Source asset not found.")

    if db.get(Asset, payload.target_asset_id) is None:
        raise AssetNotFoundError("Target asset not found.")

    relationship = AssetRelationship(**payload.model_dump())

    db.add(relationship)
    db.commit()
    db.refresh(relationship)

    return relationship
    