from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset
from app.schemas import AssetCreate
from app.services.exceptions import DuplicateAssetError


def list_assets(db: Session) -> list[Asset]:
    return db.scalars(select(Asset).order_by(Asset.id)).all()


def create_asset(db: Session, payload: AssetCreate) -> Asset:
    existing = db.scalar(select(Asset).where(Asset.name == payload.name))

    if existing:
        raise DuplicateAssetError("Asset name already exists.")

    asset = Asset(**payload.model_dump())

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset