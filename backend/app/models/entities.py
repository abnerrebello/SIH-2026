from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilitySeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(150))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    asset_type: Mapped[str] = mapped_column(String(80), nullable=False)
    operating_system: Mapped[str | None] = mapped_column(String(100))
    criticality: Mapped[AssetCriticality] = mapped_column(
        SAEnum(AssetCriticality),
        default=AssetCriticality.MEDIUM,
        nullable=False,
    )
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    vulnerabilities = relationship(
        "AssetVulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    outgoing_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan",
    )

    incoming_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[VulnerabilitySeverity] = mapped_column(
        SAEnum(VulnerabilitySeverity),
        nullable=False,
    )
    exploitability_score: Mapped[float | None] = mapped_column(Float)
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    known_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    assets = relationship(
        "AssetVulnerability",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(30), default="OPEN")

    asset = relationship("Asset", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="assets")


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(50), default="NETWORK_ACCESS")
    trust_level: Mapped[str] = mapped_column(String(30), default="MEDIUM")

    source_asset = relationship(
        "Asset",
        foreign_keys=[source_asset_id],
        back_populates="outgoing_relationships",
    )

    target_asset = relationship(
        "Asset",
        foreign_keys=[target_asset_id],
        back_populates="incoming_relationships",
    )
