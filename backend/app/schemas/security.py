from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import AssetCriticality, VulnerabilitySeverity


class AssetCreate(BaseModel):
    name: str
    hostname: str | None = None
    ip_address: str | None = None
    asset_type: str
    operating_system: str | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    internet_exposed: bool = False
    description: str | None = None


class AssetResponse(AssetCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class VulnerabilityCreate(BaseModel):
    cve_id: str
    title: str
    description: str | None = None
    cvss_score: float
    severity: VulnerabilitySeverity
    exploitability_score: float | None = None
    actively_exploited: bool = False
    known_exploit: bool = False
    remediation: str | None = None


class VulnerabilityResponse(VulnerabilityCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class RelationshipCreate(BaseModel):
    source_asset_id: int
    target_asset_id: int
    relationship_type: str = "NETWORK_ACCESS"
    trust_level: str = "MEDIUM"


class RelationshipResponse(RelationshipCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
