import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import (
    Asset,
    AssetCriticality,
    AssetRelationship,
    AssetVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
)


@pytest.fixture
def db():
    from sqlalchemy import create_engine

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        internet = Asset(
            name="Internet Gateway",
            hostname="gateway.test",
            ip_address="203.0.113.10",
            asset_type="NETWORK_GATEWAY",
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
        )

        web = Asset(
            name="Public Web Server",
            hostname="web.test",
            ip_address="10.10.10.10",
            asset_type="WEB_SERVER",
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
        )

        app = Asset(
            name="Application Server",
            hostname="app.test",
            ip_address="10.10.20.10",
            asset_type="APPLICATION_SERVER",
            criticality=AssetCriticality.HIGH,
        )

        database = Asset(
            name="Production Database",
            hostname="db.test",
            ip_address="10.10.40.10",
            asset_type="DATABASE",
            criticality=AssetCriticality.CRITICAL,
        )

        session.add_all([
            internet,
            web,
            app,
            database,
        ])

        session.flush()

        v1 = Vulnerability(
            cve_id="TEST-001",
            title="Test RCE",
            description="Test vulnerability",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            exploitability_score=3.9,
            actively_exploited=True,
            known_exploit=True,
        )

        v2 = Vulnerability(
            cve_id="TEST-002",
            title="Test Privilege Escalation",
            description="Test vulnerability",
            cvss_score=8.8,
            severity=VulnerabilitySeverity.HIGH,
            exploitability_score=3.1,
            known_exploit=True,
        )

        v3 = Vulnerability(
            cve_id="TEST-003",
            title="Test Database Weakness",
            description="Test vulnerability",
            cvss_score=7.5,
            severity=VulnerabilitySeverity.HIGH,
            exploitability_score=2.4,
        )

        v4 = Vulnerability(
            cve_id="TEST-004",
            title="Test Endpoint Weakness",
            description="Test vulnerability",
            cvss_score=6.8,
            severity=VulnerabilitySeverity.MEDIUM,
            exploitability_score=2.1,
        )

        session.add_all([v1, v2, v3, v4])
        session.flush()

        session.add_all([
            AssetVulnerability(
                asset_id=web.id,
                vulnerability_id=v1.id,
            ),
            AssetVulnerability(
                asset_id=app.id,
                vulnerability_id=v2.id,
            ),
            AssetVulnerability(
                asset_id=database.id,
                vulnerability_id=v3.id,
            ),
            AssetVulnerability(
                asset_id=web.id,
                vulnerability_id=v4.id,
            ),
        ])

        session.add_all([
            AssetRelationship(
                source_asset_id=internet.id,
                target_asset_id=web.id,
                relationship_type="NETWORK_ACCESS",
                trust_level="LOW",
            ),
            AssetRelationship(
                source_asset_id=web.id,
                target_asset_id=app.id,
                relationship_type="LATERAL_MOVEMENT",
                trust_level="MEDIUM",
            ),
            AssetRelationship(
                source_asset_id=app.id,
                target_asset_id=database.id,
                relationship_type="DATABASE_ACCESS",
                trust_level="HIGH",
            ),
        ])

        session.commit()

        yield session

    Base.metadata.drop_all(engine)
