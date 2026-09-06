from sqlalchemy import select

from app.core.database import Base, SessionLocal, engine
from app.models import (
    Asset,
    AssetCriticality,
    AssetRelationship,
    AssetVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
)


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        if db.scalar(select(Asset.id).limit(1)) is not None:
            return

        internet = Asset(
            name="Internet Gateway",
            hostname="gateway.aegis.local",
            ip_address="203.0.113.10",
            asset_type="NETWORK_GATEWAY",
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
            description="External entry point.",
        )

        web = Asset(
            name="Public Web Server",
            hostname="web01.aegis.local",
            ip_address="10.10.10.10",
            asset_type="WEB_SERVER",
            operating_system="Ubuntu Server 24.04",
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
        )

        app = Asset(
            name="Application Server",
            hostname="app01.aegis.local",
            ip_address="10.10.20.10",
            asset_type="APPLICATION_SERVER",
            operating_system="Ubuntu Server 24.04",
            criticality=AssetCriticality.HIGH,
        )

        employee = Asset(
            name="Finance Workstation",
            hostname="fin-pc01.aegis.local",
            ip_address="10.10.30.21",
            asset_type="ENDPOINT",
            operating_system="Windows 11",
            criticality=AssetCriticality.MEDIUM,
        )

        database = Asset(
            name="Production Database",
            hostname="db01.aegis.local",
            ip_address="10.10.40.10",
            asset_type="DATABASE",
            operating_system="Ubuntu Server 24.04",
            criticality=AssetCriticality.CRITICAL,
        )

        dc = Asset(
            name="Domain Controller",
            hostname="dc01.aegis.local",
            ip_address="10.10.50.10",
            asset_type="IDENTITY_SERVER",
            operating_system="Windows Server 2025",
            criticality=AssetCriticality.CRITICAL,
        )

        db.add_all([internet, web, app, employee, database, dc])
        db.flush()

        v1 = Vulnerability(
            cve_id="CVE-DEMO-001",
            title="Remote Code Execution in Public Web Service",
            description="Demonstration internet-facing RCE weakness.",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            exploitability_score=3.9,
            actively_exploited=True,
            known_exploit=True,
            remediation="Patch the web service and restrict external exposure.",
        )

        v2 = Vulnerability(
            cve_id="CVE-DEMO-002",
            title="Privilege Escalation in Application Server",
            description="Demonstration privilege escalation weakness.",
            cvss_score=8.8,
            severity=VulnerabilitySeverity.HIGH,
            exploitability_score=3.1,
            known_exploit=True,
            remediation="Apply security updates and restrict privileged accounts.",
        )

        v3 = Vulnerability(
            cve_id="CVE-DEMO-003",
            title="Database Authentication Weakness",
            description="Demonstration database authentication weakness.",
            cvss_score=7.5,
            severity=VulnerabilitySeverity.HIGH,
            exploitability_score=2.4,
            remediation="Harden authentication and apply the security patch.",
        )

        v4 = Vulnerability(
            cve_id="CVE-DEMO-004",
            title="Endpoint Credential Exposure",
            description="Demonstration endpoint credential weakness.",
            cvss_score=6.8,
            severity=VulnerabilitySeverity.MEDIUM,
            exploitability_score=2.1,
            remediation="Patch endpoint software and enforce credential protection.",
        )

        db.add_all([v1, v2, v3, v4])
        db.flush()

        db.add_all([
            AssetVulnerability(asset_id=web.id, vulnerability_id=v1.id),
            AssetVulnerability(asset_id=app.id, vulnerability_id=v2.id),
            AssetVulnerability(asset_id=database.id, vulnerability_id=v3.id),
            AssetVulnerability(asset_id=employee.id, vulnerability_id=v4.id),
        ])

        db.add_all([
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
            AssetRelationship(
                source_asset_id=employee.id,
                target_asset_id=app.id,
                relationship_type="APPLICATION_ACCESS",
                trust_level="MEDIUM",
            ),
            AssetRelationship(
                source_asset_id=app.id,
                target_asset_id=dc.id,
                relationship_type="IDENTITY_ACCESS",
                trust_level="HIGH",
            ),
        ])

        db.commit()
