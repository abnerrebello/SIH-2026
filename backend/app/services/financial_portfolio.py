from app.core.database import SessionLocal
from app.models import Asset, AssetVulnerability, Vulnerability
from app.services.financial_risk import FinancialRiskEngine


def calculate_portfolio_eal(db):
    rows = (
        db.query(
            AssetVulnerability,
            Asset,
            Vulnerability,
        )
        .join(
            Asset,
            Asset.id == AssetVulnerability.asset_id,
        )
        .join(
            Vulnerability,
            Vulnerability.id
            == AssetVulnerability.vulnerability_id,
        )
        .filter(
            AssetVulnerability.status == "OPEN",
        )
        .all()
    )

    total = 0.0
    contributors = []

    for _, asset, vulnerability in rows:
        result = FinancialRiskEngine.calculate(
            asset_id=asset.id,
            asset_name=asset.name,
            criticality=asset.criticality.value,
            asset_type=asset.asset_type,
            internet_exposed=asset.internet_exposed,
            cvss=vulnerability.cvss_score,
            epss=vulnerability.epss_score,
            actively_exploited=vulnerability.actively_exploited,
            known_exploit=vulnerability.known_exploit,
            kev_status=getattr(
                vulnerability,
                "kev_status",
                False,
            ),
        )

        total += result.expected_annual_loss

        contributors.append(
            {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "cve_id": vulnerability.cve_id,
                "expected_annual_loss": result.expected_annual_loss,
            }
        )

    contributors.sort(
        key=lambda item: item["expected_annual_loss"],
        reverse=True,
    )

    return {
        "expected_annual_loss": round(total, 2),
        "contributors": contributors,
    }

