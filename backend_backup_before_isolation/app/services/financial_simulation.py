from app.engines.attack_graph import AttackGraphEngine
from app.models import Asset, AssetVulnerability, Vulnerability
from app.services.financial_risk import FinancialRiskEngine


def calculate_financial_exposure(
    db,
    removed_vulnerability_assets=None,
    removed_relationships=None,
    isolated_assets=None,
):
    removed_vulnerability_assets = (
        removed_vulnerability_assets or set()
    )

    removed_relationships = (
        removed_relationships or set()
    )

    isolated_assets = (
        isolated_assets or set()
    )

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
            AssetVulnerability.status == "ACTIVE",
        )
        .all()
    )

    graph_result = AttackGraphEngine(db).analyze()

    total_eal = 0.0
    contributors = []

    for _, asset, vulnerability in rows:
        mapping_key = (
            vulnerability.id,
            asset.id,
        )

        if mapping_key in removed_vulnerability_assets:
            continue

        base = FinancialRiskEngine.calculate(
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

        likelihood_factor = 1.0

        if asset.id in isolated_assets:
            likelihood_factor *= 0.35

        affected_paths = [
            path
            for path in graph_result.paths
            if (
                vulnerability.cve_id
                in path.vulnerabilities
                and asset.id in path.asset_ids
            )
        ]

        if removed_relationships:
            surviving_paths = []

            for path in affected_paths:
                broken = any(
                    (
                        path.asset_ids[index],
                        path.asset_ids[index + 1],
                    )
                    in removed_relationships
                    for index in range(
                        len(path.asset_ids) - 1
                    )
                )

                if not broken:
                    surviving_paths.append(path)

            if affected_paths:
                reachability = (
                    len(surviving_paths)
                    / len(affected_paths)
                )

                likelihood_factor *= reachability

        adjusted_eal = round(
            base.expected_annual_loss
            * max(
                min(
                    likelihood_factor,
                    1.0,
                ),
                0.0,
            ),
            2,
        )

        total_eal += adjusted_eal

        contributors.append(
            {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "cve_id": vulnerability.cve_id,
                "expected_annual_loss": adjusted_eal,
            }
        )

    contributors.sort(
        key=lambda item: item["expected_annual_loss"],
        reverse=True,
    )

    return {
        "expected_annual_loss": round(
            total_eal,
            2,
        ),
        "contributors": contributors,
    }


