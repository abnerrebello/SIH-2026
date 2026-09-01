from dataclasses import dataclass


@dataclass(frozen=True)
class FinancialRiskResult:
    asset_id: int
    asset_name: str
    annual_incident_probability: float
    single_loss_expectancy: float
    expected_annual_loss: float
    impact_multiplier: float
    likelihood_multiplier: float


class FinancialRiskEngine:
    BASE_LOSS = {
        "LOW": 1_000_000.0,
        "MEDIUM": 5_000_000.0,
        "HIGH": 15_000_000.0,
        "CRITICAL": 35_000_000.0,
    }

    ASSET_TYPE_MULTIPLIER = {
        "DATABASE": 1.35,
        "APPLICATION_SERVER": 1.20,
        "WEB_SERVER": 1.10,
        "NETWORK_GATEWAY": 1.05,
        "WORKSTATION": 0.60,
    }

    @classmethod
    def impact_multiplier(cls, criticality, asset_type, internet_exposed):
        criticality_factor = {
            "LOW": 0.7,
            "MEDIUM": 1.0,
            "HIGH": 1.35,
            "CRITICAL": 1.7,
        }.get(criticality, 1.0)

        asset_factor = cls.ASSET_TYPE_MULTIPLIER.get(
            asset_type, 1.0
        )

        exposure_factor = 1.15 if internet_exposed else 1.0

        return round(
            criticality_factor
            * asset_factor
            * exposure_factor,
            3,
        )

    @staticmethod
    def likelihood_multiplier(
        *,
        cvss,
        epss,
        actively_exploited,
        known_exploit,
        kev_status,
        internet_exposed,
    ):
        score = 0.10

        score += (
            max(min(cvss, 10.0), 0.0)
            / 10.0
            * 0.25
        )

        if epss is not None:
            score += max(min(epss, 1.0), 0.0) * 0.30

        if actively_exploited:
            score += 0.15

        if known_exploit:
            score += 0.08

        if kev_status:
            score += 0.12

        if internet_exposed:
            score += 0.10

        return min(round(score, 4), 0.99)

    @classmethod
    def calculate(
        cls,
        *,
        asset_id,
        asset_name,
        criticality,
        asset_type,
        internet_exposed,
        cvss,
        epss,
        actively_exploited,
        known_exploit,
        kev_status,
    ):
        impact = cls.impact_multiplier(
            criticality,
            asset_type,
            internet_exposed,
        )

        likelihood = cls.likelihood_multiplier(
            cvss=cvss,
            epss=epss,
            actively_exploited=actively_exploited,
            known_exploit=known_exploit,
            kev_status=kev_status,
            internet_exposed=internet_exposed,
        )

        base_loss = cls.BASE_LOSS.get(
            criticality,
            cls.BASE_LOSS["MEDIUM"],
        )

        single_loss = round(
            base_loss * impact,
            2,
        )

        expected_annual_loss = round(
            likelihood * single_loss,
            2,
        )

        return FinancialRiskResult(
            asset_id=asset_id,
            asset_name=asset_name,
            annual_incident_probability=likelihood,
            single_loss_expectancy=single_loss,
            expected_annual_loss=expected_annual_loss,
            impact_multiplier=impact,
            likelihood_multiplier=likelihood,
        )

