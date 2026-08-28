def cvss_priority(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def contextual_priority(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    return "LOW"


def criticality_points(criticality: str) -> float:
    return {
        "LOW": 5.0,
        "MEDIUM": 12.0,
        "HIGH": 18.0,
        "CRITICAL": 25.0,
    }.get(criticality, 10.0)


def cvss_points(cvss: float) -> float:
    return min(max(cvss, 0.0), 10.0) * 3.0


def exploitability_points(score: float | None) -> float:
    if score is None:
        return 0.0

    normalized = min(max(score, 0.0), 4.0) / 4.0
    return normalized * 12.0


def build_score_breakdown(
    *,
    cvss_score: float,
    exploitability_score: float | None,
    asset_criticality: str,
    internet_exposed: bool,
    actively_exploited: bool,
    known_exploit: bool,
    attack_path_count: int,
    critical_targets_reached: int,
    choke_point: bool,
) -> dict[str, float]:
    return {
        "cvss": cvss_points(cvss_score),
        "exploitability": exploitability_points(
            exploitability_score
        ),
        "asset_criticality": criticality_points(
            asset_criticality
        ),
        "internet_exposure": (
            12.0 if internet_exposed else 0.0
        ),
        "active_exploitation": (
            15.0 if actively_exploited else 0.0
        ),
        "known_exploit": (
            8.0 if known_exploit else 0.0
        ),
        "attack_path_impact": min(
            attack_path_count * 4.0,
            12.0,
        ),
        "critical_target_impact": min(
            critical_targets_reached * 7.0,
            14.0,
        ),
        "choke_point": (
            8.0 if choke_point else 0.0
        ),
    }


def build_reasons(
    *,
    cvss_score: float,
    exploitability_score: float | None,
    asset_criticality: str,
    internet_exposed: bool,
    actively_exploited: bool,
    known_exploit: bool,
    attack_path_count: int,
    critical_targets_reached: int,
    choke_point: bool,
) -> list[str]:
    reasons: list[str] = []

    if cvss_score >= 9.0:
        reasons.append(
            f"Very high CVSS score ({cvss_score:.1f})"
        )
    elif cvss_score >= 7.0:
        reasons.append(
            f"High CVSS score ({cvss_score:.1f})"
        )

    if exploitability_score is not None:
        if exploitability_score >= 3.0:
            reasons.append("High exploitability")

    if asset_criticality in {"HIGH", "CRITICAL"}:
        reasons.append(
            f"{asset_criticality} asset"
        )

    if internet_exposed:
        reasons.append("Internet-facing asset")

    if actively_exploited:
        reasons.append(
            "Active exploitation reported"
        )

    if known_exploit:
        reasons.append(
            "Known exploit available"
        )

    if attack_path_count:
        reasons.append(
            f"Present on {attack_path_count} attack path(s)"
        )

    if critical_targets_reached:
        reasons.append(
            "Can contribute to reaching "
            f"{critical_targets_reached} critical asset(s)"
        )

    if choke_point:
        reasons.append(
            "Located at an attack-path choke point"
        )

    return reasons
