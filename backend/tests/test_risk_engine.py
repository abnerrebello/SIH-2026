from app.engines.risk import RiskEngine


def test_risk_engine_returns_results(db):
    results = RiskEngine(db).analyze()

    assert results
    assert len(results) == 4


def test_risk_scores_are_bounded(db):
    results = RiskEngine(db).analyze()

    for item in results:
        assert 0.0 <= item.risk_score <= 100.0


def test_results_are_sorted_by_risk(db):
    results = RiskEngine(db).analyze()

    scores = [item.risk_score for item in results]

    assert scores == sorted(scores, reverse=True)


def test_cvss_priority_is_present(db):
    results = RiskEngine(db).analyze()

    for item in results:
        assert item.cvss_priority in {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }


def test_contextual_priority_is_present(db):
    results = RiskEngine(db).analyze()

    for item in results:
        assert item.priority in {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }


def test_score_breakdown_exists(db):
    results = RiskEngine(db).analyze()

    for item in results:
        assert item.score_breakdown
        assert "cvss" in item.score_breakdown
        assert "asset_criticality" in item.score_breakdown
        assert "attack_path_impact" in item.score_breakdown