from app.services.investment_optimizer import InvestmentOptimizer


def test_optimizer_returns_a_result(db):
    result = InvestmentOptimizer(db).optimize(
        budget=1_000_000,
        engineers=3,
        days=14,
    )

    assert result
    assert "actions" in result
    assert "optimized_risk" in result
    assert "risk_reduction" in result


def test_budget_constraint_is_respected(db):
    budget = 100_000

    result = InvestmentOptimizer(db).optimize(
        budget=budget,
        engineers=3,
        days=14,
    )

    assert result["investment"] <= budget


def test_engineer_constraint_is_respected(db):
    engineers = 2

    result = InvestmentOptimizer(db).optimize(
        budget=1_000_000,
        engineers=engineers,
        days=14,
    )

    assert result["engineers_used"] <= engineers


def test_time_constraint_is_respected(db):
    days = 3

    result = InvestmentOptimizer(db).optimize(
        budget=1_000_000,
        engineers=5,
        days=days,
    )

    assert result["days_used"] <= days


def test_actions_have_valid_types(db):
    result = InvestmentOptimizer(db).optimize(
        budget=1_000_000,
        engineers=3,
        days=14,
    )

    for action in result["actions"]:
        assert action["action_type"] in {
            "PATCH",
            "SEGMENT",
        }


def test_risk_reduction_is_non_negative(db):
    result = InvestmentOptimizer(db).optimize(
        budget=1_000_000,
        engineers=3,
        days=14,
    )

    assert result["risk_reduction"] >= 0.0
    assert (
        result["optimized_risk"]
        <= result["current_risk"]
    )


def test_segmentation_candidates_are_generated(db):
    actions = InvestmentOptimizer(
        db
    ).generate_actions()

    segmentation_actions = [
        action
        for action in actions
        if action.action_type == "SEGMENT"
    ]

    assert segmentation_actions

    for action in segmentation_actions:
        assert action.source_asset_id is not None
        assert action.target_asset_id is not None
        assert action.eliminated_paths > 0
        assert action.estimated_cost > 0
