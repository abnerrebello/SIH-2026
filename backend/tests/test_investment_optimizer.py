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

def test_isolate_targets_only_internet_exposed_assets(db):
    from app.models import Asset

    actions = InvestmentOptimizer(
        db
    ).generate_actions()

    internet_ids = {
        asset.id
        for asset in db.query(Asset)
        .filter(Asset.internet_exposed.is_(True))
        .all()
    }

    isolate_actions = [
        action
        for action in actions
        if action.action_type == "ISOLATE"
    ]

    assert isolate_actions

    for action in isolate_actions:
        assert action.asset_id in internet_ids


def test_isolate_action_has_real_graph_impact(db):
    actions = InvestmentOptimizer(
        db
    ).generate_actions()

    isolate_actions = [
        action
        for action in actions
        if action.action_type == "ISOLATE"
    ]

    assert any(
        action.eliminated_paths > 0
        and action.eliminated_critical_paths > 0
        for action in isolate_actions
    )


def test_no_feasible_plan_for_tiny_budget(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=1,
        engineers=3,
        days=14,
    )

    assert result["actions"] == []
    assert result["investment"] == 0.0
    assert result["risk_reduction"] == 0.0


def test_one_engineer_constraint(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=1_000_000,
        engineers=1,
        days=14,
    )

    assert result["engineers_used"] <= 1


def test_short_deadline_constraint(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=1_000_000,
        engineers=10,
        days=1,
    )

    assert result["days_used"] <= 1


def test_high_budget_never_exceeds_constraints(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=10_000_000,
        engineers=10,
        days=30,
    )

    assert result["investment"] <= 10_000_000
    assert result["engineers_used"] <= 10
    assert result["days_used"] <= 30


def test_explainability_fields_are_present(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=100_000,
        engineers=3,
        days=14,
    )

    assert result["actions"]

    for action in result["actions"]:
        assert action["action_label"]
        assert action["selection_reason"]
        assert action["value_per_100000"] >= 0

    for alternative in result["alternatives"]:
        assert alternative["action_label"]
        assert alternative["rejection_reason"]


def test_financial_fields_are_present(db):
    result = InvestmentOptimizer(
        db
    ).optimize(
        budget=100_000,
        engineers=3,
        days=14,
    )

    assert "current_eal" in result
    assert "optimized_eal" in result
    assert "financial_exposure_avoided" in result
    assert "rosi" in result

    assert result["current_eal"] >= 0
    assert result["optimized_eal"] >= 0
    assert result["financial_exposure_avoided"] >= 0
    assert result["rosi"] >= 0


def test_all_supported_action_types_exist(db):
    actions = InvestmentOptimizer(
        db
    ).generate_actions()

    action_types = {
        action.action_type
        for action in actions
    }

    assert "PATCH" in action_types
    assert "SEGMENT" in action_types
    assert "ISOLATE" in action_types
