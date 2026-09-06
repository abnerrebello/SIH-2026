from __future__ import annotations

def action_type_label(action_type: str) -> str:
    return {
        "PATCH": "PATCH",
        "SEGMENT": "SEGMENT",
        "ISOLATE": "REDUCE EXPOSURE",
    }.get(action_type, action_type)


def selected_reason(action) -> str:
    label = action_type_label(action.action_type)

    return (
        f"{label} was selected because it removes "
        f"{action.eliminated_paths} attack path(s), including "
        f"{action.eliminated_critical_paths} critical path(s), "
        f"for an estimated investment of "
        f"₹{action.estimated_cost:,.0f}."
    )


def rejected_reason(
    action,
    selected_actions,
) -> str:
    if not selected_actions:
        return (
            "Not selected because no feasible portfolio "
            "containing this action improved the objective."
        )

    best_selected_value = max(
        item.value_per_1000
        for item in selected_actions
    )

    if action.value_per_1000 < best_selected_value:
        return (
            f"Not selected because its value of "
            f"{action.value_per_1000:.2f} per ₹1K was lower "
            f"than the selected portfolio."
        )

    return (
        "Not selected because adding this action did not "
        "produce a lower residual risk under the current "
        "budget, staffing, and time constraints."
    )

