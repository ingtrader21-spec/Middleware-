from typing import Any


def safe_ratio(numerator: float | int, denominator: float | int) -> float:
    return round(float(numerator) / float(denominator), 6) if denominator else 0.0


def calculate_kpis(values: dict[str, Any]) -> dict[str, float]:
    dialed = values.get("dialed_calls", 0)
    answered = values.get("answered_calls", 0)
    contacts = values.get("human_contacts", 0)
    sales = values.get("sales", 0)
    due = values.get("callbacks_due", 0)
    completed = values.get("callbacks_completed", 0)
    on_time = values.get("callbacks_completed_on_time", 0)
    successful = values.get("successful_executions", 0)
    executions = values.get("completed_executions", 0)
    handled = values.get("calls_handled", 0)
    return {
        "answer_rate": safe_ratio(answered, dialed),
        "contact_rate": safe_ratio(contacts, dialed),
        "answered_conversion_rate": safe_ratio(sales, answered),
        "contact_conversion_rate": safe_ratio(sales, contacts),
        "callback_completion_rate": safe_ratio(completed, due),
        "callback_sla_rate": safe_ratio(on_time, due),
        "average_handle_time": safe_ratio(
            values.get("talk_seconds", 0)
            + values.get("hold_seconds", 0)
            + values.get("wrap_seconds", 0),
            handled,
        ),
        "automation_success_rate": safe_ratio(successful, executions),
    }
