"""Run with: python examples/basic_usage.py (from repository root)."""
from ethicsbrain import GuardrailBrain, Policy, ModelRequest


def demo_model(request: ModelRequest) -> str:
    """Replace this function with a local or hosted model adapter."""
    evidence = request.context.get("E1", "")
    return f"The supplied source says: {evidence.rstrip('. ')} [E1]."


policy = Policy(
    grounding_mode="strict",
    allowed_actions={"search_docs", "read_dashboard", "send_email"},
)
brain = GuardrailBrain(policy=policy, audit_log_path="artifacts/ethicsbrain-audit.jsonl")
result = brain.run(
    "Summarize the provided source in one sentence.",
    demo_model,
    context={"E1": "The sample project uses a provider-neutral model adapter."},
)

print("OK:", result.ok)
print("TEXT:", result.text)
print("REPORT:", result.report.to_dict())

# Proposed actions are only checked, never executed by the library.
from ethicsbrain import ActionRequest

action = brain.authorize_action(ActionRequest("send_email", {"to": "user@example.test"}))
print("ACTION:", action.to_dict())
