"""Example of adding app-specific checks; this is illustrative, not a fairness detector."""
from ethicsbrain import Finding, GuardrailBrain, ModelRequest, Policy


def review_high_impact_decision(text: str, context: dict[str, str]) -> list[Finding]:
    # In a real deployment, connect a validated domain-specific evaluator or
    # route applicable decisions to a human-review queue. This keyword example
    # only demonstrates the extension API and is not semantically reliable.
    indicators = ("hire this candidate", "reject this applicant", "deny this patient")
    if any(term in text.lower() for term in indicators):
        return [Finding(
            rule_id="demo_high_impact_review",
            category="human_oversight",
            severity="high",
            message="Potential high-impact decision language requires domain review.",
        )]
    return []


def model(request: ModelRequest) -> str:
    return "We should hire this candidate based on this summary."


brain = GuardrailBrain(Policy(grounding_mode="off"), output_checks=[review_high_impact_decision])
result = brain.run("Summarize candidate", model)
print(result.ok)  # False: custom high-impact review finding blocks output.
print(result.report.to_dict())
