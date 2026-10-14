"""Run the optional local NLI claim-verification component.

Install with: python -m pip install -e '.[nli]'
The first run downloads the model checkpoint unless it is already cached locally.
"""
from ethicsbrain import GuardrailBrain, Policy, make_verification_check, verify_response
from ethicsbrain.nli import TransformersNliEvaluator


def main() -> None:
    evaluator = TransformersNliEvaluator(device=-1)
    evidence = {
        "E1": "Sensitive tool actions require independent authorization outside the language model. The authorization layer validates permissions before execution.",
    }
    response = "Sensitive tool actions require independent authorization [E1]."

    report = verify_response(response, evidence, evaluator, minimum_confidence=0.75)
    print("Verification report:")
    print(report.to_dict())

    # Attach the verifier to the output path of the usual middleware.
    brain = GuardrailBrain(
        Policy(grounding_mode="off"),
        output_checks=[make_verification_check(evaluator, minimum_confidence=0.75)],
    )
    result = brain.run(
        "Answer using the provided evidence.",
        lambda request: response,
        context=evidence,
    )
    print("Guardrail result:")
    print(result.report.to_dict())
    if not result.ok:
        print("Response withheld: the evidence verifier did not pass.")
    else:
        print("Verified response:", result.text)


if __name__ == "__main__":
    main()
