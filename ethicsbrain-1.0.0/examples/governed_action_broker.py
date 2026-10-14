"""Local demo of the action broker with a harmless in-memory document search.

No external tool is called. Sensitive actions remain pending because this demo does not
configure an authenticated human-approval service.
"""
from ethicsbrain import ActionBroker, ActionRequest, Policy

DOCUMENTS = {
    "retention": "The example policy retains synthetic demo records for 30 days.",
    "security": "The example policy says access must be limited to authorized reviewers.",
}


def search_docs(arguments: dict[str, object]) -> list[str]:
    query = str(arguments.get("query", "")).lower()
    return [text for key, text in DOCUMENTS.items() if query in key or query in text.lower()]


policy = Policy(allowed_actions={"search_docs", "send_email"}, grounding_mode="off")
broker = ActionBroker(policy, proposal_ttl_seconds=60)
broker.register(
    "search_docs",
    search_docs,
    validate_arguments=lambda args: isinstance(args.get("query"), str) and 0 < len(args["query"]) <= 100,
)
# Registered to demonstrate that a risky action can be proposed, but not approved by this demo.
broker.register("send_email", lambda args: {"queued": True}, validate_arguments=lambda args: False)

safe_proposal = broker.propose(ActionRequest("search_docs", {"query": "retention"}))
print("Safe proposal:", safe_proposal.to_dict())
if safe_proposal.status == "ready":
    print("Search result:", broker.execute(safe_proposal.proposal_id))

risky_proposal = broker.propose(ActionRequest(
    "send_email", {"to": "someone@example.test", "subject": "Demo", "body": "Not sent"},
))
print("Risky proposal (no real approval configured):", risky_proposal.to_dict())
print("The demo intentionally does not execute it. Integrate your authenticated approval service first.")
