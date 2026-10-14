"""Illustrate allowlisting and approval for tools with side effects."""
from ethicsbrain import ActionRequest, GuardrailBrain, Policy

brain = GuardrailBrain(Policy(allowed_actions={"search_docs", "send_email"}))

read_only = brain.authorize_action(ActionRequest("search_docs", {"query": "policy manual"}))
assert read_only.allowed

email = ActionRequest("send_email", {"to": "person@example.test", "body": "Draft only"})
first_check = brain.authorize_action(email)
assert not first_check.allowed and first_check.requires_approval

# The host application must obtain real user approval and then set this flag.
# Never set approved_by_human=True merely because the model requested it.
second_check = brain.authorize_action(email, approved_by_human=True)
assert second_check.allowed
print("Tool action gate examples passed.")
