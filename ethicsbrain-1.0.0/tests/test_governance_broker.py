from __future__ import annotations

import unittest
import threading

from ethicsbrain import ActionBroker, ActionGovernanceError, ActionRequest, Policy


class ActionBrokerTests(unittest.TestCase):
    def test_action_must_be_allowlisted_to_register(self):
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        with self.assertRaises(ValueError):
            broker.register("delete_database", lambda args: "deleted")

    def test_safe_action_executes_once(self):
        calls = []
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", lambda args: calls.append(args["query"]) or "found")
        proposal = broker.propose(ActionRequest("read_docs", {"query": "policy"}))
        self.assertEqual(proposal.status, "ready")
        self.assertEqual(broker.execute(proposal.proposal_id), "found")
        self.assertEqual(calls, ["policy"])
        self.assertEqual(broker.get_proposal(proposal.proposal_id)["status"], "executed")
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)
        self.assertEqual(calls, ["policy"])

    def test_sensitive_action_requires_authenticated_human_approval(self):
        calls = []
        policy = Policy(allowed_actions={"send_email"})
        broker = ActionBroker(policy, approval_authorizer=lambda identity, action, proof: identity == "reviewer" and proof == "valid")
        broker.register("send_email", lambda args: calls.append(args) or "sent")
        proposal = broker.propose(ActionRequest("send_email", {"to": "person@example.test"}))
        self.assertEqual(proposal.status, "awaiting_approval")
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)
        with self.assertRaises(ActionGovernanceError):
            broker.approve(proposal.proposal_id, approver_id="attacker", proof="invalid")
        approved = broker.approve(proposal.proposal_id, approver_id="reviewer", proof="valid")
        self.assertEqual(approved.status, "approved")
        self.assertEqual(broker.execute(proposal.proposal_id), "sent")
        self.assertEqual(len(calls), 1)

    def test_sensitive_action_cannot_be_approved_without_authenticator(self):
        broker = ActionBroker(Policy(allowed_actions={"send_email"}))
        broker.register("send_email", lambda args: None)
        proposal = broker.propose(ActionRequest("send_email", {"to": "person@example.test"}))
        with self.assertRaises(ActionGovernanceError):
            broker.approve(proposal.proposal_id, approver_id="admin")

    def test_denylisted_action_cannot_register(self):
        broker = ActionBroker(Policy(allowed_actions={"deploy_ransomware"}))
        with self.assertRaises(ValueError):
            broker.register("deploy_ransomware", lambda args: None)

    def test_argument_validation_fails_closed(self):
        called = []
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", lambda args: called.append(args), validate_arguments=lambda args: isinstance(args.get("limit"), int) and args["limit"] <= 20)
        proposal = broker.propose(ActionRequest("read_docs", {"limit": 100}))
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)
        self.assertEqual(called, [])

    def test_expired_proposal_cannot_execute(self):
        now = [100.0]
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}), proposal_ttl_seconds=5, clock=lambda: now[0])
        broker.register("read_docs", lambda args: "should not run")
        proposal = broker.propose(ActionRequest("read_docs", {}))
        now[0] = 106.0
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)
        self.assertEqual(broker.get_proposal(proposal.proposal_id)["status"], "expired")

    def test_handler_exception_is_sanitized_and_not_replayed(self):
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", lambda args: (_ for _ in ()).throw(RuntimeError("secret internal failure")))
        proposal = broker.propose(ActionRequest("read_docs", {}))
        with self.assertRaisesRegex(Exception, "authorized action handler failed") as ctx:
            broker.execute(proposal.proposal_id)
        self.assertNotIn("secret internal failure", str(ctx.exception))
        self.assertEqual(broker.get_proposal(proposal.proposal_id)["status"], "failed")
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)

    def test_concurrent_execute_calls_cannot_run_handler_twice(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def handler(_args):
            calls.append(1)
            entered.set()
            if not release.wait(timeout=2):
                raise RuntimeError("test handler timed out")
            return "done"

        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", handler)
        proposal = broker.propose(ActionRequest("read_docs", {}))
        result = []
        thread = threading.Thread(target=lambda: result.append(broker.execute(proposal.proposal_id)))
        thread.start()
        self.assertTrue(entered.wait(timeout=2))
        with self.assertRaises(ActionGovernanceError):
            broker.execute(proposal.proposal_id)
        release.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, ["done"])
        self.assertEqual(len(calls), 1)

    def test_proposal_metadata_never_includes_action_arguments(self):
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", lambda args: None)
        proposal = broker.propose(ActionRequest("read_docs", {"token": "secret-value"}))
        self.assertNotIn("secret-value", str(broker.get_proposal(proposal.proposal_id)))

    def test_returned_proposal_snapshot_cannot_change_broker_state(self):
        from dataclasses import FrozenInstanceError
        broker = ActionBroker(Policy(allowed_actions={"read_docs"}))
        broker.register("read_docs", lambda args: "ran")
        proposal = broker.propose(ActionRequest("read_docs", {}))
        with self.assertRaises(FrozenInstanceError):
            proposal.status = "approved"
        proposal.decision.allowed = False  # Nested view is copied and cannot mutate broker state.
        self.assertEqual(broker.execute(proposal.proposal_id), "ran")


if __name__ == "__main__":
    unittest.main()
