import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.service import Service
from src.rules import STATES


class SignoffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "signoff item", "description": "versioned closure",
             "severity": "high", "quantity": 5, "threshold": 10},
            "creator", "field_commander")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _advance_to_controlled(self, item_id, actor, role):
        item = self.service.get_item(item_id, "viewer")
        version = item["version"]
        for target in STATES[1:-1]:
            item = self.service.transition(item_id, target, version, actor, role)
            version = item["version"]
        return version

    def test_observation_versions_and_expires_signoff(self):
        item_id = self.item["id"]
        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "北风3级"},
                                     "obs", "field_commander")
        signoff = self.service.create_signoff(item_id, "cmdr", "incident_commander")
        self.assertEqual(signoff["observation_version"], 1)
        self.assertEqual(signoff["status"], "valid")

        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "转南风4级"},
                                     "obs", "field_commander")
        current = self.service.current_signoff(item_id, "viewer")
        self.assertFalse(current["valid"])
        self.assertIn("观察版本已从 v1 变更为 v2", current["reason"])

    def test_close_with_stale_signoff_is_rejected_then_reconfirmed(self):
        item_id = self.item["id"]
        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "北风3级"},
                                     "obs", "field_commander")
        self.service.create_signoff(item_id, "cmdr", "incident_commander")
        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "转南风4级"},
                                     "obs", "field_commander")
        version = self._advance_to_controlled(item_id, "cmdr", "incident_commander")

        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(item_id, STATES[-1], version, "cmdr", "incident_commander")
        self.assertIn("重新确认", str(ctx.exception))

        self.service.create_signoff(item_id, "cmdr", "incident_commander")
        closed = self.service.transition(item_id, STATES[-1], version, "cmdr", "incident_commander")
        self.assertEqual(closed["status"], STATES[-1])
        current = self.service.current_signoff(item_id, "viewer")
        self.assertFalse(current["valid"])
        self.assertIn("已消耗", current["reason"])

    def test_handover_window_rejects_old_party_and_authorizes_new(self):
        item_id = self.item["id"]
        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "东风2级"},
                                     "obs", "field_commander")
        self.service.create_signoff(item_id, "zhang", "incident_commander")
        self.service.add_handover(
            item_id, {"to_actor": "li", "to_role": "incident_commander", "reason": "夜班交接"},
            "zhang", "incident_commander")

        current = self.service.current_signoff(item_id, "viewer")
        self.assertFalse(current["valid"])
        self.assertIn("交接窗口已从 w0 变更为 w1", current["reason"])

        with self.assertRaises(PermissionDenied) as ctx:
            self.service.create_signoff(item_id, "zhang", "incident_commander")
        self.assertIn("越权", str(ctx.exception))

        signoff = self.service.create_signoff(item_id, "li", "incident_commander")
        self.assertEqual(signoff["handover_window"], 1)
        self.assertEqual(signoff["signer_actor"], "li")

    def test_outside_window_close_is_rejected(self):
        item_id = self.item["id"]
        self.service.add_handover(
            item_id, {"to_actor": "li", "to_role": "incident_commander"},
            "zhang", "incident_commander")
        version = self._advance_to_controlled(item_id, "li", "incident_commander")
        with self.assertRaises(PermissionDenied):
            self.service.transition(item_id, STATES[-1], version, "zhang", "incident_commander")

    def test_fresh_item_implicit_confirmation_still_closes(self):
        item_id = self.item["id"]
        version = self._advance_to_controlled(item_id, "cmdr", "incident_commander")
        closed = self.service.transition(item_id, STATES[-1], version, "cmdr", "incident_commander")
        self.assertEqual(closed["status"], STATES[-1])

    def test_audit_records_both_parties_and_every_step_in_order(self):
        item_id = self.item["id"]
        self.service.add_observation(item_id, {"kind": "wind_direction", "detail": "北风"},
                                     "obs", "field_commander")
        self.service.create_signoff(item_id, "zhang", "incident_commander")
        self.service.add_handover(
            item_id, {"to_actor": "li", "to_role": "incident_commander", "reason": "交班"},
            "zhang", "incident_commander")
        self.service.create_signoff(item_id, "li", "incident_commander")

        events = self.service.audit("viewer", item_id)
        self.assertTrue(self.repo.verify_audit_chain())
        actions = [e["action"] for e in events]
        self.assertIn("observation", actions)
        self.assertIn("signoff", actions)
        self.assertIn("handover", actions)
        # handover event must carry both parties
        handover = next(e for e in events if e["action"] == "handover")
        self.assertEqual(handover["detail"]["from_actor"], "zhang")
        self.assertEqual(handover["detail"]["to_actor"], "li")
        # chain order is monotonic
        ids = [e["id"] for e in events]
        self.assertEqual(ids, sorted(ids))


if __name__ == "__main__":
    unittest.main()
