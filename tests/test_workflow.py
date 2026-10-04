import tempfile, unittest
from pathlib import Path
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES
class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def _to_controlled(self, ref="WF-1"):
        item=self.service.create_item({"title":"workflow item","description":"complete business flow","severity":'high',"quantity":12,"threshold":6,"external_ref":ref},"creator",'field_commander')
        self.service.add_record(item["id"],{"kind":"evidence","detail":"evidence registered","status":"closed","external_ref":"EV-1"},"recorder",'field_commander')
        current=item
        for target in STATES[1:-1]:
            current=self.service.transition(current["id"],target,current["version"],"reviewer",TRANSITION_ROLES[target][0])
        return current
    def test_signoff_close_workflow_and_audit(self):
        current=self._to_controlled()
        iid=current["id"]
        self.service.update_observation(iid,{"task_zone":"东坡任务区","wind_dir":"N","wind_speed":3},"scout",'field_commander')
        view=self.service.submit_signoff(iid,{"basis":"火势受控、风向稳定"},"sun",'incident_commander')
        sid=view["signoffs"][-1]["id"]
        view=self.service.confirm_signoff(iid,sid,"sun",'incident_commander')
        self.assertIsNotNone(view["current_effective_signoff"])
        view=self.service.close_with_signoff(iid,{"signoff_id":sid},"sun",'incident_commander')
        self.assertEqual(view["item"]["status"],STATES[-1])
        self.assertEqual(view["signoffs"][-1]["status"],"consumed")
        events=self.service.audit("viewer",iid)
        actions=[e["action"] for e in events]
        self.assertIn("observation_open",actions); self.assertIn("signoff_submit",actions)
        self.assertIn("signoff_confirm",actions); self.assertIn("close",actions)
        self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
