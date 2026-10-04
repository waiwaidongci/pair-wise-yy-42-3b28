import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES
class FailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
        self.item=self.service.create_item({"title":"failure item","description":"failure scenarios","severity":'high',"quantity":5,"threshold":10,"external_ref":"FAIL-1"},"creator",'field_commander')
        self.iid=self.item["id"]
        self.service.add_record(self.iid,{"kind":"action","detail":"closed item","status":"closed","external_ref":"C-1"},"recorder",'field_commander')
        cur=self.item
        for target in STATES[1:-1]:
            cur=self.service.transition(cur["id"],target,cur["version"],"sun",TRANSITION_ROLES[target][0])
        self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"N"},"scout",'field_commander')
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def test_version_conflict_still_guarded(self):
        fresh=self.service.create_item({"title":"fresh","description":"d","severity":'low',"quantity":1,"threshold":2,"external_ref":"V-1"},"c",'field_commander')
        with self.assertRaises(ConflictError):
            self.service.transition(fresh["id"],"active",99,"sun",'incident_commander')
    def test_direct_close_transition_is_blocked(self):
        with self.assertRaises(ConflictError):
            self.service.transition(self.iid,"closed",self.service.get_item(self.iid,"viewer")["version"],"sun",'incident_commander')
    def test_handover_invalidates_old_signoff_and_old_actor_rejected(self):
        v=self.service.submit_signoff(self.iid,{"basis":"sun批准"},"sun",'incident_commander')
        sid=v["signoffs"][-1]["id"]
        self.service.confirm_signoff(self.iid,sid,"sun",'incident_commander')
        v=self.service.handover(self.iid,{"to_actor":"qian","to_role":"deputy_commander","reason":"夜班交接"},"sun",'incident_commander')
        self.assertEqual([s["status"] for s in v["signoffs"] if s["id"]==sid],["invalidated"])
        self.assertIsNone(v["current_effective_signoff"])
        with self.assertRaises(PermissionDenied):
            self.service.submit_signoff(self.iid,{"basis":"交班后的旧审批"},"sun",'incident_commander')
        view=self.service.signoff_view(self.iid,"viewer")
        rejected=[s for s in view["signoffs"] if s["status"]=="rejected"]
        self.assertEqual(len(rejected),1)
        self.assertIn("越权",rejected[0]["failure_reason"])
        # 越权拒绝已进入同一条审计链
        self.assertTrue(self.repo.verify_audit_chain())
    def test_observation_change_invalidates_pending_and_active(self):
        v=self.service.handover(self.iid,{"to_actor":"qian","to_role":"deputy_commander"},"sun",'incident_commander')
        v=self.service.submit_signoff(self.iid,{"basis":"v1依据"},"qian",'deputy_commander')
        pending=v["signoffs"][-1]["id"]
        # 风向再变：pending立即失效
        v=self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"NW"},"scout",'field_commander')
        self.assertEqual([s["status"] for s in v["signoffs"] if s["id"]==pending],["invalidated"])
        v=self.service.submit_signoff(self.iid,{"basis":"v2依据"},"qian",'deputy_commander')
        sid=v["signoffs"][-1]["id"]
        self.service.confirm_signoff(self.iid,sid,"qian",'deputy_commander')
        # active签认后风向再变：当前有效签认消失
        v=self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"E"},"scout",'field_commander')
        self.assertIsNone(v["current_effective_signoff"])
        with self.assertRaises(ConflictError):
            self.service.close_with_signoff(self.iid,{"signoff_id":sid},"qian",'deputy_commander')
        self.assertEqual([s["status"] for s in self.repo.list_signoffs(self.iid) if s["id"]==sid],["invalidated"])
    def test_confirm_stale_pending_is_invalidated(self):
        self.service.handover(self.iid,{"to_actor":"qian","to_role":"deputy_commander"},"sun",'incident_commander')
        v=self.service.submit_signoff(self.iid,{"basis":"x"},"qian",'deputy_commander')
        sid=v["signoffs"][-1]["id"]
        self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"SE"},"scout",'field_commander')
        with self.assertRaises(ConflictError):
            self.service.confirm_signoff(self.iid,sid,"qian",'deputy_commander')
        self.assertEqual([s["status"] for s in self.repo.list_signoffs(self.iid) if s["id"]==sid],["invalidated"])
    def test_role_guards(self):
        with self.assertRaises(PermissionDenied):
            self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"N"},"qian",'deputy_commander')
        with self.assertRaises(PermissionDenied):
            self.service.handover(self.iid,{"to_actor":"qian","to_role":"deputy_commander"},"qian",'deputy_commander')
        with self.assertRaises(PermissionDenied):
            self.service.submit_signoff(self.iid,{"basis":"x"},"scout",'field_commander')
        with self.assertRaises(ValidationError):
            self.service.update_observation(self.iid,{"task_zone":"z","wind_dir":"BAD"},"scout",'field_commander')
    def test_no_observation_blocks_signoff(self):
        item=self.service.create_item({"title":"no obs","description":"d","severity":"low","quantity":1,"threshold":2,"external_ref":"N2"},"c",'field_commander')
        for target in STATES[1:-1]:
            item=self.service.transition(item["id"],target,item["version"],"sun",'incident_commander')
        with self.assertRaises(ValidationError):
            self.service.submit_signoff(item["id"],{"basis":"无观察先签认"},"sun",'incident_commander')
    def test_open_records_block_close(self):
        item=self.service.create_item({"title":"open rec","description":"d","severity":"low","quantity":1,"threshold":2,"external_ref":"OR-1"},"c",'field_commander')
        self.service.add_record(item["id"],{"kind":"todo","detail":"still open","status":"open","external_ref":"O-1"},"r",'field_commander')
        for target in STATES[1:-1]:
            item=self.service.transition(item["id"],target,item["version"],"sun",'incident_commander')
        self.service.update_observation(item["id"],{"task_zone":"z","wind_dir":"N"},"scout",'field_commander')
        v=self.service.submit_signoff(item["id"],{"basis":"b"},"sun",'incident_commander')
        sid=v["signoffs"][-1]["id"]
        self.service.confirm_signoff(item["id"],sid,"sun",'incident_commander')
        with self.assertRaises(ConflictError):
            self.service.close_with_signoff(item["id"],{"signoff_id":sid},"sun",'incident_commander')
        self.assertNotEqual(self.service.get_item(item["id"],"viewer")["status"],"closed")
if __name__=="__main__": unittest.main()
