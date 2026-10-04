from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, PermissionDenied, ValidationError, WIND_DIRS,
                     ensure_role, normalize_severity, require_number, require_text)
from .audit import utc_now
from .repository import Repository
from .rules import (AUDIT_ROLES, COMMANDER_ROLE, CREATE_ROLES, DEPUTY_ROLE, ENTITY,
                    HANDOVER_ROLES, OBSERVATION_ROLES, RECORD_ROLES, SIGNOFF_ROLES,
                    TITLE, VIEW_ROLES, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        if target == "closed":
            raise ConflictError(
                "关闭火场必须走关闭签认：POST /api/items/{id}/signoffs/close，"
                "且须持有当前观察/交接窗口内的有效签认")
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ---- 任务区观察 / 角色交接 / 关闭签认 ----

    def _current_authority(self, conn, item_id: int) -> Dict[str, Any]:
        """返回当前持权人：未交接时为 incident_commander 通用角色；交接后为指定的人。"""
        handover = self.repository.latest_handover(conn, item_id)
        if handover and handover["active"]:
            return {"handover_version": handover["version"], "actor": handover["to_actor"],
                    "role": handover["to_role"], "handover": handover}
        return {"handover_version": 0, "actor": None, "role": COMMANDER_ROLE,
                "handover": None}

    @staticmethod
    def _require_observation(observation) -> Dict[str, Any]:
        if observation is None:
            raise ValidationError("尚未建立任务区观察窗口，无法签认关闭")
        return observation

    def update_observation(self, item_id: int, payload: Dict[str, Any],
                           actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, OBSERVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        task_zone = require_text(payload.get("task_zone"), "task_zone", 200)
        wind_dir = payload.get("wind_dir")
        if wind_dir not in WIND_DIRS:
            raise ValidationError("wind_dir必须是八方位之一(N/NE/E/SE/S/SW/W/NW)")
        wind_speed = require_number(payload.get("wind_speed", 0), "wind_speed")
        note = payload.get("note", "")
        note = require_text(note, "note", 2000) if note else ""
        invalidated: list = []
        with self.repository.transaction() as conn:
            before = self.repository.get_observation(conn, item_id)
            observation = self.repository.upsert_observation(
                conn, item_id, task_zone, wind_dir, wind_speed, note, actor)
            if before is not None:
                invalidated = self.repository.invalidate_open_signoffs(
                    conn, item_id, "observation",
                    f"观察窗口已更新(v{before['version']}→v{observation['version']}，"
                    f"风向{before['wind_dir']}→{wind_dir})，未完成签认失效")
                self.repository._insert_audit(
                    conn, "observation_update", ENTITY, item_id, actor, {
                        "version": observation["version"], "task_zone": task_zone,
                        "wind_dir": wind_dir, "wind_speed": wind_speed,
                        "invalidated_signoff_ids": invalidated,
                    })
            else:
                self.repository._insert_audit(
                    conn, "observation_open", ENTITY, item_id, actor, {
                        "version": observation["version"], "task_zone": task_zone,
                        "wind_dir": wind_dir, "wind_speed": wind_speed,
                    })
        return self._signoff_view(item_id, item=item)

    def handover(self, item_id: int, payload: Dict[str, Any],
                 actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, HANDOVER_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        to_actor = require_text(payload.get("to_actor"), "to_actor", 100)
        to_role = payload.get("to_role", DEPUTY_ROLE)
        if to_role not in (COMMANDER_ROLE, DEPUTY_ROLE):
            raise ValidationError("to_role必须是incident_commander或deputy_commander")
        reason = payload.get("reason", "")
        reason = require_text(reason, "reason", 500) if reason else ""
        with self.repository.transaction() as conn:
            authority = self._current_authority(conn, item_id)
            if authority["handover"] is not None and \
                    authority["handover"]["to_role"] == DEPUTY_ROLE and \
                    actor != authority["handover"]["from_actor"] and role != COMMANDER_ROLE:
                raise PermissionDenied("只有原交接指挥可收回或变更关闭权限")
            new_version = authority["handover_version"] + 1
            record = self.repository.insert_handover(
                conn, item_id, new_version, actor, role, to_actor, to_role, reason)
            invalidated = self.repository.invalidate_open_signoffs(
                conn, item_id, "handover",
                f"交接窗口已更新至v{new_version}：{actor}({role})→{to_actor}({to_role})，"
                "未完成签认失效，须由当前持权人重新确认")
            self.repository._insert_audit(
                conn, "handover", ENTITY, item_id, actor, {
                    "handover_version": new_version,
                    "from_actor": actor, "from_role": role,
                    "to_actor": to_actor, "to_role": to_role,
                    "reason": reason, "invalidated_signoff_ids": invalidated,
                })
        return self._signoff_view(item_id, item=item)

    def submit_signoff(self, item_id: int, payload: Dict[str, Any],
                       actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SIGNOFF_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        basis = require_text(payload.get("basis"), "basis(关闭依据)", 2000)
        with self.repository.transaction() as conn:
            authority = self._current_authority(conn, item_id)
            observation = self._require_observation(
                self.repository.get_observation(conn, item_id))

            # 窗口外提交：人不对（旧指挥的旧审批）或角色不对，一律按越权拒绝并落审计。
            if authority["actor"] is not None and actor != authority["actor"]:
                self._reject_signoff(
                    item_id, observation, authority, actor, role,
                    f"越权：当前关闭权限已交给{authority['actor']}({authority['role']})，"
                    f"{actor}的旧审批不得放行（窗口外提交）")
            if role != authority["role"]:
                self._reject_signoff(
                    item_id, observation, authority, actor, role,
                    f"越权：当前窗口要求角色{authority['role']}，提交角色为{role}（窗口外提交）")

            pending = self.repository.insert_signoff(
                conn, item_id, "pending", observation["version"],
                authority["handover_version"], observation["wind_dir"], actor, role)
            self.repository._insert_audit(
                conn, "signoff_submit", ENTITY, item_id, actor, {
                    "signoff_id": pending["id"],
                    "observation_version": observation["version"],
                    "handover_version": authority["handover_version"],
                    "basis_wind_dir": observation["wind_dir"], "basis": basis,
                    "status": "pending",
                })
        return self._signoff_view(item_id, item=item)

    def _reject_signoff(self, item_id: int, observation, authority,
                        actor: str, role: str, reason: str) -> None:
        # 越权拒绝必须独立事务先落库（含审计），再抛异常；此时外层事务只有读操作。
        with self.repository.transaction() as conn:
            rejected = self.repository.insert_signoff(
                conn, item_id, "rejected", observation["version"],
                authority["handover_version"], observation["wind_dir"], actor, role,
                failure_reason=reason)
            self.repository._insert_audit(
                conn, "signoff_reject", ENTITY, item_id, actor, {
                    "signoff_id": rejected["id"], "reason": reason,
                    "observation_version": observation["version"],
                    "handover_version": authority["handover_version"],
                })
        raise PermissionDenied(reason)

    def confirm_signoff(self, item_id: int, signoff_id: int,
                        actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SIGNOFF_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        with self.repository._lock:
            conn = self.repository.conn
            signoff = self.repository.get_signoff(conn, signoff_id)
            if signoff["item_id"] != item_id:
                raise ValidationError("签认不属于该任务区")
            authority = self._current_authority(conn, item_id)
            observation = self._require_observation(
                self.repository.get_observation(conn, item_id))
        if signoff["status"] != "pending":
            raise ConflictError(
                f"签认当前状态为{signoff['status']}，无法确认："
                + (signoff["failure_reason"] or "仅pending签认可确认"))
        if authority["actor"] is not None and actor != authority["actor"]:
            raise PermissionDenied("越权：只有当前持权人可确认签认")
        if role != authority["role"]:
            raise PermissionDenied("越权：当前角色不在关闭授权窗口内")
        if signoff["observation_version"] != observation["version"] or \
                signoff["handover_version"] != authority["handover_version"]:
            reason = (
                f"窗口版本已变化(观察v{signoff['observation_version']}→"
                f"v{observation['version']}，交接v{signoff['handover_version']}→"
                f"v{authority['handover_version']})，请重新提交签认")
            with self.repository.transaction() as conn2:
                conn2.execute(
                    """UPDATE signoffs SET status='invalidated', failure_reason=?,
                       invalidated_by_kind='stale_confirm', updated_at=? WHERE id=?""",
                    (reason, utc_now(), signoff_id))
                self.repository._insert_audit(
                    conn2, "signoff_invalidate", ENTITY, item_id, actor,
                    {"signoff_id": signoff_id, "reason": reason})
            raise ConflictError(reason)
        with self.repository.transaction() as conn2:
            active = self.repository.confirm_signoff(conn2, signoff_id, actor)
            self.repository._insert_audit(
                conn2, "signoff_confirm", ENTITY, item_id, actor, {
                    "signoff_id": signoff_id,
                    "observation_version": active["observation_version"],
                    "handover_version": active["handover_version"],
                    "basis_wind_dir": active["basis_wind_dir"],
                })
        return self._signoff_view(item_id, item=item)

    def close_with_signoff(self, item_id: int, payload: Dict[str, Any],
                           actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SIGNOFF_ROLES)
        actor = require_text(actor, "actor", 100)
        signoff_id = payload.get("signoff_id")
        if not isinstance(signoff_id, int) or signoff_id < 1:
            raise ValidationError("signoff_id必须是正整数")
        item = self.repository.get_item(item_id)
        if item["status"] != "controlled":
            raise ConflictError(
                f"任务区当前状态为{item['status']}，须先推进至controlled方可关闭")
        blockers = completion_blockers("closed", self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))

        with self.repository._lock:
            conn = self.repository.conn
            authority = self._current_authority(conn, item_id)
            observation = self.repository.get_observation(conn, item_id)
        if (authority["actor"] is not None and actor != authority["actor"]) \
                or role != authority["role"]:
            reason = (
                f"越权关闭被拒绝：当前持权人为{authority['actor'] or 'incident_commander'}"
                f"({authority['role']})，提交人{actor}({role})在授权窗口外")
            if observation is not None:
                with self.repository.transaction() as conn2:
                    rejected = self.repository.insert_signoff(
                        conn2, item_id, "rejected", observation["version"],
                        authority["handover_version"], observation["wind_dir"],
                        actor, role, failure_reason=reason)
                    self.repository._insert_audit(
                        conn2, "signoff_reject", ENTITY, item_id, actor, {
                            "signoff_id": rejected["id"], "reason": reason,
                            "attempt": "close",
                            "observation_version": observation["version"],
                            "handover_version": authority["handover_version"]})
            raise PermissionDenied(reason)

        with self.repository.transaction() as conn:
            signoff = self.repository.get_signoff(conn, signoff_id)
            if signoff["item_id"] != item_id:
                raise ValidationError("签认不属于该任务区")
            stale = (signoff["observation_version"] != observation["version"]
                     or signoff["handover_version"] != authority["handover_version"])
            if signoff["status"] != "active" or stale:
                reason = (
                    "关闭依据失真：观察或交接窗口已变化，签认失效，须重新确认"
                    if stale else
                    f"无有效签认可关闭（该签认状态：{signoff['status']}"
                    + (f"，{signoff['failure_reason']}" if signoff["failure_reason"] else "")
                    + "）")
                if stale and signoff["status"] == "active":
                    conn.execute(
                        """UPDATE signoffs SET status='invalidated', failure_reason=?,
                           invalidated_by_kind='stale_close', updated_at=? WHERE id=?""",
                        (reason, utc_now(), signoff_id))
                    self.repository._insert_audit(
                        conn, "signoff_invalidate", ENTITY, item_id, actor,
                        {"signoff_id": signoff_id, "reason": reason})
                raise ConflictError(reason)
            self.repository.consume_active_signoff(conn, item_id)
            self.repository.update_status_conn(conn, item_id, "closed")
            self.repository._insert_audit(
                conn, "close", ENTITY, item_id, actor, {
                    "signoff_id": signoff_id,
                    "observation_version": observation["version"],
                    "handover_version": authority["handover_version"],
                    "basis_wind_dir": signoff["basis_wind_dir"],
                    "from": item["status"], "to": "closed",
                })
        return self._signoff_view(item_id)

    def signoff_view(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._signoff_view(item_id)

    def _signoff_view(self, item_id: int, item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        item = item or self.repository.get_item(item_id)
        with self.repository._lock:
            conn = self.repository.conn
            observation = self.repository.get_observation(conn, item_id)
            handover = self.repository.latest_handover(conn, item_id)
            signoffs = self.repository.list_signoffs(item_id)
            active = self.repository.active_signoff(conn, item_id)
        authority = {"actor": None, "role": COMMANDER_ROLE, "handover_version": 0}
        if handover and handover["active"]:
            authority = {"actor": handover["to_actor"], "role": handover["to_role"],
                         "handover_version": handover["version"]}
        current_effective = None
        if active and observation and \
                active["observation_version"] == observation["version"] and \
                active["handover_version"] == authority["handover_version"]:
            current_effective = active
        return {
            "item": self.enrich(item),
            "observation": observation,
            "authority": authority,
            "current_effective_signoff": current_effective,
            "signoffs": signoffs,
            "audit_chain_ok": self.repository.verify_audit_chain(),
        }

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
