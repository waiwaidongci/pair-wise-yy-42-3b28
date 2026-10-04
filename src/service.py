from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ROLES, ConflictError, PermissionDenied, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, DEFAULT_CLOSURE_ROLE, ENTITY,
                    HANDOVER_ROLES, OBSERVATION_KINDS, OBSERVATION_ROLES,
                    RECORD_ROLES, TITLE, VIEW_ROLES, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    # -- 授权窗口：观察版本 + 交接窗口，关闭签认必须在窗口内 --
    def _window_context(self, item_id: int):
        obs = self.repository.current_observation_version(item_id)
        handover = self.repository.latest_handover(item_id)
        window = handover["window_version"] if handover else 0
        return obs, window, handover

    def _ensure_within_window(self, item_id: int, actor: str, role: str) -> None:
        handover = self.repository.latest_handover(item_id)
        if handover:
            if actor != handover["to_actor"]:
                raise PermissionDenied(
                    f"越权：当前交接窗口（第{handover['window_version']}任）仅授权 "
                    f"{handover['to_actor']}（{handover['to_role']}），{actor} 不在窗口内"
                )
        else:
            if role != DEFAULT_CLOSURE_ROLE:
                raise PermissionDenied(
                    f"越权：关闭签认仅授权 {DEFAULT_CLOSURE_ROLE} 角色"
                )

    def _stale_reason(self, item_id: int, signoff: Dict[str, Any],
                      obs: int, window: int) -> str:
        if signoff["status"] == "consumed":
            return "签认已用于关闭（已消耗），请重新确认后再关闭"
        changes = []
        if signoff["observation_version"] != obs:
            changes.append(
                f"观察版本已从 v{signoff['observation_version']} 变更为 v{obs}"
            )
        if signoff["handover_window"] != window:
            changes.append(
                f"交接窗口已从 w{signoff['handover_window']} 变更为 w{window}"
            )
        if not changes and signoff["status"] == "expired":
            changes.append("签认已失效")
        basis = f"（{'，'.join(changes)}）" if changes else ""
        return f"签认已失效{basis}，请重新确认后再关闭"

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

    def add_observation(self, item_id: int, payload: Dict[str, Any], actor: str,
                        role: str) -> Dict[str, Any]:
        ensure_role(role, OBSERVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        kind = require_text(payload.get("kind"), "kind", 50)
        if kind not in OBSERVATION_KINDS:
            raise ValidationError("kind不在允许范围内")
        detail = require_text(payload.get("detail"), "detail")
        version = self.repository.current_observation_version(item_id) + 1
        obs = self.repository.add_observation(item_id, version, kind, detail, actor)
        expired = self.repository.expire_valid_signoffs(item_id)
        for signoff in expired:
            self.repository.append_audit("signoff_expired", ENTITY, item_id, actor, {
                "signoff_id": signoff["id"], "reason": "observation_changed",
                "observation_version": version,
            })
        self.repository.append_audit("observation", ENTITY, item_id, actor, {
            "observation_id": obs["id"], "version": version,
            "kind": kind, "detail": detail,
        })
        return obs

    def add_handover(self, item_id: int, payload: Dict[str, Any], actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, HANDOVER_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        to_actor = require_text(payload.get("to_actor"), "to_actor", 100)
        to_role = require_text(payload.get("to_role"), "to_role", 100)
        if to_role not in ROLES:
            raise ValidationError("to_role不在允许范围内")
        reason = payload.get("reason", "")
        if reason:
            reason = require_text(reason, "reason", 200)
        from_actor, from_role = actor, role
        previous = self.repository.latest_handover(item_id)
        window = (previous["window_version"] if previous else 0) + 1
        handover = self.repository.add_handover(
            item_id, window, from_actor, from_role, to_actor, to_role, reason)
        expired = self.repository.expire_valid_signoffs(item_id)
        for signoff in expired:
            self.repository.append_audit("signoff_expired", ENTITY, item_id, actor, {
                "signoff_id": signoff["id"], "reason": "handover_changed",
                "handover_window": window,
            })
        self.repository.append_audit("handover", ENTITY, item_id, actor, {
            "handover_id": handover["id"], "window_version": window,
            "from_actor": from_actor, "from_role": from_role,
            "to_actor": to_actor, "to_role": to_role, "reason": reason,
        })
        return handover

    def create_signoff(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        self._ensure_within_window(item_id, actor, role)
        obs, window, _ = self._window_context(item_id)
        signoff = self.repository.create_signoff(item_id, obs, window, actor, role)
        self.repository.append_audit("signoff", ENTITY, item_id, actor, {
            "signoff_id": signoff["id"], "observation_version": obs,
            "handover_window": window, "signer": actor,
        })
        return signoff

    def current_signoff(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        self.repository.get_item(item_id)
        obs, window, _ = self._window_context(item_id)
        latest = self.repository.latest_signoff(item_id)
        valid = bool(
            latest and latest["status"] == "valid"
            and latest["observation_version"] == obs
            and latest["handover_window"] == window
        )
        if valid:
            return {
                "signoff": latest, "valid": True, "reason": None,
                "observation_version": obs, "handover_window": window,
            }
        if latest is None:
            reason = "尚未签认：当前无关闭签认，关闭时将由授权人当场确认"
        else:
            reason = self._stale_reason(item_id, latest, obs, window)
        return {
            "signoff": latest, "valid": False, "reason": reason,
            "observation_version": obs, "handover_window": window,
        }

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        if target == "closed":
            if not isinstance(expected_version, int) or expected_version < 1:
                raise ValueError("expected_version必须是正整数")
            self._ensure_within_window(item_id, actor, role)
            blockers = completion_blockers(target, self.repository.open_record_count(item_id))
            if blockers:
                raise ConflictError("；".join(blockers))
            obs, window, _ = self._window_context(item_id)
            latest = self.repository.latest_signoff(item_id)
            if (latest and latest["status"] == "valid"
                    and latest["observation_version"] == obs
                    and latest["handover_window"] == window):
                self.repository.consume_signoff(latest["id"])
                signoff_info = {
                    "signoff_id": latest["id"], "signer": latest["signer_actor"],
                    "implicit": False,
                }
            elif latest is not None:
                reason = self._stale_reason(item_id, latest, obs, window)
                self.repository.append_audit("reject", ENTITY, item_id, actor, {
                    "action_target": "closed", "reason": reason,
                    "observation_version": obs, "handover_window": window,
                    "signoff_id": latest["id"],
                })
                raise ConflictError(reason)
            else:
                created = self.repository.create_signoff(item_id, obs, window, actor, role)
                self.repository.consume_signoff(created["id"])
                signoff_info = {
                    "signoff_id": created["id"], "signer": actor, "implicit": True,
                }
            updated = self.repository.transition_item(item_id, target, expected_version, actor)
            self.repository.append_audit("transition", ENTITY, item_id, actor, {
                "from": item["status"], "to": target,
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"]),
                "observation_version": obs, "handover_window": window,
                **signoff_info,
            })
            return self.enrich(updated)

        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
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

    def list_observations(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_observations(item_id)

    def list_handovers(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_handovers(item_id)

    def list_signoffs(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_signoffs(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def audit_chain_valid(self) -> bool:
        return self.repository.verify_audit_chain()

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
