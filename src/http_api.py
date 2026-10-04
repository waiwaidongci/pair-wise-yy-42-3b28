from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Tuple
from urllib.parse import urlparse

from .domain import (ConflictError, DomainError, NotFoundError,
                     PermissionDenied, ValidationError)
from .service import Service


def make_handler(service: Service, static_dir: str):
    root = Path(static_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ModularHell/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, path: Path) -> None:
            if not path.exists():
                self._json(404, {"error": "not_found"})
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _identity(self) -> Tuple[str, str]:
            return self.headers.get("X-Actor", ""), self.headers.get("X-Role", "")

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            if length > 2_000_000:
                raise ValidationError("请求体过大")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("请求体不是有效JSON") from exc
            if not isinstance(value, dict):
                raise ValidationError("请求体必须是JSON对象")
            return value

        def _send_error(self, exc: Exception) -> None:
            if isinstance(exc, ValidationError):
                status = 422
            elif isinstance(exc, NotFoundError):
                status = 404
            elif isinstance(exc, PermissionDenied):
                status = 403
            elif isinstance(exc, ConflictError):
                status = 409
            elif isinstance(exc, DomainError):
                status = 400
            elif isinstance(exc, ValueError):
                status = 422
            else:
                status = 500
            self._json(status, {"error": exc.__class__.__name__, "message": str(exc)})

        @staticmethod
        def _item_path(path: str):
            parts = path.split("/")
            # parts: ['', 'api', 'items', '<id>', '<sub>?']
            if len(parts) < 4 or parts[1] != "api" or parts[2] != "items":
                return None, None
            try:
                item_id = int(parts[3])
            except ValueError:
                return None, None
            sub = parts[4] if len(parts) > 4 else ""
            return item_id, sub

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    self._json(200, {"status": "ok"})
                elif path == "/":
                    self._html(root / "index.html")
                elif path == "/api/items":
                    _, role = self._identity()
                    self._json(200, {"items": service.list_items(role)})
                elif path == "/api/audit":
                    _, role = self._identity()
                    self._json(200, {
                        "events": service.audit(role),
                        "chain_valid": service.audit_chain_valid(),
                    })
                else:
                    item_id, sub = self._item_path(path)
                    if item_id is None:
                        self._json(404, {"error": "not_found"})
                        return
                    _, role = self._identity()
                    if sub == "":
                        self._json(200, service.get_item(item_id, role))
                    elif sub == "records":
                        self._json(200, {"records": service.list_records(item_id, role)})
                    elif sub == "observations":
                        self._json(200, {"observations": service.list_observations(item_id, role)})
                    elif sub == "handovers":
                        self._json(200, {"handovers": service.list_handovers(item_id, role)})
                    elif sub == "signoffs":
                        self._json(200, {"signoffs": service.list_signoffs(item_id, role)})
                    elif sub == "signoff":
                        self._json(200, service.current_signoff(item_id, role))
                    elif sub == "audit":
                        self._json(200, {
                            "events": service.audit(role, item_id),
                            "chain_valid": service.audit_chain_valid(),
                        })
                    else:
                        self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

        def do_POST(self) -> None:
            try:
                path = urlparse(self.path).path
                actor, role = self._identity()
                body = self._body()
                if path == "/api/items":
                    self._json(201, service.create_item(body, actor, role))
                    return
                item_id, sub = self._item_path(path)
                if item_id is None:
                    self._json(404, {"error": "not_found"})
                    return
                if sub == "records":
                    self._json(201, service.add_record(item_id, body, actor, role))
                elif sub == "observations":
                    self._json(201, service.add_observation(item_id, body, actor, role))
                elif sub == "handovers":
                    self._json(201, service.add_handover(item_id, body, actor, role))
                elif sub == "signoffs":
                    self._json(201, service.create_signoff(item_id, actor, role))
                elif sub == "transition":
                    target = body.get("target")
                    expected = body.get("expected_version")
                    self._json(200, service.transition(
                        item_id, target, expected, actor, role))
                else:
                    self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

    return Handler
