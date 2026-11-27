"""auth_events 记录（S2-IAM-005 样品，纯标准库）。

表字段（与任务一致）：id、org_id、user_id、event_type、result、
reason_code、ip、user_agent、created_at。
铁律：事件里永远不出现口令字段；record() 不接收口令参数。
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

EVENT_FIELDS = (
    "id",
    "org_id",
    "user_id",
    "event_type",
    "result",
    "reason_code",
    "ip",
    "user_agent",
    "created_at",
)


class AuthEventStore:
    """内存事件库：记录每次登录尝试，供查询与审计。"""

    def __init__(self, now=time.time):
        self._now = now
        self._events: list[dict] = []

    def record(
        self,
        org_id: str | None,
        user_id: str | None,
        event_type: str,
        result: str,
        reason_code: str,
        ip: str,
        user_agent: str,
    ) -> dict:
        event = {
            "id": uuid.uuid4().hex,
            "org_id": org_id,
            "user_id": user_id,
            "event_type": event_type,
            "result": result,
            "reason_code": reason_code,
            "ip": ip,
            "user_agent": user_agent,
            "created_at": datetime.fromtimestamp(
                self._now(), tz=timezone.utc
            ).isoformat(),
        }
        self._events.append(event)
        return dict(event)

    def query(
        self,
        org_id: str | None = None,
        user_id: str | None = None,
        result: str | None = None,
    ) -> list[dict]:
        out = []
        for event in self._events:
            if org_id is not None and event["org_id"] != org_id:
                continue
            if user_id is not None and event["user_id"] != user_id:
                continue
            if result is not None and event["result"] != result:
                continue
            out.append(dict(event))
        return out

    def all(self) -> list[dict]:
        return [dict(event) for event in self._events]
