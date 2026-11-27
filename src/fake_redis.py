"""内存版 Redis 替身（S2-IAM-005 样品，纯标准库）。

只模拟本单用到的语义：带 TTL 的键值、滑动窗口失败计数。
生产实现换成真实 Redis 客户端，键名与本样品一致。
"""

from __future__ import annotations

import math
import time


class FakeRedis:
    """最小 Redis 替身：set/get/delete + 滑动窗口计数。"""

    def __init__(self, now=time.time):
        self._now = now
        self._kv: dict[str, tuple[object, float | None]] = {}
        self._windows: dict[str, list[float]] = {}

    def now(self) -> float:
        return self._now()

    def set(self, key: str, value: object, ex: float | None = None) -> None:
        expiry = self._now() + ex if ex is not None else None
        self._kv[key] = (value, expiry)

    def get(self, key: str) -> object | None:
        item = self._kv.get(key)
        if item is None:
            return None
        value, expiry = item
        if expiry is not None and self._now() >= expiry:
            del self._kv[key]
            return None
        return value

    def delete(self, key: str) -> None:
        self._kv.pop(key, None)
        self._windows.pop(key, None)

    def incr_in_window(self, key: str, window_seconds: float) -> int:
        """窗口内记一次，返回窗口内当前次数（含本次）。"""
        now = self._now()
        stamps = [t for t in self._windows.get(key, []) if now - t < window_seconds]
        stamps.append(now)
        self._windows[key] = stamps
        return len(stamps)

    def count_in_window(self, key: str, window_seconds: float) -> int:
        now = self._now()
        stamps = [t for t in self._windows.get(key, []) if now - t < window_seconds]
        self._windows[key] = stamps
        return len(stamps)

    def clear_window(self, key: str) -> None:
        self._windows.pop(key, None)


def remaining_seconds(locked_until: float, now: float) -> int:
    """锁定剩余秒数，向上取整，至少 1 秒。"""
    return max(1, math.ceil(locked_until - now))
