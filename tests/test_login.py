"""账号密码登录接口与连续失败锁定测试（S2-IAM-005）。

测试数据全部虚构：机构编码 ORG-TEST、登录名 zhangsan / lisi 等、
口令 Test-pass-001 之类的测试口令，不对应任何真实个人或企业信息。
"""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from auth_events import EVENT_FIELDS, AuthEventStore
from auth_service import (
    CHALLENGE_TTL_SECONDS,
    FAIL_WINDOW_SECONDS,
    LOCK_SECONDS,
    LoginService,
    UserStore,
)
from fake_redis import FakeRedis
from passwords import dummy_verify, hash_password, verify_password


class Clock:
    """可手动推进的时钟，供锁定与过期测试用。"""

    def __init__(self):
        self.t = time.time()

    def now(self):
        return self.t

    def advance(self, seconds: float):
        self.t += seconds


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def svc(clock):
    users = UserStore()
    users.add_user("ORG-TEST", "zhangsan", "Test-pass-001")
    users.add_user("ORG-TEST", "lisi", "Test-pass-002", totp_enabled=True)
    users.add_user("ORG-TEST", "wangwu", "Test-pass-003", must_change=True)
    users.add_user("ORG-TEST", "locked1", "Test-pass-004", status="locked")
    users.add_user("ORG-TEST", "disabled1", "Test-pass-005", status="disabled")
    users.add_user("ORG-OTHER", "zhangsan", "Test-pass-006")
    return LoginService(
        users=users,
        redis=FakeRedis(now=clock.now),
        events=AuthEventStore(now=clock.now),
        now=clock.now,
    )


def _wrong(svc, name="zhangsan", org="ORG-TEST", ip="10.0.0.1"):
    return svc.login(org, name, "Wrong-pass-000", ip=ip)


# ---------------- 验收标准（逐条对应平台 AC 原文） ----------------

def test_ac1_five_wrong_then_sixth_423(svc):
    """1. 连续 5 次错误密码后第 6 次返回 423 并带剩余秒数（测试断言）"""
    for _ in range(5):
        status, _ = _wrong(svc)
        assert status == 401
    status, body = _wrong(svc)
    assert status == 423
    assert body["retry_after_seconds"] > 0
    assert body["retry_after_seconds"] <= LOCK_SECONDS


def test_ac1_lock_expires_then_login_ok(svc, clock):
    for _ in range(6):
        _wrong(svc)
    status, _ = _wrong(svc)
    assert status == 423
    clock.advance(LOCK_SECONDS + 1)
    status, body = svc.login("ORG-TEST", "zhangsan", "Test-pass-001", ip="10.0.0.1")
    assert status == 200
    assert body["step"] == "authenticated"


def test_ac1_remaining_seconds_decrease(svc, clock):
    for _ in range(6):
        _wrong(svc)
    _, body1 = _wrong(svc)
    clock.advance(60)
    _, body2 = _wrong(svc)
    assert body2["retry_after_seconds"] == body1["retry_after_seconds"] - 60


def test_ac2_unknown_vs_wrong_password_identical(svc):
    """2. 账号不存在与密码错误返回完全相同的状态码与文案（测试断言）"""
    status_a, body_a = svc.login("ORG-TEST", "nobody", "Wrong-pass-000", ip="10.0.0.2")
    status_b, body_b = _wrong(svc, ip="10.0.0.2")
    assert status_a == status_b == 401
    assert body_a == body_b == {"detail": "账号或密码错误"}


def test_ac3_challenge_second_use_401(svc):
    """3. 同一 challenge_id 第二次使用返回 401（测试断言）"""
    status, body = svc.login("ORG-TEST", "lisi", "Test-pass-002", ip="10.0.0.3")
    assert status == 200
    challenge_id = body["challenge_id"]
    assert svc.verify_challenge(challenge_id) is True
    # 第二次使用：challenge 已作废，对应接口层返回 401。
    assert svc.verify_challenge(challenge_id) is False


def test_ac3_challenge_second_use_401_must_change(svc):
    status, body = svc.login("ORG-TEST", "wangwu", "Test-pass-003", ip="10.0.0.3")
    assert status == 200
    assert body["step"] == "password_change_required"
    assert svc.verify_challenge(body["challenge_id"]) is True
    assert svc.verify_challenge(body["challenge_id"]) is False


def test_ac4_events_success_and_failure_no_password_field(svc):
    """4. auth_events 中可查到成功与失败记录，且没有任何密码字段"""
    svc.login("ORG-TEST", "zhangsan", "Test-pass-001", ip="10.0.0.4")
    _wrong(svc, ip="10.0.0.4")
    svc.login("ORG-TEST", "nobody", "Wrong-pass-000", ip="10.0.0.4")
    events = svc.events.all()
    assert [e for e in events if e["result"] == "success"]
    assert [e for e in events if e["result"] == "failure"]
    assert len(events) == 3
    # 注：reason_code 的值 wrong_password 是原因码，不是口令字段；
    # AC4 的“没有任何密码字段”指事件无 password 键且不存口令值。
    for event in events:
        assert tuple(event.keys()) == EVENT_FIELDS
        assert "password" not in event
        dumped = json.dumps(event, ensure_ascii=False)
        assert "Test-pass-001" not in dumped
        assert "Wrong-pass-000" not in dumped


def test_ac4_event_query_filters(svc):
    svc.login("ORG-TEST", "zhangsan", "Test-pass-001", ip="10.0.0.4")
    _wrong(svc, ip="10.0.0.4")
    assert len(svc.events.query(result="success")) == 1
    assert len(svc.events.query(result="failure")) == 1
    assert len(svc.events.query(org_id="ORG-OTHER")) == 0


# ---------------- 三种成功响应 ----------------

def test_totp_login_returns_challenge(svc):
    status, body = svc.login("ORG-TEST", "lisi", "Test-pass-002", ip="10.0.0.5")
    assert status == 200
    assert body["step"] == "totp_required"
    assert body["expires_in"] == CHALLENGE_TTL_SECONDS
    stored = svc.redis.get("auth:challenge:%s" % body["challenge_id"])
    assert stored is not None
    assert stored["purpose"] == "totp"


def test_must_change_login_returns_challenge(svc):
    status, body = svc.login("ORG-TEST", "wangwu", "Test-pass-003", ip="10.0.0.5")
    assert status == 200
    assert body["step"] == "password_change_required"
    assert "challenge_id" in body
    stored = svc.redis.get("auth:challenge:%s" % body["challenge_id"])
    assert stored["purpose"] == "password_change"


def test_direct_login_returns_token(svc):
    status, body = svc.login("ORG-TEST", "zhangsan", "Test-pass-001", ip="10.0.0.5")
    assert status == 200
    assert body["step"] == "authenticated"
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600
    assert len(body["access_token"]) == 32


def test_challenge_expires_after_ttl(svc, clock):
    _, body = svc.login("ORG-TEST", "lisi", "Test-pass-002", ip="10.0.0.6")
    clock.advance(CHALLENGE_TTL_SECONDS + 1)
    assert svc.verify_challenge(body["challenge_id"]) is False


def test_unknown_challenge_verify_false(svc):
    assert svc.verify_challenge("no-such-challenge-id") is False


# ---------------- 锁定与限流 ----------------

def test_locked_status_returns_403(svc):
    status, body = svc.login("ORG-TEST", "locked1", "Test-pass-004", ip="10.0.0.7")
    assert status == 403
    assert body == {"detail": "账号已锁定"}


def test_disabled_status_returns_403(svc):
    status, body = svc.login("ORG-TEST", "disabled1", "Test-pass-005", ip="10.0.0.7")
    assert status == 403
    assert body == {"detail": "账号已停用"}


def test_success_clears_failure_count(svc):
    for _ in range(4):
        _wrong(svc)
    status, _ = svc.login("ORG-TEST", "zhangsan", "Test-pass-001", ip="10.0.0.1")
    assert status == 200
    status, _ = _wrong(svc)
    assert status == 401  # 清零后只算 1 次失败，不是第 6 次
    for _ in range(4):
        status, _ = _wrong(svc)
        assert status == 401
    status, body = _wrong(svc)
    assert status == 423


def test_fail_window_slides(svc, clock):
    for _ in range(4):
        _wrong(svc)
    clock.advance(FAIL_WINDOW_SECONDS + 1)
    status, _ = _wrong(svc)
    assert status == 401  # 旧失败已出窗口，重新计数


def test_ip_limit_20_then_423(svc):
    for i in range(20):
        status, _ = svc.login("ORG-TEST", "ghost-%02d" % i, "Wrong-pass-000",
                              ip="10.0.1.99")
        assert status == 401
    status, body = svc.login("ORG-TEST", "ghost-99", "Wrong-pass-000", ip="10.0.1.99")
    assert status == 423
    assert body["retry_after_seconds"] > 0
    # 换 IP 不受影响，仍是 401。
    status, _ = svc.login("ORG-TEST", "ghost-99", "Wrong-pass-000", ip="10.0.2.99")
    assert status == 401


def test_ip_limit_expires(svc, clock):
    for i in range(21):
        svc.login("ORG-TEST", "ghost-%02d" % i, "Wrong-pass-000", ip="10.0.3.99")
    status, _ = svc.login("ORG-TEST", "ghost-99", "Wrong-pass-000", ip="10.0.3.99")
    assert status == 423
    clock.advance(601)
    status, _ = svc.login("ORG-TEST", "ghost-99", "Wrong-pass-000", ip="10.0.3.99")
    assert status == 401


def test_locked_attempt_recorded_as_blocked_event(svc):
    for _ in range(6):
        _wrong(svc)
    _wrong(svc)
    blocked = [e for e in svc.events.all() if e["reason_code"] == "account_locked"]
    assert blocked


# ---------------- 边界与口令 ----------------

def test_missing_field_returns_400(svc):
    assert svc.login("", "zhangsan", "Test-pass-001")[0] == 400
    assert svc.login("ORG-TEST", "", "Test-pass-001")[0] == 400
    assert svc.login("ORG-TEST", "zhangsan", "")[0] == 400


def test_org_isolation(svc):
    # 同一登录名在不同机构是不同账号，口令也不通用。
    status, body = svc.login("ORG-OTHER", "zhangsan", "Test-pass-001", ip="10.0.0.8")
    assert status == 401
    assert body == {"detail": "账号或密码错误"}
    status, body = svc.login("ORG-OTHER", "zhangsan", "Test-pass-006", ip="10.0.0.8")
    assert status == 200


def test_hash_roundtrip_and_wrong():
    stored = hash_password("Test-pass-001")
    assert verify_password("Test-pass-001", stored) is True
    assert verify_password("Test-pass-999", stored) is False
    assert verify_password("Test-pass-001", "broken-storage-string") is False


def test_dummy_verify_always_false():
    assert dummy_verify("anything-at-all") is False
    assert dummy_verify("Test-pass-001") is False


def test_wrong_password_does_not_leak_existence_in_events_shape(svc):
    _wrong(svc, ip="10.0.0.9")
    svc.login("ORG-TEST", "nobody", "Wrong-pass-000", ip="10.0.0.9")
    for event in svc.events.all():
        assert "password" not in event
        dumped = json.dumps(event, ensure_ascii=False)
        assert "Test-pass-001" not in dumped
        assert "Wrong-pass-000" not in dumped
        assert event["event_type"] == "login_attempt"
