"""账号密码登录接口与连续失败锁定（S2-IAM-005 样品，纯标准库）。

实现 POST /api/iam/auth/login 的核心逻辑（不含 HTTP 层，生产用
FastAPI 薄层包一层即可，见 README 对接点）：
- 成功分三种响应：TOTP 已开启、须改密、直接发令牌（仅 dev 免二次验证）。
- 失败统一 401 与相同文案「账号或密码错误」，不区分账号不存在与口令错误；
  账号不存在时也执行一次假哈希比较，使耗时接近。
- 同一账号 15 分钟内连续失败 5 次锁定 15 分钟（auth:fail:{user_id}）；
  同一 IP 10 分钟内失败 20 次限流 10 分钟（auth:ipfail:{ip}）；
  锁定期间返回 423 并带剩余秒数；登录成功清零计数。
- status 为 locked 或 disabled 的账号返回 403。
- 每次登录尝试都记一条 auth_events，不记录口令。

只用虚构测试数据；challenge 与令牌均为随机生成，不含真实用户信息。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from auth_events import AuthEventStore
from fake_redis import FakeRedis, remaining_seconds
from passwords import dummy_verify, hash_password, verify_password

IDENTICAL_FAILURE = "账号或密码错误"

MAX_FAILURES = 5
FAIL_WINDOW_SECONDS = 900
LOCK_SECONDS = 900
MAX_IP_FAILURES = 20
IP_WINDOW_SECONDS = 600
IP_LIMIT_SECONDS = 600
CHALLENGE_TTL_SECONDS = 300
TOKEN_TTL_SECONDS = 3600


@dataclass
class User:
    org_code: str
    login_name: str
    password_hash: str
    totp_enabled: bool = False
    must_change_password: bool = False
    status: str = "active"
    user_id: str = field(default_factory=lambda: uuid.uuid4().hex)


class UserStore:
    """内存用户库：按 (org_code, login_name) 查用户。"""

    def __init__(self):
        self._users: dict[tuple[str, str], User] = {}

    def add_user(
        self,
        org_code: str,
        login_name: str,
        password: str,
        totp_enabled: bool = False,
        must_change: bool = False,
        status: str = "active",
    ) -> User:
        user = User(
            org_code=org_code,
            login_name=login_name,
            password_hash=hash_password(password),
            totp_enabled=totp_enabled,
            must_change_password=must_change,
            status=status,
        )
        self._users[(org_code, login_name)] = user
        return user

    def find(self, org_code: str, login_name: str) -> User | None:
        return self._users.get((org_code, login_name))


class LoginService:
    """登录服务：锁定、challenge 单次使用、事件记录。"""

    def __init__(
        self,
        users: UserStore | None = None,
        redis: FakeRedis | None = None,
        events: AuthEventStore | None = None,
        now=time.time,
    ):
        self._now = now
        self.users = users if users is not None else UserStore()
        self.redis = redis if redis is not None else FakeRedis(now=now)
        self.events = events if events is not None else AuthEventStore(now=now)

    # -- challenge ------------------------------------------------------
    def _new_challenge(self, user: User, purpose: str) -> str:
        challenge_id = uuid.uuid4().hex
        self.redis.set(
            "auth:challenge:%s" % challenge_id,
            {"user_id": user.user_id, "org_id": user.org_code, "purpose": purpose},
            ex=CHALLENGE_TTL_SECONDS,
        )
        return challenge_id

    def verify_challenge(self, challenge_id: str) -> bool:
        """challenge 只能使用一次：首次返回 True 并立即作废，第二次返回 False。"""
        key = "auth:challenge:%s" % challenge_id
        if self.redis.get(key) is None:
            return False
        self.redis.delete(key)
        return True

    # -- 登录 ------------------------------------------------------------
    def login(
        self,
        org_code: str,
        login_name: str,
        password: str,
        ip: str = "127.0.0.1",
        user_agent: str = "",
    ) -> tuple[int, dict]:
        now = self._now()
        if not org_code or not login_name or not password:
            return 400, {"detail": "请求参数缺失"}

        ip_lock_key = "auth:iplock:%s" % ip
        ip_locked_until = self.redis.get(ip_lock_key)
        if ip_locked_until is not None:
            self.events.record(
                org_code, None, "login_attempt", "failure",
                "ip_rate_limited", ip, user_agent,
            )
            return 423, {
                "detail": "登录过于频繁，请稍后再试",
                "retry_after_seconds": remaining_seconds(float(ip_locked_until), now),
            }

        user = self.users.find(org_code, login_name)
        if user is None:
            # 账号不存在：也做一次假哈希比较，响应与口令错误完全相同。
            dummy_verify(password)
            self._note_ip_failure(ip, org_code, user_agent)
            self.events.record(
                org_code, None, "login_attempt", "failure",
                "user_not_found", ip, user_agent,
            )
            return 401, {"detail": IDENTICAL_FAILURE}

        if user.status in ("locked", "disabled"):
            detail = "账号已锁定" if user.status == "locked" else "账号已停用"
            self.events.record(
                org_code, user.user_id, "login_attempt", "failure",
                "account_locked" if user.status == "locked" else "account_disabled",
                ip, user_agent,
            )
            return 403, {"detail": detail}

        lock_key = "auth:lock:%s" % user.user_id
        locked_until = self.redis.get(lock_key)
        if locked_until is not None:
            self.events.record(
                org_code, user.user_id, "login_attempt", "failure",
                "account_locked", ip, user_agent,
            )
            return 423, {
                "detail": "登录失败次数过多，账号已锁定",
                "retry_after_seconds": remaining_seconds(float(locked_until), now),
            }

        if not verify_password(password, user.password_hash):
            fail_key = "auth:fail:%s" % user.user_id
            fails = self.redis.incr_in_window(fail_key, FAIL_WINDOW_SECONDS)
            if fails >= MAX_FAILURES:
                self.redis.set(lock_key, now + LOCK_SECONDS, ex=LOCK_SECONDS)
            self._note_ip_failure(ip, org_code, user_agent)
            self.events.record(
                org_code, user.user_id, "login_attempt", "failure",
                "wrong_password", ip, user_agent,
            )
            return 401, {"detail": IDENTICAL_FAILURE}

        # 成功：清零账号与本 IP 的失败计数。
        self.redis.clear_window("auth:fail:%s" % user.user_id)
        self.redis.delete(lock_key)
        self.redis.clear_window("auth:ipfail:%s" % ip)
        self.events.record(
            org_code, user.user_id, "login_attempt", "success",
            "ok", ip, user_agent,
        )
        if user.totp_enabled:
            return 200, {
                "step": "totp_required",
                "challenge_id": self._new_challenge(user, "totp"),
                "expires_in": CHALLENGE_TTL_SECONDS,
            }
        if user.must_change_password:
            return 200, {
                "step": "password_change_required",
                "challenge_id": self._new_challenge(user, "password_change"),
            }
        return 200, {
            "step": "authenticated",
            "access_token": uuid.uuid4().hex,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL_SECONDS,
        }

    def _note_ip_failure(self, ip: str, org_code: str, user_agent: str) -> None:
        fails = self.redis.incr_in_window("auth:ipfail:%s" % ip, IP_WINDOW_SECONDS)
        if fails >= MAX_IP_FAILURES:
            self.redis.set(
                "auth:iplock:%s" % ip,
                self._now() + IP_LIMIT_SECONDS,
                ex=IP_LIMIT_SECONDS,
            )
