# 会员空间平台 · 账号密码登录接口与连续失败锁定

任务编码：**S2-IAM-005**（ClawHunt #2949）。最小可验证样品：账号密码登录
接口、challenge 单次使用、连续失败锁定与 IP 限流、auth_events 记录、
pytest 用例。只用 Python 标准库，不连数据库、不调真实 IAM；测试数据全部虚构。

## 一键复跑

```bash
bash setup.sh
```

依次跑：pytest 全量测试 → 变异自证 → MANIFEST 核验，全过打印
`SELFTEST: PASS`。需要 Python >= 3.11；没有 pytest 时自动建本地
`.venv` 并安装 `requirements.txt`（只需 pytest）。

```python
from src.auth_service import LoginService

svc = LoginService()
svc.users.add_user("ORG-TEST", "zhangsan", "Test-pass-001")
status, body = svc.login("ORG-TEST", "zhangsan", "Test-pass-001")
# (200, {"step": "authenticated", "access_token": ..., ...})

svc.users.add_user("ORG-TEST", "lisi", "Test-pass-002", totp_enabled=True)
status, body = svc.login("ORG-TEST", "lisi", "Test-pass-002")
# (200, {"step": "totp_required", "challenge_id": ..., "expires_in": 300})
svc.verify_challenge(body["challenge_id"])  # True，第二次 False
```

## 文件

| 文件 | 说明 |
| --- | --- |
| `src/auth_service.py` | 登录服务：三种成功响应、统一 401、连续失败锁定、IP 限流、challenge 单次使用 |
| `src/passwords.py` | 口令哈希与校验（PBKDF2-HMAC-SHA256）、账号不存在时的假哈希比较 |
| `src/fake_redis.py` | 内存版 Redis 替身：带 TTL 的键值、滑动窗口失败计数 |
| `src/auth_events.py` | auth_events 记录与查询（9 个字段，永不含口令字段） |
| `tests/test_login.py` | 25 项 pytest 测试（含 4 条 AC 断言测试） |
| `scripts/mutation_check.py` | 变异自证：锁定阈值改坏，测试必须变红 |
| `scripts/run_all.sh` | 只跑 pytest 全量测试 |
| `ACCEPTANCE-EVIDENCE.md` | 每条验收标准的逐字实测输出 |

## 核心规则

- 成功分三种响应：已开启 TOTP 返回 `{step: 'totp_required', challenge_id,
  expires_in: 300}`，challenge 存 Redis（`auth:challenge:{id}`，5 分钟过期，
  只能使用一次）；须改密返回 `{step: 'password_change_required',
  challenge_id}`；未开启 TOTP 且当前环境允许免二次验证（仅 dev）直接返回令牌。
- 失败统一返回 401 与相同文案「账号或密码错误」，不区分账号不存在与口令错误；
  账号不存在时也执行一次假哈希比较，使耗时接近。
- 锁定：同一账号 15 分钟内连续失败 5 次锁定 15 分钟（`auth:fail:{user_id}`）；
  同一 IP 10 分钟内失败 20 次限流 10 分钟（`auth:ipfail:{ip}`）；
  锁定期间返回 423 并带剩余秒数；登录成功清零计数。
- status 为 locked 或 disabled 的账号返回 403。
- 新建 auth_events 表（id、org_id、user_id、event_type、result、reason_code、
  ip、user_agent、created_at）记录每次登录尝试，不记录口令。
  注：`reason_code` 的值 `wrong_password` 是原因码，不是口令字段；
  事件无 password 键且不存任何口令值，见 AC4 测试。

## 对接点（生产集成时换真实件）

- HTTP 层：本样品是纯逻辑层，生产用 FastAPI 薄层包一层实现
  `POST /api/iam/auth/login`，请求 `{org_code, login_name, password}`，
  状态码与响应体与 `LoginService.login` 返回值一一对应；
  `verify_challenge` 对应 TOTP / 改密第二步接口，第二次使用返回 401。
- Redis：把 `FakeRedis` 换成真实 Redis 客户端，键名不变
  （`auth:challenge:{id}`、`auth:fail:{user_id}`、`auth:ipfail:{ip}`、
  `auth:lock:{user_id}`、`auth:iplock:{ip}`）。
- 数据库：把 `AuthEventStore` 与 `UserStore` 换成 SQLAlchemy 2 模型与
  Alembic 迁移（PostgreSQL 16），auth_events 字段与本样品一致；
  用户表按统一约定含 id(UUID)、org_id、site_id、created_at、created_by、
  updated_at、deleted_at（软删除）。
- 令牌：本样品直接返回随机 `access_token`（仅 dev 免二次验证）；
  生产由 S2-IAM 令牌工单的签发逻辑替换，并按环境变量决定是否允许免二次验证。
- 依赖 S2-INFRA（云环境、CI/CD 与运维基础），本样品先用接口桩与 mock，
  不连真实云环境。

## 实测结果（2026-11-27，本机 Python 3.12.3，pytest 9.2.0）

- pytest：25 passed in 16.40s（日志：`evidence/pytest-20261127.log`）
- 变异自证：MUTATION CHECK: PASS（A 相 25 passed in 15.01s；B 相锁定阈值
  5 改成 999 后 5 failed, 20 passed in 17.77s，变红的含 AC1 用例；
  C 相恢复后 25 passed in 17.62s；
  日志：`evidence/mutation-check-20261127.log`）
- 一键复跑：`bash setup.sh` → SELFTEST: PASS
  （日志：`evidence/selftest-setup-sh-20261127.log`）
