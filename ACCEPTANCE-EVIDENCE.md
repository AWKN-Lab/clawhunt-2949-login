# 验收证据（S2-IAM-005，ClawHunt #2949）

实测环境：本机 Python 3.12.3，pytest 9.2.0，纯标准库实现，未连真实库与真实 Redis。
测试数据全部虚构。原始日志见 `evidence/`。

## AC1 — 连续 5 次错误密码后第 6 次返回 423 并带剩余秒数（测试断言）

测试：`test_ac1_five_wrong_then_sixth_423`

```text
25 passed in 16.40s（全量，含本用例）
```

用例做法：同一账号连错 5 次口令均返回 401，第 6 次返回 423，
`retry_after_seconds` 大于 0 且不大于 900（LOCK_SECONDS）。
另有 `test_ac1_lock_expires_then_login_ok`（锁过期后正确口令可登录）与
`test_ac1_remaining_seconds_decrease`（剩余秒数随时间递减 60 秒）。

## AC2 — 账号不存在与密码错误返回完全相同的状态码与文案（测试断言）

测试：`test_ac2_unknown_vs_wrong_password_identical`

```text
status_a == status_b == 401
body_a == body_b == {"detail": "账号或密码错误"}
```

账号不存在时也执行一次假哈希比较（`passwords.dummy_verify`），使耗时接近。

## AC3 — 同一 challenge_id 第二次使用返回 401（测试断言）

测试：`test_ac3_challenge_second_use_401`（TOTP 分支）、
`test_ac3_challenge_second_use_401_must_change`（须改密分支）

```text
首次 verify_challenge(challenge_id) is True
第二次 verify_challenge(challenge_id) is False（对应接口层返回 401）
```

challenge 存 Redis（`auth:challenge:{id}`），5 分钟过期，只能使用一次；
过期用例见 `test_challenge_expires_after_ttl`。

## AC4 — auth_events 中可查到成功与失败记录，且没有任何密码字段

测试：`test_ac4_events_success_and_failure_no_password_field`、
`test_ac4_event_query_filters`

```text
成功登录 1 次 + 失败 2 次后，events 共 3 条：
result == "success" 的记录存在，result == "failure" 的记录存在；
每条事件的键恰为 9 个字段
(id、org_id、user_id、event_type、result、reason_code、ip、user_agent、created_at)，
无 password 键，且 JSON 里不含测试口令值。
```

注：`reason_code` 的值 `wrong_password` 是原因码，不是口令字段。

## 全量测试与变异自证

```text
pytest：25 passed in 16.40s（evidence/pytest-20261127.log）
变异自证：MUTATION CHECK: PASS
  A 相：25 passed in 15.01s
  B 相：锁定阈值 5 改成 999 后 5 failed, 20 passed in 17.77s，变红的含 AC1 用例
  C 相：恢复后 25 passed in 17.62s，auth_service.py SHA256 变异前后一致
  （evidence/mutation-check-20261127.log）
一键复跑：bash setup.sh → SELFTEST: PASS
  （evidence/selftest-setup-sh-20261127.log）
```

## 未执行（诚实记录）

- 真实 FastAPI 服务、PostgreSQL 16 迁移、真实 Redis、OpenAPI 文档截图：
  本样品是纯标准库逻辑层，未起真实服务；生产集成时按 README 对接点
  换真实件并补截图，不冒充已跑通。
- 真实云环境（S2-INFRA 依赖）：须客户云账号与 CI/CD 基础，见 README。
