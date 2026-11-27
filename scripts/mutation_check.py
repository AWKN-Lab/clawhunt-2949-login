#!/usr/bin/env python3
"""变异自证（S2-IAM-005）：证明测试真的能抓住实现错误。

A 相：原实现跑 pytest，全过。
B 相：把实现改坏一处（连续失败锁定阈值 5 改成 999，等于取消锁定），
     跑 pytest 必须变红，且变红的须包含 AC1 用例。
C 相：恢复原实现，跑 pytest，全过；并核对 auth_service.py 的 SHA256
     与变异前后一致（文件已恢复原样）。

任一相不符即 exit 1。为不污染源文件，B 相用复制到临时目录的副本跑测试，
C 相直接跑原文件。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "auth_service.py"
TESTS = ROOT / "tests"

# 跑 pytest 用的解释器：setup.sh 透传 TEST_PY（能 import pytest 的那个）；
# 直接跑本脚本时默认用当前解释器。相对路径按仓库根目录解析成绝对路径，
# 否则 B 相切到临时目录后就找不到解释器。
_TEST_PY = os.environ.get("TEST_PY", sys.executable)
if not os.path.isabs(_TEST_PY) and (ROOT / _TEST_PY).exists():
    # 只取绝对路径，不用 Path.resolve()：.venv/bin/python 是指向系统解释器的
    # 符号链接，resolve 会把它还原成 /usr/bin/python3.12，那就丢了 venv 的包。
    _TEST_PY = os.path.abspath(ROOT / _TEST_PY)
TEST_PY = _TEST_PY


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_pytest(cwd: Path, tests_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    return subprocess.run(
        [TEST_PY, "-m", "pytest", "-q", str(tests_dir)],
        cwd=str(cwd), capture_output=True, text=True, env=env, timeout=300,
    )


def main() -> int:
    orig_sha = sha256(SRC)
    print("original SHA256: %s" % orig_sha)

    print("=== A 相：原实现 ===")
    a = run_pytest(ROOT, TESTS)
    print(a.stdout.strip().splitlines()[-1] if a.stdout.strip() else a.stderr.strip())
    if a.returncode != 0:
        print("A 相失败：原实现测试未全过")
        return 1

    print("=== B 相：变异（锁定阈值 5 改成 999）===")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "src").mkdir()
        mutated = SRC.read_text()
        assert "MAX_FAILURES = 5" in mutated
        mutated = mutated.replace("MAX_FAILURES = 5", "MAX_FAILURES = 999")
        (tmp / "src" / "auth_service.py").write_text(mutated)
        # src 其余文件与 tests 一起拷进临时目录：测试用自身相对路径找 src，
        # 不拷的话 B 相仍会 import 原实现，变异就测不出来。
        for name in ("auth_events.py", "fake_redis.py", "passwords.py", "__init__.py"):
            shutil.copy2(ROOT / "src" / name, tmp / "src" / name)
        shutil.copytree(TESTS, tmp / "tests")
        b = run_pytest(tmp, tmp / "tests")
        tail = (b.stdout.strip().splitlines() or [""])[-1]
        print(tail)
        if b.returncode == 0:
            print("B 相失败：变异后测试仍全过，测试抓不住实现错误")
            return 1
        if "test_ac1" not in b.stdout and "test_ac1" not in b.stderr:
            print("B 相失败：变红的用例里没有 AC1 用例")
            return 1
        print("B 相变红用例含 AC1，符合预期")

    print("=== C 相：恢复后复跑 ===")
    c = run_pytest(ROOT, TESTS)
    print(c.stdout.strip().splitlines()[-1] if c.stdout.strip() else c.stderr.strip())
    if c.returncode != 0:
        print("C 相失败：恢复后测试未全过")
        return 1
    if sha256(SRC) != orig_sha:
        print("C 相失败：源文件 SHA256 变了，未恢复原样")
        return 1
    print("源文件 SHA256 变异前后一致：%s" % orig_sha)
    print("MUTATION CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
