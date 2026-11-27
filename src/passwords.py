"""口令哈希与校验（S2-IAM-005 样品，纯标准库）。

只用虚构测试口令，不含任何真实个人信息。
"""

from __future__ import annotations

import hashlib
import hmac
import os

_ITERATIONS = 100_000

_DUMMY_SALT = bytes.fromhex("00" * 16)
_DUMMY_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"dummy-nonexistent-account", _DUMMY_SALT, _ITERATIONS
).hex()


def hash_password(password: str, salt: bytes | None = None) -> str:
    """生成存储用哈希：pbkdf2$<salt hex>$<digest hex>。"""
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return "pbkdf2$%s$%s" % (salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    """用常数时间比较校验口令；存储串损坏时返回 False，不抛错。"""
    try:
        algo, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), _ITERATIONS
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def dummy_verify(password: str) -> bool:
    """账号不存在时也做一次等价哈希比较，使耗时接近真实校验。

    调用方忽略返回值，一律按失败处理；本函数恒返回 False。
    """
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _DUMMY_SALT, _ITERATIONS
    )
    hmac.compare_digest(digest.hex(), _DUMMY_HASH)
    return False
