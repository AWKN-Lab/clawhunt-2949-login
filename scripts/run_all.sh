#!/usr/bin/env bash
# 跑全部测试（供 CI 与本地复核用）。
set -u
cd "$(dirname "$0")/.."
python3 -m pytest -q tests
