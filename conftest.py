"""Pytest bootstrap: make the project root importable and enable logs."""
import logging
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth.logging_utils import configure_test_logging  # noqa: E402

configure_test_logging(logging.INFO)


# Business area shown in the run summary for each test module. Keyed by
# file stem so the report states which businesses were exercised.
BUSINESS_AREAS = OrderedDict([
    ("test_smoke", "组装冒烟"),
    ("test_tokens", "令牌签发/验签/密钥轮换"),
    ("test_store", "存储层原子性（刷新 claim / 一次性口令消费）"),
    ("test_mfa", "TOTP 校验 / 限流 / 锁定"),
    ("test_sessions", "登录 / 刷新轮换 / 登出生命周期"),
    ("test_reauth", "敏感操作再认证与新鲜度窗口"),
    ("test_concurrent_refresh", "并发刷新（同时提交）"),
    ("test_concurrent_sessions", "并发再认证 / 下线与刷新交错"),
    ("test_concurrent_reauth_replay",
     "一次性口令：同时提交 & 跨会话重放"),
    ("test_device_sessions", "多设备会话列举 / 单个与批量下线"),
    ("test_authz", "统一授权判定 / scope 调和"),
    ("test_http_api", "HTTP 登录刷新授权链路"),
    ("test_http_sessions", "HTTP 多设备会话 / 再认证 / 重放"),
])


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print a per-business-area coverage/result block after the run."""
    stats = terminalreporter.stats
    groups: dict[str, dict[str, int]] = {}
    for phase in ("passed", "failed", "error", "skipped"):
        for report in stats.get(phase, []):
            stem = Path(str(report.fspath)).stem
            bucket = groups.setdefault(stem, {
                "passed": 0, "failed": 0, "error": 0, "skipped": 0})
            bucket[phase] += 1

    lines = ["", "业务覆盖与结果汇总 (business coverage):"]
    for stem, label in BUSINESS_AREAS.items():
        counts = groups.get(stem)
        if not counts:
            continue
        total = sum(counts.values())
        detail = ", ".join(
            f"{phase}={counts[phase]}"
            for phase in ("passed", "failed", "error", "skipped")
            if counts[phase]
        )
        lines.append(f"  - {label:<42} {total:>2} 例 ({detail})  [{stem}]")
    terminalreporter.write_line("\n".join(lines))

