# -*- coding: utf-8 -*-
"""SWE-ReX 冒烟测试(限时探针)。

验证 swe-rex 包可导入、DockerDeployment 可构造,并尝试在隔离容器中
执行一条命令。注意:本会话的沙箱策略不允许 Python 子进程访问 Docker
命名管道,若 execute 失败于 pipe 权限,则记录为"环境受限"而非
"SWE-ReX 不可用"。
"""
import asyncio
import sys
import traceback

import swerex


async def main() -> int:
    print("swerex version:", getattr(swerex, "__version__", "?"))
    try:
        from swerex.deployment.docker import DockerDeployment  # noqa: F401
        print("import DockerDeployment: ok")
    except Exception as exc:
        print("import DockerDeployment: FAIL", exc)
        return 1

    try:
        d = DockerDeployment(image="python:3.12-slim")
        await d.start()
        r = d.runtime
        out = await r.execute("echo hello-swerex && python -V")
        print("execute stdout:", (out.stdout or "").strip()[:200])
        await d.stop()
        print("SWE_REX_SMOKE: OK")
        return 0
    except Exception as exc:
        print("SWE_REX_SMOKE: FAIL")
        print("type:", type(exc).__name__)
        print("detail:", str(exc)[:400])
        traceback.print_exc(limit=2)
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
