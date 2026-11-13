# -*- coding: utf-8 -*-
"""SWE-ReX 冒烟测试(限时探针)。

验证 swe-rex 包可导入、DockerDeployment 可构造,并尝试在隔离容器中
执行一条命令。注意:本会话的沙箱策略不允许 Python 子进程访问 Docker
命名管道,若 execute 失败于 pipe 权限,则记录为"环境受限"而非
"SWE-ReX 不可用"。
"""
import asyncio
import os
import sys
import traceback

import swerex

# 运行镜像可覆盖：默认官方 python:3.12-slim；本机因容器内无法访问 pypi.org，
# 改用预装 swe-rex 的自建镜像（见 docker/swerex.Dockerfile）。
IMAGE = os.environ.get("SWEREX_IMAGE", "python:3.12-slim")


async def main() -> int:
    print("swerex version:", getattr(swerex, "__version__", "?"))
    print("image:", IMAGE)
    print("DOCKER_HOST:", os.environ.get("DOCKER_HOST", "(默认,命名管道)"))
    try:
        from swerex.deployment.docker import DockerDeployment  # noqa: F401
        print("import DockerDeployment: ok")
    except Exception as exc:
        print("import DockerDeployment: FAIL", exc)
        return 1

    try:
        d = DockerDeployment(image=IMAGE)
        await d.start()
        r = d.runtime
        # swe-rex 1.4.0 API：execute() 接收 Command 模型（不是字符串）；
        # 含 shell 语法（&&）需 shell=True。
        from swerex.runtime.abstract import Command
        out = await r.execute(
            Command(command="echo hello-swerex && python -V", shell=True)
        )
        print("execute stdout:", (out.stdout or "").strip()[:200])
        print("execute exit_code:", getattr(out, "exit_code", "?"))
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
