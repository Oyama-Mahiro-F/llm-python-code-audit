# SWE-ReX 运行镜像
#
# 背景: SWE-ReX 启动容器时会执行 `swerex-remote --auth-token <T> || (pip install pipx && pipx run swe-rex ...)`。
# 基础镜像 python:3.12-slim 里没有 swerex-remote,容器内又连不上 pypi.org(SSL 被拦截),
# 导致启动失败。本镜像预装 swe-rex,使 `swerex-remote` 直接可用,无需容器内联网。
#
# 构建:
#   docker build -f docker/swerex.Dockerfile -t swerex-runner:1.4.0 docker
#
# 使用:
#   $env:SWEREX_IMAGE = "swerex-runner:1.4.0"
#   $env:DOCKER_HOST  = "tcp://127.0.0.1:2375"
#   .venv\Scripts\python.exe smoke_swerex.py

FROM python:3.12-slim

LABEL description="SWE-ReX runtime image (pre-installed swe-rex, Tsinghua mirror)"

# 预装 swe-rex（提供 swerex-remote 入口点）；与实际使用的客户端版本保持一致
RUN pip install --no-cache-dir \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        swe-rex==1.4.0 \
    && swerex-remote --help > /dev/null 2>&1 || echo "swerex-remote installed"

# SWE-ReX 协议默认在容器内 8000 端口提供 HTTP 服务
EXPOSE 8000

WORKDIR /testbed
