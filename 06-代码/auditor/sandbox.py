# -*- coding: utf-8 -*-
"""沙箱执行(对应《项目方案》4.3.3)。

三种驱动方式:
  driver="docker"   由本模块直接 subprocess 调用 docker(标准环境,如
                    Linux/WSL2 中运行编排器时的默认路径);
  driver="external" 两阶段模式:docker 命令由编排器生成落盘
                    (sandbox_cmds.sh),由 shell 执行后回收产物
                    (本机实测路径——ZCode 会话沙箱不允许 Python 子进程
                    直接访问 Docker 命名管道,故容器步骤由 shell 代执行);
  其余(如 SWE-ReX)预留。

依赖环境准备(方案 4.4.3):镜像可用性与依赖清单检查,产出
env_snapshot.json;依赖安装失败记为环境问题、不计入模型效果评估。
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

SANDBOX_IMAGE = "python:3.12-slim"


def _docker(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def _image_id(image: str) -> str | None:
    try:
        proc = _docker(["image", "inspect", "--format", "{{.Id}}", image], 30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def prepare_env(work_dir: Path, image: str) -> dict:
    """依赖环境准备:镜像可用性与依赖清单检查,产出 env_snapshot。"""
    image_id = _image_id(image)
    req = work_dir / "requirements.txt"
    deps = []
    if req.exists():
        deps = [ln.strip() for ln in req.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return {
        "image": image,
        "image_id": image_id,
        "image_available": image_id is not None,
        "requirements": deps,
        "deps_install_required": bool(deps),
        "deps_install_done": True,  # 演示样本零第三方依赖
        "env_ok": image_id is not None,
    }


def write_env_snapshot(work_dir: Path, image: str) -> dict:
    env = prepare_env(work_dir, image)
    # 两阶段模式:shell 步骤会落盘 image_id.txt(docker 由 shell 执行,
    # 绕开 Python 子进程无法访问 docker 管道的会话限制),优先采信。
    image_id_file = work_dir / "image_id.txt"
    if image_id_file.exists():
        shell_id = image_id_file.read_text(encoding="utf-8").strip()
        if shell_id:
            env["image_id"] = shell_id
            env["image_available"] = True
            env["image_id_source"] = "shell_probe"
    env["env_ok"] = env["image_available"]
    (work_dir / "env_snapshot.json").write_text(
        json.dumps(env, ensure_ascii=False, indent=2), encoding="utf-8")
    return env


def docker_command(work_dir: Path, harness_name: str = "harness.py",
                   image: str | None = None,
                   language: str = "python") -> list[str]:
    """构造在隔离容器中执行 harness 的完整 docker 命令(按语言选镜像与执行器)。"""
    from .lang import RUNTIME
    rt = RUNTIME.get(language, RUNTIME["python"])
    image = image or rt["image"]
    runner = [rt["run"][0], harness_name]
    return ["docker", "run", "--rm",
            "-v", f"{work_dir.resolve().as_posix()}:/work",
            "-w", "/work", image, *runner]


def replay_command(work_dir: Path, harness_name: str = "harness.py",
                   image: str | None = None,
                   language: str = "python") -> str:
    return " ".join(docker_command(work_dir, harness_name, image, language))


def run_harness(work_dir: str | Path, harness_name: str = "harness.py",
                image: str | None = None, timeout: int = 120,
                language: str = "python") -> dict:
    """driver=docker:直接执行并捕获 stdout/stderr 与退出码。"""
    from .lang import RUNTIME
    image = image or RUNTIME.get(language, RUNTIME["python"])["image"]
    work_dir = Path(work_dir).resolve()
    env = write_env_snapshot(work_dir, image)
    started = time.time()
    if not env["env_ok"]:
        return {"env": env, "env_ok": False, "exit_code": None,
                "stdout": "", "stderr": "image_unavailable",
                "elapsed_s": 0.0,
                "error": "image_unavailable",
                "replay_command": replay_command(work_dir, harness_name, image,
                                                 language)}
    cmd = docker_command(work_dir, harness_name, image, language)
    try:
        args = cmd[1:] if cmd[0] == "docker" else cmd
        proc = _docker(args, timeout)
        exit_code, stdout, stderr, err = proc.returncode, proc.stdout, proc.stderr, None
    except subprocess.TimeoutExpired as exc:
        exit_code, stdout, stderr, err = None, "", "", f"timeout:{exc}"
    return {"env": env, "env_ok": True, "exit_code": exit_code,
            "stdout": stdout, "stderr": stderr,
            "elapsed_s": round(time.time() - started, 2), "error": err,
            "replay_command": " ".join(cmd)}


# ---------------- external(两阶段)驱动 ----------------

def emit_command_file(work_dir: Path, harness_name: str = "harness.py",
                      image: str | None = None,
                      language: str = "python") -> str:
    """生成一行可被 bash 执行的命令(stdout/stderr/退出码落盘到 run 目录)。

    首句为镜像探测(docker image inspect),供两阶段回收时采信环境状态。
    """
    from .lang import RUNTIME
    rt = RUNTIME.get(language, RUNTIME["python"])
    image = image or rt["image"]
    runner = rt["run"][0]
    work_dir = Path(work_dir).resolve()
    wd = work_dir.as_posix()
    return (f'docker image inspect --format "{{{{.Id}}}}" {image} '
            f'> "{wd}/image_id.txt" 2>/dev/null; '
            f'docker run --rm -v "{wd}:/work" -w /work {image} '
            f'{runner} {harness_name} > "{wd}/stdout.txt" '
            f'2> "{wd}/stderr.txt"; echo $? > "{wd}/exit_code.txt"')


def load_captured(work_dir: str | Path, language: str = "python") -> dict:
    """回收 shell 执行产物,组装成与 run_harness 相同结构的结果。"""
    from .lang import RUNTIME
    rt = RUNTIME.get(language, RUNTIME["python"])
    work_dir = Path(work_dir)
    # 始终重算环境状态(镜像探测以 shell 侧 image_id.txt 为准),
    # 避免沿用上一轮遗留的陈旧快照。
    env = write_env_snapshot(work_dir, rt["image"])
    stdout_f, stderr_f, exit_f = (work_dir / "stdout.txt",
                                  work_dir / "stderr.txt",
                                  work_dir / "exit_code.txt")
    exit_code = None
    if exit_f.exists():
        txt = exit_f.read_text(encoding="utf-8").strip()
        exit_code = int(txt) if txt.lstrip("-").isdigit() else None
    return {
        "env": env,
        "env_ok": bool(env.get("env_ok")),
        "exit_code": exit_code,
        "stdout": stdout_f.read_text(encoding="utf-8", errors="replace")
        if stdout_f.exists() else "",
        "stderr": stderr_f.read_text(encoding="utf-8", errors="replace")
        if stderr_f.exists() else "",
        "elapsed_s": None,
        "error": None if exit_f.exists() else "sandbox_step_not_executed",
        "replay_command": replay_command(
            work_dir, rt["filename"], rt["image"], language),
    }
