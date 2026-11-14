#!/usr/bin/env bash
# 由 auditor.orchestrator prepare 生成;执行容器内 harness。
set -u
# Git Bash 会把 /work 改写为 Windows 路径,此变量在 Linux 上无副作用
export MSYS_NO_PATHCONV=1
docker image inspect --format "{{.Id}}" python:3.12-slim > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/case_L002/run_case3/L-002/image_id.txt" 2>/dev/null; docker run --rm -v "D:/university_learning/4.1/信息安全工程概论/06-代码/records/case_L002/run_case3/L-002:/work" -w /work python:3.12-slim python harness.py > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/case_L002/run_case3/L-002/stdout.txt" 2> "D:/university_learning/4.1/信息安全工程概论/06-代码/records/case_L002/run_case3/L-002/stderr.txt"; echo $? > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/case_L002/run_case3/L-002/exit_code.txt"
echo "sandbox step done"
