#!/usr/bin/env bash
# 由 auditor.orchestrator prepare 生成;执行容器内 harness。
set -u
# Git Bash 会把 /work 改写为 Windows 路径,此变量在 Linux 上无副作用
export MSYS_NO_PATHCONV=1
docker image inspect --format "{{.Id}}" php:8.2-cli > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001/image_id.txt" 2>/dev/null; docker run --rm -v "D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001:/work" -w /work php:8.2-cli php harness.php > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001/stdout.txt" 2> "D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001/stderr.txt"; echo $? > "D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001/exit_code.txt"
echo "sandbox step done"
