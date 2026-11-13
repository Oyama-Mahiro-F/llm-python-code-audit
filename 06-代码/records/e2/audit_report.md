# 审计报告(中期演示)

- 运行编号:e2_retry_demo
- 告警总数:5
- 判定分布:TP=5, FP=0, 未确认=0

## A-001(CWE-89)
- 判定:**TP** —— payload 原样拼入 SQL 并到达 sqlite3.Cursor.execute，sanitized 为 false，构成 SQL 注入。
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/e2/run_e2_retry_demo/A-001:/work -w /work python:3.12-slim python harness.py

## A-002(CWE-89)
- 判定:**TP** —— payload 原样拼入 SQL 并到达 sqlite3.Cursor.execute，sanitized 为 false，构成 SQL 注入。
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/e2/run_e2_retry_demo/A-002:/work -w /work python:3.12-slim python harness.py

## L-001(CWE-22)
- 判定:**TP** —— payload ../../etc/passwd-zxq-demo-marker 经字符串拼接到达 builtins.open，路径穿越未被拦截，构成路径穿越漏洞
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/e2/run_e2_retry_demo/L-001:/work -w /work python:3.12-slim python harness.py

## L-002(CWE-78)
- 判定:**TP** —— payload 中的 shell 元字符经字符串拼接进入 os.system，捕获到的调用为 "ls zxq-demo-marker; echo pwned"，证明命令注入已到达危险 sink。
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/e2/run_e2_retry_demo/L-002:/work -w /work python:3.12-slim python harness.py

## L-003(CWE-89)
- 判定:**TP** —— payload 原样拼入 SQL 并到达 sqlite3.Cursor.execute，sanitized 为 false，构成 SQL 注入。
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/e2/run_e2_retry_demo/L-003:/work -w /work python:3.12-slim python harness.py
