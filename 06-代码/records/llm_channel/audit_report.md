# 审计报告(中期演示)

- 运行编号:llmreal
- 告警总数:3
- 判定分布:TP=3, FP=0, 未确认=0

## A-001(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次 execute 调用),且未使用参数化绑定——污点数据未净化即进入 SQL 语句,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/llm_channel/run_llmreal/A-001:/work -w /work python:3.12-slim python harness.py

## A-002(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次 execute 调用),且未使用参数化绑定——污点数据未净化即进入 SQL 语句,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/llm_channel/run_llmreal/A-002:/work -w /work python:3.12-slim python harness.py

## L-001(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次 execute 调用),且未使用参数化绑定——污点数据未净化即进入 SQL 语句,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/llm_channel/run_llmreal/L-001:/work -w /work python:3.12-slim python harness.py
