# 审计报告(中期演示)

- 运行编号:llmmock
- 告警总数:5
- 判定分布:TP=5, FP=0, 未确认=0

## A-001(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次调用被拦截),且未净化——污点数据未处理即进入危险操作,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/run_llmmock/A-001:/work -w /work python:3.12-slim python harness.py

## A-002(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次调用被拦截),且未净化——污点数据未处理即进入危险操作,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/run_llmmock/A-002:/work -w /work python:3.12-slim python harness.py

## L-001(CWE-22)
- 判定:**TP** —— payload 已到达 sink(共 1 次调用被拦截),且未净化——污点数据未处理即进入危险操作,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/run_llmmock/L-001:/work -w /work python:3.12-slim python harness.py

## L-002(CWE-78)
- 判定:**TP** —— payload 已到达 sink(共 1 次调用被拦截),且未净化——污点数据未处理即进入危险操作,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/run_llmmock/L-002:/work -w /work python:3.12-slim python harness.py

## L-003(CWE-89)
- 判定:**TP** —— payload 已到达 sink(共 1 次调用被拦截),且未净化——污点数据未处理即进入危险操作,漏洞成立
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/run_llmmock/L-003:/work -w /work python:3.12-slim python harness.py
