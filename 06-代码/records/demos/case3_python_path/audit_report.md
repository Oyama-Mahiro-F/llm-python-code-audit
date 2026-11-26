# 审计报告

- 运行编号:demo_case3_python_path
- 告警总数:1
- 判定分布:TP=1, FP=0, 未确认=0

## L-001 · Python 路径穿越 / CWE-22
- 判定:**TP**(模式 A)
- 具体描述:Python 路径穿越(CWE-22):report_reader.py:18,所属函数 read_report()。污点源:report_name 参数（外部可控输入）(候选来自LLM 候选发现通道)。传播:第 17 行 `path = REPORT_DIR + "/" + report_name`,外部输入未经净化即拼接进危险调用的参数。危险操作点:第 18 行 `with open(path) as f:`,执行危险调用 builtins.open。沙箱截获的实际实参:`/var/app/reports/../../etc/passwd`,payload `../../etc/passwd` 已到达危险操作点。payload 原样出现在 builtins.open 的实参中且未见净化处理(无 sanitized 标记、无参数绑定),污点路径被执行证实 → 已确认(TP)。CVE 参照:CVE-2007-4559(Python tarfile 模块的 extract/extractall 存在目录穿越,可覆盖任意文件;CWE-22;NVD 链接见下方)
- 截获实参:`/var/app/reports/../../etc/passwd`
- CVE 参照:[CVE-2007-4559](https://nvd.nist.gov/vuln/detail/CVE-2007-4559) — Python tarfile 模块的 extract/extractall 存在目录穿越,可覆盖任意文件
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case3_python_path/run_demo_case3_python_path/L-001:/work -w /work python:3.12-slim python harness.py
