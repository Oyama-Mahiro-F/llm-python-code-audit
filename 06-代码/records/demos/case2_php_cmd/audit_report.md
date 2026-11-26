# 审计报告

- 运行编号:demo_case2_php_cmd
- 告警总数:1
- 判定分布:TP=1, FP=0, 未确认=0

## A-001 · PHP OS 命令注入 / CWE-78
- 判定:**TP**(模式 A)
- 具体描述:PHP OS 命令注入(CWE-78):ping.php:14,所属函数 ping_host()。污点源:$host 形参(候选来自SAST 规则扫描)。传播:第 13 行 `$cmd = "ping -c 1 " . $host;`,外部输入未经净化即拼接进危险调用的参数。危险操作点:第 14 行 `$output = shell_exec($cmd);`,执行危险调用 shell_exec。沙箱截获的实际实参:`ping -c 1 127.0.0.1; echo zxq-demo-marker`,payload `127.0.0.1; echo zxq-demo-marker` 已到达危险操作点。payload 原样出现在 shell_exec 的实参中且未见净化处理(无 sanitized 标记、无参数绑定),污点路径被执行证实 → 已确认(TP)。CVE 参照:CVE-2019-9194(elFinder < 2.1.48 的 PHP connector 存在命令注入;CWE-78;NVD 链接见下方)
- 截获实参:`ping -c 1 127.0.0.1; echo zxq-demo-marker`
- CVE 参照:[CVE-2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194) — elFinder < 2.1.48 的 PHP connector 存在命令注入
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case2_php_cmd/run_demo_case2_php_cmd/A-001:/work -w /work php:8.2-cli php harness.php
