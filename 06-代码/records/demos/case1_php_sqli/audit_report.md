# 审计报告

- 运行编号:demo_case1_php_sqli
- 告警总数:1
- 判定分布:TP=1, FP=0, 未确认=0

## L-001 · PHP SQL 注入 / CWE-89
- 判定:**TP**(模式 A)
- 具体描述:PHP SQL 注入(CWE-89):user_login.php:15,所属函数 login_check()。污点源:函数参数 $user(外部可控输入)(候选来自LLM 候选发现通道)。传播:第 14 行 `$sql = "SELECT id, name FROM users WHERE name = '" . $user . "'";`,外部输入未经净化即拼接进危险调用的参数。危险操作点:第 15 行 `$res = mysqli_query($conn, $sql);`,执行危险调用 mysqli_query。沙箱截获的实际实参:`SELECT id, name FROM users WHERE name = 'zxq-demo-marker' OR '1'='1'`,payload `zxq-demo-marker' OR '1'='1` 已到达危险操作点。payload 原样出现在 mysqli_query 的实参中且未见净化处理(无 sanitized 标记、无参数绑定),污点路径被执行证实 → 已确认(TP)。CVE 参照:CVE-2019-15573(Gesior-AAC 的 tankyou.php 存在 SQL 注入:用户可控输入未加处理即拼入 SQL 语句;CWE-89,CVSS 9.8 CRITICAL;NVD 链接见下方)
- 截获实参:`SELECT id, name FROM users WHERE name = 'zxq-demo-marker' OR '1'='1'`
- CVE 参照:[CVE-2019-15573](https://nvd.nist.gov/vuln/detail/CVE-2019-15573) — Gesior-AAC 的 tankyou.php 存在 SQL 注入:用户可控输入未加处理即拼入 SQL 语句
- 复现命令:docker run --rm -v D:/university_learning/4.1/信息安全工程概论/06-代码/records/demos/case1_php_sqli/run_demo_case1_php_sqli/L-001:/work -w /work php:8.2-cli php harness.php
