# 三个可明确演示的案例

> 对应老师 2026-11-22 反馈第 3 条:"我需要 3 个能够明确演示的例子,比如 php 漏洞"
> 每个案例都是**可独立运行的最小项目**:一个源文件 + 一条候选告警 + 完整证据链 +
> 经 NVD 核验的真实 CVE 参照。

## 一览

| 案例 | 语言 | 漏洞类型 | 候选来源 | 真实 CVE 参照 | 判定 |
|---|---|---|---|---|---|
| `case1_php_sqli` | PHP | SQL 注入(CWE-89) | **LLM 候选发现通道** | [CVE-2019-15573](https://nvd.nist.gov/vuln/detail/CVE-2019-15573)(CVSS 9.8) | TP |
| `case2_php_cmd` | PHP | OS 命令注入(CWE-78) | **SAST 规则扫描**(p/default) | [CVE-2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194) | TP |
| `case3_python_path` | Python | 路径穿越(CWE-22) | **LLM 候选发现通道** | [CVE-2007-4559](https://nvd.nist.gov/vuln/detail/CVE-2007-4559) | TP |

**这组案例本身就在说明系统的价值**:三个案例中有两个(`case1`、`case3`)Semgrep 官方
规则集(`p/default`、`p/php`、`p/security-audit`、`p/owasp-top-ten`)**全部零命中**,
只靠 SAST 会漏掉;而 LLM 通道找到后,仍必须通过沙箱动态验证才被采纳——**发现通道
拓宽召回,验证环节守住精度**。

## 每个案例的演示要点

### case1:PHP SQL 注入
- 代码事实:`$user` 经 `.` 拼接进 `$sql`(第 14 行),第 15 行交给 `mysqli_query`;
- 沙箱截获实参:`SELECT id, name FROM users WHERE name = 'zxq-demo-marker' OR '1'='1'`;
- 为什么是漏洞:外部输入原样进入 SQL 语句且未参数化 → 可闭合引号改变查询语义;
- 同类真实漏洞:Gesior-AAC `tankyou.php`(CVE-2019-15573)。

### case2:PHP 命令注入
- 代码事实:`$host` 经 `.` 拼接进 `$cmd`(第 13 行),第 14 行交给 `shell_exec`;
- 沙箱截获实参:`ping -c 1 127.0.0.1; echo zxq-demo-marker`(分号后即任意命令);
- 为什么是漏洞:shell 元字符未过滤,payload 可追加新命令;
- 同类真实漏洞:elFinder PHP connector(CVE-2019-9194)、php-shellcommand(CVE-2019-10774);
- CWE 说明:Semgrep 该规则 metadata 记为 CWE-94(代码注入),本项目按显式规则归一为
  CWE-78(OS 命令注入),原始值保留在告警的 `cwe_reported` 字段——见
  `auditor/sast_scan.py::CWE_NORMALIZE_RULES`。

### case3:Python 路径穿越
- 代码事实:`report_name` 经 `+` 拼接进 `path`(第 17 行),第 18 行交给 `open`;
- 沙箱截获实参:`/var/app/reports/../../etc/passwd`;
- 为什么是漏洞:`../` 序列跳出预期目录,可读任意文件;未做 `realpath` 规范化与白名单;
- 同类真实漏洞:Python `tarfile` 的 `extract/extractall`(CVE-2007-4559);
- 附带演示:模块级常量 `REPORT_DIR` 被 Extract 一并提取(否则 harness 会 NameError)。

## 复现(以 case1 为例)

```bash
cd 06-代码
PY=.venv/Scripts/python.exe

# 1) 候选(已落盘;重跑需 DEEPSEEK_API_KEY,或复用 records/demos/case1_php_sqli/llm_candidates.json)
$PY -m auditor.llm_discover --project demos/case1_php_sqli \
    --out records/demos/case1_php_sqli/llm_candidates.json \
    --backend replay --replay-file records/demos/case1_php_sqli/llm_replay/llm_replay.json

# 2) 编排·提取 + 模板 mock + 组装
$PY -m auditor.orchestrator prepare --alerts records/demos/case1_php_sqli/llm_candidates.json \
    --project demos/case1_php_sqli --run-id demo_case1_php_sqli \
    --out records/demos/case1_php_sqli --mock-backend template

# 3) 容器内执行(标准终端可直连 docker;受限环境由 shell 代执行)
bash records/demos/case1_php_sqli/run_demo_case1_php_sqli/sandbox_cmds.sh

# 4) 判定 + 报告(含具体描述与 CVE 参照)
$PY -m auditor.orchestrator collect --alerts records/demos/case1_php_sqli/llm_candidates.json \
    --project demos/case1_php_sqli --run-id demo_case1_php_sqli \
    --out records/demos/case1_php_sqli
cat records/demos/case1_php_sqli/audit_report.md
```

## 样本设计约定(重要)

1. **被测函数第一个形参接收外部输入**——harness 以 payload 作为第一个实参调用;
   真实代码中该值来自 `$_GET` / `$_POST` / HTTP 参数,案例里用注释标明;
2. **PHP 顶层赋值不提取**——所以案例把连接等依赖写成函数内局部变量;
3. **PHP 的 mock 采用"接缝重定向"**——PHP 内建函数无法重定义,harness 在组装期把
   `mysqli_query(` / `shell_exec(` 改写为 `__mock_*`,改写次数记录在
   `harness_meta.json::redirects_applied`,可审计;
4. 案例代码为**自建的最小复现**,不是任何真实项目的源码;真实 CVE 仅作为
   "同类漏洞在真实世界长什么样"的参照,并标注 NVD 链接。
