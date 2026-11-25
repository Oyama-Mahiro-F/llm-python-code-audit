"""演示案例 3:Python 路径穿越(CWE-22)

对应真实漏洞:CVE-2007-4559 — Python tarfile 模块 extract/extractall 路径穿越
  NVD: https://nvd.nist.gov/vuln/detail/CVE-2007-4559
漏洞模式:外部输入拼进文件路径,未做规范化(os.path.realpath)与目录约束,
          `../` 序列可跳出预期目录读取任意文件。

说明:第一个形参接收外部输入(真实代码中来自 HTTP 参数 report_name)。
      模块级常量 REPORT_DIR 用于演示 Extract 的"被引用常量一并提取"能力。
"""
import os

REPORT_DIR = "/var/app/reports"


def read_report(report_name):
    path = REPORT_DIR + "/" + report_name
    with open(path) as f:
        return f.read()


def list_reports():
    return os.listdir(REPORT_DIR)
