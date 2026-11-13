# 数据集选型决策(开题待核实项 A12 的考证结论)

> 考证日期:2026-11-09 ｜ 结论状态:**A12 部分证实、部分证伪,选型已调整**
> 影响:任务书/开题中"真实漏洞集用 Defects4Py"的表述需在期末报告中更正

## 一、考证结论

**"Defects4Py"作为 Python 漏洞数据集未证实存在。** 检索(2026-11-09)显示:

1. 该名字在文献中最常指 Zou 等人受 Defects4J 启发构建的 **Python 可复现缺陷**数据集——
   收录的是一般性 bug,不是安全漏洞,与本项目"污点流漏洞真值"的需求不匹配;
2. Python 侧与安全漏洞对齐的基准,可行选项为:
   - **Vul4Py**:100 个真实漏洞、60 个开源 Python 项目、覆盖约 60 类 CWE、**每个漏洞带测试套件**,
     与本项目"Python 为主 + CWE 真值 + 可执行验证"三要素最贴合;
   - **BugsInPy**:真实缺陷补丁数据集(社区熟知),但缺陷≠安全漏洞,仅可作扩展对照;
   - **PrimeVul / Big-Vul**:以 C/C++ 为主,与"审计对象以 Python 为主"不符,排除。

**决策**:受控集维持 **SARD Python 子集**(NIST,人工构造、CWE 标注);真实漏洞集由
"Defects4Py"更正为 **Vul4Py**(获取后先核实其许可证与样本许可);BugsInPy 列为可选对照。
此考证同时闭环开题附录 A12;开题为历史文件不回改,以本记录为准。

## 二、接入计划(期末周执行)

| 步骤 | 内容 | 产出 |
|---|---|---|
| D1 | 获取 Vul4Py 仓库/数据包,核实许可证与样本结构;SARD Python 子集下载 | 原始数据 + 许可证记录 |
| D2 | 真值构造:漏洞版本代码运行 SAST/LLM 通道采集候选,对照修复 commit/测试套件标注 | alert 级 ground-truth |
| D3 | `python -m auditor.dataset build-manifest` 生成 dataset_manifest.json(含过滤规则与前后样本数) | 清单(S2 产物) |
| D4 | 抽样(固定种子)→ 现有流水线直接消费(候选 schema 与 SAST/LLM 通道一致) | E1/E3 数据 |

## 三、脚手架现状

`auditor/dataset.py` 已提供清单构建器(对任意目录生成符合任务书 S2 口径的
dataset_manifest.json),演示样本清单已生成于 `records/dataset_manifest.json`;
SARD/Vul4Py 的下载器待 D1 落地(命令与 URL 以官方页面为准,不预先猜测)。
