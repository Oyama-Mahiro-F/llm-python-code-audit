# 06-代码 · 基于大语言模型的 Python 代码审计系统

> 对应《项目方案》4.3 动态验证模块与开题 4.6 接口契约。
> **当前状态(2026-11-06):动态验证链路 + LLM 双通道全部实测跑通**——
>
> - 10/29:SAST 候选 → Extract → 模板 Mock → Docker 沙箱 → 模式 A 判定,2 条 CWE-89 → **TP×2**;
> - 10/30:`llm_discover` 第二候选来源接入(真实 DeepSeek),合并验证 **TP=3**;
> - 11/6:**mock 生成接入 LLM**——SAST 2 条 + LLM 候选 3 条(含无模板的 CWE-78/CWE-22),
>   5 条告警全部由 LLM 生成 mock 并通过输出校验,沙箱复现 **TP=5 / FP=0 / 未确认=0**
>   (LLM 调用 5 次全部入账),详见第七节;
> - 11/9:**模式 B(LLM 日志推理判定)实现 + E2 消融四配置跑通**——模式 B 带三道确定性
>   护栏,实测抓到模式 A 放过的一个证据弱点并经重试闭环修复确认;数据集选型考证完成
>   (A12:Defects4Py 证伪 → Vul4Py),见第八节与 `05-实验步骤/数据集选型决策`。

## 一、运行环境

| 项 | 值 |
|---|---|
| Python | CPython 3.12.13(uv 管理,`.venv`) |
| tree-sitter / tree-sitter-python | 0.26.0 / 0.26.x |
| swe-rex(SWE-ReX) | 1.4.0(见"四、接入状态") |
| Semgrep | 1.182.1,**官方容器** `semgrep/semgrep:latest` 内执行 |
| 沙箱运行时镜像 | `python:3.12-slim`(Docker Engine 29.5.3 + WSL2) |
| 规则集 | `p/default`(官方默认配置,未针对基准调优) |

版本快照见 `records/env.json`(步骤 S1 产物)。

## 二、目录结构

```
06-代码/
├── requirements.txt          依赖(固定版本口径)
├── samples/                  演示样本(自建)
│   ├── vuln_cwe89_user_dao.py   漏洞样本:f-string 拼接 SQL(CWE-89)
│   ├── vuln_cwe78_cmd.py        漏洞样本:os.system 命令注入(CWE-78,11/6 新增)
│   ├── vuln_cwe22_path.py       漏洞样本:路径穿越(CWE-22,11/6 新增)
│   └── safe_cwe89_user_dao.py   安全对照:参数化查询(未被规则命中)
├── auditor/                  自研模块(全部独立可执行入口)
│   ├── sast_scan.py          SAST 封装(scan 直连 / normalize 两阶段)
│   ├── llm_discover.py       LLM 候选发现(SAST 之外的第二来源;dry/replay/deepseek 三后端)
│   ├── extract.py            Extract:tree-sitter 提取 sink 函数+同文件辅助函数+被引用常量
│   ├── mock_gen.py           Mock 桩:模板(保底)+ LLM 生成(校验+回退),见第七节
│   ├── harness.py            harness 组装器(业务片段+mock+payload)
│   ├── sandbox.py            沙箱执行(docker 直连 / 两阶段 external)
│   ├── verdict.py            模式 A(确定性)/ 模式 B(LLM 日志推理+三道护栏)
│   ├── orchestrator.py       编排:prepare+collect+regen 重试闭环(--alerts 支持多来源)
│   ├── e2.py                 E2 消融报告(none/A/B/full 四配置)
│   ├── dataset.py            数据集清单构建(S2:dataset_manifest.json)
│   └── tests/                单元测试 36 项(extract 4 + llm_discover 9 + mock/verdict 23)
├── records/                  实验记录(与任务书 3.2 各步骤产出一一对应)
└── smoke_swerex.py           SWE-ReX 冒烟测试脚本
```

## 三、复现演示(两阶段命令序列)

本机(ZCode 会话沙箱)限制 Python 子进程直接访问 Docker 命名管道,
容器步骤由 shell 执行;编排器负责其余全部逻辑与确定性控制。
标准环境(Linux/WSL2 终端)可用一体化模式 `orchestrator run`。

```bash
cd 06-代码
PY=.venv/Scripts/python.exe

# 1) SAST 扫描(官方容器,p/default)→ 原始 JSON
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)/samples:/src" \
  -e SEMGREP_SEND_METRICS=off semgrep/semgrep:latest \
  semgrep scan --json --config p/default /src > records/semgrep_raw_demo.json

# 2) 归一化告警 → records/sast_alerts.json
$PY -m auditor.sast_scan normalize --raw records/semgrep_raw_demo.json \
  --out records/sast_alerts.json --config p/default

# 3) 编排·阶段 1:提取 + mock + harness 组装,生成容器命令
$PY -m auditor.orchestrator prepare --alerts records/sast_alerts.json \
  --project samples --run-id demo --out records

# 4) 编排·阶段 2:shell 执行容器内 harness
bash records/run_demo/sandbox_cmds.sh

# 5) 编排·阶段 3:回收执行产物 → 模式 A 判定 → 审计报告
$PY -m auditor.orchestrator collect --alerts records/sast_alerts.json \
  --project samples --run-id demo --out records

# 单元测试
$PY -m unittest discover -s auditor/tests -v
```

## 四、实测验证结果(2026-10-29)

| 项 | 结果 |
|---|---|
| 单元测试 | **4/4 通过**(sink 定位、辅助函数提取、跨文件标记、函数外 sink 失败处理) |
| SAST 扫描 | 官方容器 p/default:漏洞样本命中 **2 条 CWE-89** 告警(formatted-sql-query、sqlalchemy-execute-raw-query);安全对照样本**零命中** |
| 动态验证 | 2 条告警端到端复现:mock 捕获 payload `zxq-demo-marker' OR '1'='1` 到达 `Cursor.execute` 且未参数化 → **均判定 TP**(0 误报、0 未确认) |
| 证据材料 | 每条 finding 附 harness 脚本、payload、env_snapshot、replay 命令与 stdout,可第三方独立复现 |

落盘产物:`records/sast_alerts.json`、`records/alerts_result.jsonl`、
`records/audit_report.json / .md`、`records/run_demo/<alert_id>/`(snippet、
mock、payload、harness、env_snapshot、stdout/stderr、exit_code)。

## 五、SWE-ReX 接入状态(如实记录)

- `swe-rex 1.4.0` 已安装,`DockerDeployment` 可正常导入与构造;
- 冒烟测试(`smoke_swerex.py`)在本开发会话中**失败于 docker 命名管道
  权限**——ZCode 会话沙箱不允许 Python 子进程访问 Docker 管道
  (与编排器直连模式 `run` 受限是同一根因),**并非 SWE-ReX 本身不可用**;
- 沙箱执行已按风险预案 **R2(降级为 `docker run` 直接驱动)**验证通过,
  执行语义与 SWE-ReX Docker 后端一致;
- 在无此限制的环境(Linux / WSL2 终端)执行 `$PY smoke_swerex.py`
  即可完成接入验证,列为下一步工作。

## 六、候选发现扩展:LLM 作为第二来源(2026-10-30 新增)

**动机**:SAST 规则覆盖不到的漏洞永远不会进入本流水线,系统召回上界被 SAST 封住。`llm_discover.py` 不依赖任何 SAST 告警,直接把函数源码交给大模型判断是否存在污点流,从而把"发现能力"与该规则集是否覆盖解耦。

**与"用 LLM 直接判定漏洞"的本质区别**:本模块产出的候选**一律不被采纳**,必须经下游 Extract-Mock-Test 动态验证。LLM 在这里只当**候选生成器**,其幻觉由确定性验证层兜住——这是"确定性夹住不确定性"在发现层的延伸。

**接口**:输出与 `sast_alerts.json` **完全同 schema**,alert_id 用 `L-` 前缀(SAST 为 `A-`),合并后全局唯一;`orchestrator` 侧只需把 `--alerts` 传成多个路径,下游流程零改动。

```bash
# 1) LLM 候选发现
$PY -m auditor.llm_discover --project samples --out records/llm_candidates.json \
    --backend dry          # 无 key:校验切片与提示词,候选数必为 0
                           # --backend replay --replay-file <响应.json>  回放已录响应
                           # --backend deepseek                          真实 API(需 DEEPSEEK_API_KEY)

# 2) 多来源合并后统一编排(--alerts 支持给多个来源)
$PY -m auditor.orchestrator prepare --alerts records/sast_alerts.json \
    records/llm_candidates.json --project samples --run-id demo --out records
$PY -m auditor.orchestrator collect --alerts records/sast_alerts.json \
    records/llm_candidates.json --project samples --run-id demo --out records
```

**三种后端**:

| 后端 | 是否调 LLM | 用途 |
|---|---|---|
| `dry` | 否 | 校验 AST 切片与提示词构造,输出 token 估算;候选数必为 0 |
| `replay` | 否 | 回放已录制响应,离线回归与演示 |
| `deepseek` | 是 | 真实 API(OpenAI 兼容,需 `DEEPSEEK_API_KEY`);`--record-dir` 可把响应录制成 replay 文件 |

**预算控制**:`--max-functions`(默认 50,最多送 LLM 的函数数)、`--max-chars`(默认 8000,单函数上限)、`--cwe`(默认 CWE-89/78/22/79)。

**实测结果(2026-10-30,真实 DeepSeek 调用)**:

| 项 | 结果 |
|---|---|
| 调用规模 | 2 文件 / 4 函数 / **4 次 API 调用 / 0 错误** |
| 候选产出 | **1 条**(CWE-89);安全对照样本的两个函数均返回 `[]`——**零误报** |
| 动态验证 | **L-001 判定 TP**:mock 捕获 payload 到达 `Cursor.execute` 且未参数化 |
| 多来源合并 | A-001、A-002(SAST)+ L-001(LLM)→ **TP=3 / FP=0 / 未确认=0** |

**位置差异(值得记录)**:同一处漏洞,LLM 报 **line 19**(`query = f"...'{username}'"`,污点进入 SQL 语句那行),SAST 报 **line 20**(`cursor.execute(query)`,sink 调用行)。两者都落在同一函数内(16–21),Extract 均能正确定位 `get_user` —— 这说明**候选不要求位置精确到 sink**,只要在同一语义单元内即可被验证,降低了 LLM 定位精度的要求。

**可复现性**:真实调用时用 `--record-dir records/llm_replay` 录制了响应;后续可 `--backend replay --replay-file records/llm_replay/llm_replay.json` **在无 API 密钥的情况下离线复现同一结果**,实验不依赖密钥、不重复产生费用。

> ⚠️ **密钥管理**:`DEEPSEEK_API_KEY` 只经环境变量传入,**不得写入仓库任何文件**;`records/llm_replay/` 中只有响应内容,不含密钥。

---

## 七、Mock 生成接入 LLM(2026-11-06 新增)

`mock_gen.py` 升级为**双路径**:`template`(CWE-89/sqlite 保底,确定性)/
`llm`(deepseek,与 llm_discover 共用后端与录制回放机制)。LLM 失败自动回退
模板并记录 `fallback_reason`;无模板可回退时按三分类口径返回失败。

**输出契约**(校验不过不进沙箱):`{"imports", "mock_code", "payload", "rationale"}`;
mock_code 必须含 `CAPTURED = {"sink_api", "calls"}` 与 `_install_mock()`,payload 必须
含标记串 `zxq-demo-marker`。校验三道关:`compile()` 语法检查 → CAPTURED/契约检查 →
**调用形态黑名单**(`os.system(`、`subprocess.`、`eval(` 等调用形态禁止;
`os.system = 桩` 这类赋值拦截形态允许)。

**判定契约同步泛化**(verdict.py):CAPTURED.calls 每项必须含 `args`(危险参数字符串);
模式 A 判定改为"payload 出现在任一记录字段 + sanitized 标记/参数化绑定" → 三分类,
与 CWE 类型无关(此前只认 `sql` 字段)。

**重试闭环**(orchestrator 新增 `regen` 子命令,方案 4.3.5):TP 不动;FP 且建议改
payload → 仅换 payload、复用现有 harness(省一次生成);FP/未确认且建议改 mock →
带上一轮 reason+stderr 反馈重新生成并重新组装;上限 3 轮、单告警 LLM 预算 12 次;
重试产物入 `attempt_N/` 子目录,轨迹写 `retry_trace.jsonl`。

**实测(2026-11-06,run_llmmock,真实 DeepSeek)**:

| 项 | 结果 |
|---|---|
| 候选来源 | SAST 2 条(CWE-89;p/default 未命中 CWE-78/22 样本——SAST 召回上界的活例证)+ LLM 候选 3 条(CWE-22/78/89,6 次调用零误报) |
| mock 生成 | **5/5 由 LLM 生成并一次通过校验**(含无模板的 CWE-78/CWE-22);LLM 调用 5 次、0 错误,响应已录制 `records/mock_replay_multi/` |
| 动态验证 | **TP=5 / FP=0 / 未确认=0**,0 重试;LLM 为 `open()` 生成的桩正确处理了 `with` 语句(`__enter__/__exit__`) |
| 过程缺陷(已修) | 首轮 5 次调用全部 422:请求体出现 `model: null`(`--mock-model` 未传时 None 一路透传)——已修复并给后端加防御与**错误响应体捕获**;此前后端抛错不带响应体,422 无法定位 |
| 已知小瑕疵 | LLM 将 marker 追加在路径尾部而非嵌入路径段;契约上成立,提示词后续可优化 |

**命令序列**(在第三节基础上,prepare/collect 增加 `--mock-backend deepseek
--mock-record-dir records/mock_replay_multi`;重试轮:`orchestrator regen --round 2
...` → `bash sandbox_cmds_round2.sh` → `collect --round 2`)。

---

## 八、模式 B 与 E2 消融(2026-11-09 新增)

**模式 B(LLM 日志推理判定)**:判定规则由本项目设计并写入固定提示词,DeepSeek 仅做
归因推理;输出经结构化校验(白名单 verdict/fix_suggestion)。**三道确定性护栏(代码强制,
LLM 不可越过)**:①env_ok=False 或 exit_code≠0 → 直接 Unconfirmed(坏运行不进 LLM);
②输出不可解析 → Unconfirmed(fail-safe);③TP/FP 必须有 CAPTURED 到达记录支撑,
与执行证据矛盾一律降级 Unconfirmed。

**E2 消融**(任务书 3.4 四配置,`auditor/e2.py` 汇总,报告 `records/e2/e2_report.md`):

| 配置 | 机制 | 判定分布 | LLM 调用 | 沙箱轮次 |
|---|---|---|---|---|
| none | 候选直接采纳 | accepted×5 | 0 | 0 |
| A | 模式 A | TP×5 | 5(mock 生成) | 1 |
| B | 模式 B | TP×5 | 7(判定 6 + 重试 mock 1) | 2 |
| full | 动态验证 + 重试闭环 | TP×5 | 7 | 2 |

**E2 关键发现(判定模式比选的初步结论)**:

1. **模式分歧有真实价值**:L-001(CWE-22)模式 A 判 TP(标记到达即认),模式 B 归因
   "mock 假文件返回空内容、payload 构造证据弱"判 Unconfirmed——它抓到了 11/6 记录的
   已知瑕疵(payload marker 追加在路径尾部);
2. **重试闭环实战走通**:regen 带反馈再生成 mock(`read()` 改为回显路径内容)后
   round 2 判 TP——Unconfirmed→反馈→修复→确认 全链路完成(轨迹 `retry_trace.jsonl`);
3. **初步比选结论**:模式 A 确定性强、零判定调用,为主判;模式 B 每告警 1 次调用、
   能发现证据构造弱点,建议期末采用 **"A 主判 + B 复核触发重试"** 的组合(实现上
   即以 B 的护栏化输出作为 regen 触发条件之一);
4. **演示集无区分度**(全部告警指向真实缺陷、精确率同为 1.0),E2 定量结论以
   Vul4Py/SARD 真实数据集为准——数据集选型考证见
   `05-实验步骤/数据集选型决策(Defects4Py考证A12).md`(**Defects4Py 证伪,
   更正为 Vul4Py**;`dataset.py` 清单构建器已落地,演示样本清单已生成)。

**运行环境记录失误(如实说明)**:首次模式 B 运行的判定响应被后续重跑共用录制目录覆盖、
attempt 目录被清理,retry_trace 首行为其残留;修复措施:录制目录此后按运行隔离
(`--judge-record-dir records/judge_replay_<run_id>`)。

---

## 九、已知局限(与方案 4.5 对应)

1. Extract 仅取**同文件**函数与被引用的模块级常量,丢失跨文件全局状态
   与净化逻辑;此类样本将按三分类口径归入"**未确认**",如实统计;
2. Mock 桩已支持 **LLM 生成**(见第七节),当前 few-shot 样例为 CWE-89/sqlite
   与 CWE-78/os.system 两类,其余 CWE 依赖模型泛化——生成的桩若不满足契约
   会回退模板或判失败,不会带病进沙箱;
2a. 模式 B 依赖 LLM 归因,存在非确定性(同一证据两轮判定可能不同,11/9 实测);
    护栏保证其不产生超出执行证据的结论,但**最终报告以模式 A 判定为准**,
    模式 B 仅作复核与重试触发(见第八节比选结论);
3. 本机 ZCode 会话内 Python 子进程不可直连 Docker 管道,容器步骤经
   shell 两阶段执行;标准环境用 `orchestrator run` 一体化模式;
4. **系统召回上界受候选来源限制**:SAST 未报出的漏洞不会进入流水线。
   第六节的 LLM 发现通道用于缓解此限制(把发现与规则覆盖解耦),但
   **它本身也产候选、不保证召回**;评测时应区分"分诊召回"(分母=候选数)
   与"端到端召回"(分母=数据集已知漏洞数),并单列**候选覆盖率**。
