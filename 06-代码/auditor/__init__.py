# -*- coding: utf-8 -*-
"""auditor: 可验证的大模型代码审计系统 — 中期演示实现。

模块对应《项目方案》4.3 动态验证模块与开题 4.6 接口契约:
  sast_scan.py    SAST 扫描封装(Semgrep)→ sast_alerts.json
  extract.py      Extract 代码提取(tree-sitter)
  mock_gen.py     Mock 桩生成(模板化,LLM 接入点预留)
  harness.py      harness 组装器
  sandbox.py      沙箱执行(Docker)
  verdict.py      漏洞判定(模式 A 硬编码检测器,三分类)
  orchestrator.py audit_alert 契约 + 重试闭环骨架
"""
