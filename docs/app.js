/* 可验证的大模型代码审计系统 · 静态证据浏览器
 *
 * 定位(GitHub Pages 只能托管静态文件):
 *   1) 浏览已落盘的判定证据;
 *   2) 用户自带 DeepSeek Key 时,在浏览器里做**候选发现**(CORS 已实测允许)。
 *      浏览器无法执行 Docker,所以候选 ≠ 判定 —— UI 中明确标注。
 */
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const STATE = { data: null, caseId: null };
const KEY_STORE = 'audit_demo_deepseek_key';

/* ------------------------------- 数据加载 ------------------------------- */
async function boot() {
  try {
    const res = await fetch('data/index.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    STATE.data = await res.json();
  } catch (err) {
    $('#boundary').innerHTML =
      '<b>无法加载数据。</b>若你是直接双击打开本地文件,浏览器的 fetch 会被 file:// 拦住,'
      + '请改用 <code>python -m http.server</code> 或访问 GitHub Pages 网址。';
    return;
  }
  $('#boundary').innerHTML = '📍 <b>静态证据浏览器</b>　'
    + esc(STATE.data.boundary || '');
  $('#genAt').textContent = '数据生成于 ' + (STATE.data.generated_at || '').slice(0, 19).replace('T', ' ')
    + '（CVE 核验日期 ' + (STATE.data.cve_verified_at || '—') + '）';

  renderCaseList();
  const first = STATE.data.cases[0];
  if (first) selectCase(first.id);

  const saved = sessionStorage.getItem(KEY_STORE);
  if (saved) { $('#apiKey').value = saved; $('#rememberKey').checked = true; }
  $('#rememberKey').addEventListener('change', storeKey);
  $('#apiKey').addEventListener('change', storeKey);
  $('#analyzeBtn').addEventListener('click', analyze);
}

function storeKey() {
  if ($('#rememberKey').checked && $('#apiKey').value.trim()) {
    sessionStorage.setItem(KEY_STORE, $('#apiKey').value.trim());
  } else {
    sessionStorage.removeItem(KEY_STORE);
  }
}

/* ------------------------------- 案例列表 ------------------------------- */
function renderCaseList() {
  const list = $('#caseList');
  list.innerHTML = '';
  STATE.data.cases.forEach((c) => {
    const btn = el('button', 'case');
    btn.type = 'button';
    btn.dataset.id = c.id;
    btn.innerHTML =
      '<div class="t">' + esc(c.title) + '</div>' +
      '<div class="m">' +
        '<span class="chip lang-' + esc((c.findings[0] || {}).extract?.language || '') + '">'
          + esc(langLabel((c.findings[0] || {}).extract?.language)) + '</span>' +
        '<span class="chip">' + esc((c.findings[0] || {}).cwe || '') + '</span>' +
        '<span class="chip v-' + esc((c.findings[0] || {}).verdict || '') + '">'
          + esc((c.findings[0] || {}).verdict || '') + '</span>' +
      '</div>';
    btn.addEventListener('click', () => selectCase(c.id));
    list.appendChild(btn);
  });
}

function currentCase() {
  return STATE.data.cases.find((c) => c.id === STATE.caseId);
}

function selectCase(id) {
  STATE.caseId = id;
  document.querySelectorAll('.case').forEach((b) => b.classList.toggle('active', b.dataset.id === id));
  $('#analyzeResult').hidden = true;
  $('#analyzeStatus').hidden = true;
  renderCase(currentCase());
}

/* ------------------------------- 案例渲染 ------------------------------- */
function renderCase(c) {
  if (!c) return;
  const f0 = c.findings[0] || {};
  const lang = langLabel(f0.extract?.language);

  $('#caseHeader').innerHTML =
    '<div class="case-header">' +
      '<h2>' + esc(c.title) + '</h2>' +
      '<div class="meta">' +
        '<span class="chip lang-' + esc((f0.extract?.language || '')) + '">' + esc(lang) + '</span>' +
        '<span class="chip">' + esc(f0.cwe || '') + '</span>' +
        '<span class="chip">候选来源：' + esc(c.channel) + '</span>' +
        '<span class="chip">判定模式 ' + esc(f0.verdict_mode || 'A') + '</span>' +
      '</div>' +
      (c.note ? '<div class="case-note">' + esc(c.note) + '</div>' : '') +
    '</div>';

  const s = c.summary || {};
  const counts = s.counts || {};
  const cards = [
    ['候选告警', s.total ?? '—', ''],
    ['已确认 TP', counts.TP ?? 0, 'tp'],
    ['已排除 FP', counts.FP ?? 0, 'fp'],
    ['未确认', counts.Unconfirmed ?? 0, 'un'],
    ['LLM 调用', s.llm_calls ?? 0, ''],
  ];
  const cardBox = $('#summaryCards');
  cardBox.innerHTML = '';
  cards.forEach(([k, v, cls]) => {
    const box = el('div', 'card ' + cls);
    box.innerHTML = '<div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div>';
    cardBox.appendChild(box);
  });

  const host = $('#findings');
  host.innerHTML = '';
  c.findings.forEach((f) => host.appendChild(renderFinding(f)));
}

function renderFinding(f) {
  const n = f.narrative || {};
  const wrap = el('div', 'finding');

  const head = el('div', 'f-head');
  head.innerHTML =
    '<h3 class="f-title"><span>' + esc(f.alert_id) + ' · ' + esc(n.title || f.cwe) + '</span>' +
      '<span class="chip v-' + esc(f.verdict || '') + '">' + esc(verdictLabel(f.verdict)) + '</span>' +
    '</h3>' +
    '<div class="f-sub">判定依据：' + esc(f.reason || '') + '</div>';
  wrap.appendChild(head);

  if (n.text || n.basis) {
    const nar = el('div', 'narrative');
    nar.innerHTML = highlightInline(esc(n.text || n.basis));
    wrap.appendChild(nar);
  }

  // 五段证据链
  const chain = el('div', 'chain');
  const rows = [
    ['① 污点源', n.source?.desc || '—', false],
    ['② 传播', n.propagation?.code || '—', true],
    ['③ 危险操作点', (n.sink?.api || '—') + (n.sink?.line ? '  @ 第 ' + n.sink.line + ' 行' : ''), true],
    ['④ 沙箱截获实参', n.captured_arg || '（未截获）', true],
    ['⑤ payload', n.payload || '—', true],
  ];
  rows.forEach(([k, v, mono]) => {
    const row = el('div', 'chain-row');
    row.innerHTML = '<div class="chain-k">' + esc(k) + '</div>'
      + '<div class="chain-v' + (mono ? '' : ' plain') + '">' + esc(v) + '</div>';
    chain.appendChild(row);
  });
  wrap.appendChild(chain);

  if (n.cve_ref) {
    const cve = el('div', 'cve');
    const r = n.cve_ref;
    cve.innerHTML = '🔖 <b>CVE 参照</b>：<a href="' + esc(r.nvd_url) + '" target="_blank" rel="noopener">'
      + esc(r.cve_id) + '</a> — ' + esc(r.summary_zh || '')
      + (r.cvss ? '（CVSS ' + esc(r.cvss) + '）' : '')
      + '<br><span style="opacity:.8">经 NVD CVE API 逐条核验；匹配不到时此处留空，不臆造。</span>';
    wrap.appendChild(cve);
  }

  // 代码 / mock / harness / 日志 / 复现命令
  const tabs = [
    ['源码片段', f.files?.snippet],
    ['mock 桩', f.files?.mock],
    ['harness 组装', f.files?.harness],
    ['运行日志', f.files?.stdout ? f.files.stdout + (f.files.stderr ? '\n--- stderr ---\n' + f.files.stderr : '') : null],
  ].filter(([, v]) => v);

  if (tabs.length) {
    const box = el('div', 'tabs');
    const bar = el('div', 'tabbar');
    const panels = el('div');
    tabs.forEach(([label, code], i) => {
      const tab = el('button', 'tab' + (i === 0 ? ' active' : ''), label);
      tab.type = 'button';
      const panel = el('div', 'panel' + (i === 0 ? ' active' : ''));
      panel.innerHTML = '<pre class="code">' + highlight(esc(code)) + '</pre>';
      tab.addEventListener('click', () => {
        bar.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
        panels.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
        tab.classList.add('active');
        panel.classList.add('active');
      });
      bar.appendChild(tab);
      panels.appendChild(panel);
    });
    box.appendChild(bar);
    box.appendChild(panels);
    wrap.appendChild(box);
  }

  const applied = f.harness?.redirects_applied || [];
  if (applied.length) {
    const note = el('div', 'redirect-note');
    note.innerHTML = 'PHP 内建函数不可重定义：harness 在组装期把危险调用重定向到记录桩 —— '
      + applied.map((a) => '<code>' + esc(a.name) + '×' + esc(a.count) + '</code>').join('、')
      + '（改写次数落盘于 harness_meta.json，可审计）。';
    wrap.appendChild(note);
  }

  if (f.replay_command) {
    const row = el('div', 'toolrow');
    row.innerHTML = '<div style="font-size:12.5px;color:var(--ink-3)">'
      + '第三方复现命令（换一台机器执行，应得到同一结论）</div>';
    const btn = el('button', 'copy', '复制命令');
    btn.type = 'button';
    btn.addEventListener('click', async () => {
      await navigator.clipboard.writeText(f.replay_command);
      btn.textContent = '已复制 ✓';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = '复制命令'; btn.classList.remove('copied'); }, 1800);
    });
    row.appendChild(btn);
    wrap.appendChild(row);
    const pre = el('div');
    pre.innerHTML = '<pre class="code" style="margin:0 18px 16px;border-radius:10px">'
      + esc(f.replay_command) + '</pre>';
    wrap.appendChild(pre);
  }

  return wrap;
}

const verdictLabel = (v) => ({ TP: '✅ 已确认 TP', FP: '❌ 已排除 FP' }[v] || '⚠️ 未确认');

const langLabel = (l) => ({ php: 'PHP', python: 'Python' }[String(l || '').toLowerCase()]
  || String(l || '').toUpperCase());

/* 把 `代码` 片段渲染成 <code>
 */
function highlightInline(s) {
  return s.replace(/`([^`]+)`/g, '<code>$1</code>');
}

/* 极简语法着色:注释 / 字符串 / 关键字 */
function highlight(s) {
  return s
    .replace(/(\/\/[^\n]*|#[^\n]*)/g, '<span class="tok-com">$1</span>')
    .replace(/(&#x27;[^&\n]*?&#x27;|&quot;[^&\n]*?&quot;)/g, '<span class="tok-str">$1</span>')
    .replace(/\b(function|def|return|if|else|while|for|with|import|from|class|new|echo|try|catch|throw|use|as|in|and|or|not|True|False|None|null)\b/g,
             '<span class="tok-kw">$1</span>');
}

/* --------------------------- 自带 Key:候选发现 --------------------------- */
const PROMPT = (cweScope, filename, code) => `你是代码安全审计助手。请只做一件事:找出给定源码里**可能存在的污点流漏洞**。

本次只关注这些漏洞类型:${cweScope}

文件:${filename}

源码:
\`\`\`
${code}
\`\`\`

判定要求:
1. 只有当你能够明确指出"外部可控输入(source)→ 未经净化 → 到达危险操作(sink)"的路径时才报告;
2. 不报告风格问题、密码学误用、配置问题、依赖问题;
3. line 必须是该文件中真实存在的行号;
4. 输出严格的 JSON 数组,每项字段如下,不要输出任何解释文字:
   {"cwe": "CWE-xxx", "line": <行号>, "source": "<source 描述>",
    "sink": "<危险函数名>", "reason": "<一句话理由>", "confidence": <0~1>}
5. 没有发现就输出 []

只输出 JSON。`;

async function analyze() {
  const key = $('#apiKey').value.trim();
  const status = $('#analyzeStatus');
  const btn = $('#analyzeBtn');
  status.hidden = false;
  status.className = 'status';

  if (!key) {
    status.classList.add('err');
    status.textContent = '请先填入你自己的 DeepSeek API Key（仅存本页 sessionStorage）。';
    return;
  }
  const c = currentCase();
  if (!c) return;
  storeKey();

  btn.disabled = true;
  let totalCands = 0;
  const collected = [];
  const started = performance.now();

  try {
    for (const src of c.sources) {
      status.textContent = '正在分析 ' + src.path + ' …（真实调用 DeepSeek，会产生少量费用）';
      const resp = await fetch('https://api.deepseek.com/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
        body: JSON.stringify({
          model: 'deepseek-chat',
          temperature: 0,
          messages: [{ role: 'user', content: PROMPT(c.cwe_scope.join('、'), src.path, src.code) }],
        }),
      });
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error('HTTP ' + resp.status + '：' + body.slice(0, 300));
      }
      const data = await resp.json();
      const text = data.choices?.[0]?.message?.content || '';
      const items = parseJsonArray(text);
      items.forEach((it) => collected.push({ ...it, file: src.path }));
      totalCands += items.length;
    }
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    status.classList.add('ok');
    status.textContent = '完成：' + c.sources.length + ' 个文件，候选 ' + totalCands
      + ' 条，耗时 ' + secs + 's。（注意：这只是候选，未经沙箱验证不算漏洞）';
    renderAnalyze(c, collected, totalCands, secs);
  } catch (err) {
    status.classList.add('err');
    const msg = String(err.message || err);
    status.textContent = /HTTP 401|Unauthorized|invalid/i.test(msg)
      ? '密钥无效或已过期：请检查 Key（HTTP 401）。\n' + msg
      : /HTTP 429/.test(msg)
        ? '触发限流（HTTP 429）：稍后重试，或换 Key。\n' + msg
        : '调用失败：' + msg + '\n若为网络/CORS 问题，可改用本地 Streamlit 界面。';
  } finally {
    btn.disabled = false;
  }
}

function parseJsonArray(text) {
  if (!text) return [];
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) t = fence[1].trim();
  const tryParse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  let data = tryParse(t);
  if (data == null) {
    const i = t.indexOf('['), j = t.lastIndexOf(']');
    if (i >= 0 && j > i) data = tryParse(t.slice(i, j + 1));
  }
  if (data == null) return [];
  if (!Array.isArray(data)) data = [data];
  return data.filter((d) => d && typeof d === 'object');
}

function renderAnalyze(c, cands, n, secs) {
  const box = $('#analyzeResult');
  box.hidden = false;
  box.innerHTML =
    '<h3>🔎 你的 Key · 候选发现结果</h3>'
    + '<p class="sub">案例：' + esc(c.title) + ' ｜ 模型 deepseek-chat（temperature=0） ｜ '
    + '候选 ' + n + ' 条 ｜ 耗时 ' + secs + 's</p>';

  if (!n) {
    box.innerHTML += '<div class="empty">模型未报告任何候选。'
      + '（对本案例而言这不正常——可对比下方已落盘证据；也可能是 Key/网络问题。）</div>';
    return;
  }
  const table = el('table', 'cand');
  table.innerHTML =
    '<thead><tr><th>文件</th><th>行</th><th>CWE</th><th>source → sink</th>'
    + '<th>理由</th><th>置信度(模型自述)</th></tr></thead><tbody>'
    + cands.map((d) => '<tr>'
      + '<td class="mono">' + esc(d.file || '') + '</td>'
      + '<td class="mono">' + esc(d.line ?? '') + '</td>'
      + '<td class="mono">' + esc(d.cwe || '') + '</td>'
      + '<td class="mono">' + esc(d.source || '') + ' → ' + esc(d.sink || '') + '</td>'
      + '<td>' + esc(d.reason || '') + '</td>'
      + '<td class="mono">' + esc(d.confidence ?? '') + '</td>'
      + '</tr>').join('')
    + '</tbody>';
  box.appendChild(table);
  const note = el('p', 'sub');
  note.style.marginTop = '10px';
  note.innerHTML = '⚠️ 上表是<b>模型给出的候选</b>，位置与理由均由模型生成，'
    + '可能虚构——下方「已落盘证据」是系统把候选放进沙箱实际执行后的判定与截获实参。'
    + '这正是本项目的主张：<b>候选可以来自模型，判定必须来自执行</b>。';
  box.appendChild(note);
}

boot();
