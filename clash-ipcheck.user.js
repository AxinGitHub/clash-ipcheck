// ==UserScript==
// @name         Clash Verge Rev · 全屏 IP 检测
// @namespace    xx-ip-check/ipcheck-yh
// @version      1.2.1
// @description  全屏查看节点出口 IP 与 TeleAPI 报告，支持质量排序、地区筛选、行内详情、批量检测与恢复。
// @match        http://127.0.0.1:9097/*
// @match        http://localhost:9097/*
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
// @connect      127.0.0.1
// @connect      localhost
// @connect      api.ipify.org
// @connect      ai01.teleapi.top
// @run-at       document-idle
// @noframes
// ==/UserScript==

(() => {
  'use strict';
  const SITE = 'https://ai01.teleapi.top/ipcheck/';
  const PROBE = 'api.ipify.org';
  const KEY = 'ipcheck-yh-recovery-v1';
  const HISTORY = 'ipcheck-yh-history-v1';
  const LOCK = 'ipcheck-yh-controller-9097';
  const SWITCHABLE = new Set(['Selector', 'URLTest', 'Fallback']);
  const BUILTIN = new Set(['Direct', 'Reject', 'RejectDrop', 'Pass', 'Compatible', 'DNS']);
  const state = { sort: 'desc', expanded: new Set(), visible: [], nodes: [], results: new Map(), selected: new Set(), busy: false, stop: false, cache: new Map(), journal: null, active: null };
  const show = value => value === null || value === undefined || value === '' ? '未提供' : typeof value === 'boolean' ? (value ? '是' : '否') : String(value);
  const esc = value => show(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const reportURL = ip => SITE + '?ip=' + encodeURIComponent(ip);
  function isIP(ip) {
    if (typeof ip !== 'string') return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split('.').every(n => Number(n) <= 255);
    try { return ip.includes(':') && new URL('http://[' + ip + ']/').hostname.length > 2; } catch { return false; }
  }

  // Plan a concrete route from GLOBAL, including provider nodes nested in groups.
  function planNodes(proxies) {
    if (!proxies.GLOBAL || !Array.isArray(proxies.GLOBAL.all)) throw new Error('控制器缺少 GLOBAL 策略组。');
    const paths = new Map();
    const visit = (name, path, seen) => {
      if (seen.has(name) || !proxies[name]) return;
      const p = proxies[name];
      if (!Array.isArray(p.all)) {
        if (!BUILTIN.has(p.type) && !['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'].includes(name)) {
          if (!paths.has(name) || path.length < paths.get(name).length) paths.set(name, path);
        }
        return;
      }
      if (!SWITCHABLE.has(p.type)) return; // LoadBalance/Relay cannot identify a single exit this way.
      if (p.type !== 'Selector' && !Object.hasOwn(p, 'fixed')) return;
      const next = new Set(seen).add(name);
      for (const child of p.all) visit(child, [...path, { group: name, child }], next);
    };
    visit('GLOBAL', [], new Set());
    return Object.entries(proxies).filter(([name, p]) => !Array.isArray(p.all) && !BUILTIN.has(p.type) && !['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'].includes(name))
      .map(([name, p]) => ({ name, type: p.type, path: paths.get(name), reason: paths.has(name) ? '' : 'GLOBAL 无可安全恢复的选择路径；请通过手动选择组包含此节点' }));
  }

  // Request credentials are local-only; third-party lookups never receive the controller secret.
  function request(url, { method = 'GET', data, headers = {}, timeout = 20000, signal } = {}) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) { reject(new Error('已停止')); return; }
      let handle;
      const abort = () => handle?.abort();
      const finish = (fn, value) => { signal?.removeEventListener('abort', abort); fn(value); };
      handle = GM_xmlhttpRequest({
        method, url, timeout, anonymous: true, redirect: 'error',
        headers: { Accept: 'application/json', 'Cache-Control': 'no-cache', ...headers },
        ...(data === undefined ? {} : { data: JSON.stringify(data) }),
        onload(r) {
          if (r.status < 200 || r.status >= 300) {
            finish(reject, new Error(r.status === 401 ? '控制器密钥不正确，请填写 Clash 外部控制的 Secret。' : r.status === 429 ? '检测服务限流（429），稍后重试。' : '请求失败：HTTP ' + r.status)); return;
          }
          if (!r.responseText && r.status === 204) { finish(resolve, null); return; }
          try { finish(resolve, JSON.parse(r.responseText)); } catch { finish(reject, new Error('服务返回了非 JSON 内容，可能是验证页或接口异常。')); }
        },
        onerror: () => finish(reject, new Error('网络请求失败，请检查节点、网络和油猴跨域权限。')),
        ontimeout: () => finish(reject, new Error('请求超时（' + timeout / 1000 + ' 秒）')),
        onabort: () => finish(reject, new Error('已停止'))
      });
      signal?.addEventListener('abort', abort, { once: true });
    });
  }

  const host = document.createElement('div');
  host.id = 'ipcheck-yh-host';
  if (document.getElementById(host.id)) return;
  host.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483647';
  const root = host.attachShadow({ mode: 'open' });
  root.innerHTML = `
  <style>
    :host{font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e7edf8;color-scheme:dark}
    *{box-sizing:border-box} [hidden]{display:none!important}
    button,input,select{font:inherit}button,a{touch-action:manipulation}
    button,.link{border:1px solid #35435c;border-radius:9px;background:#202e45;color:#e7edf8;padding:8px 13px;cursor:pointer;text-decoration:none;display:inline-block}
    button:hover,.link:hover{background:#304360}button:disabled{opacity:.42;cursor:default}button.primary{background:#6e64f2;border-color:#8c85ff;color:white}
    button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid #b1aaff;outline-offset:3px}
    input,select{color:inherit;background:#101b2d;border:1px solid #35435c;border-radius:8px;padding:8px 10px;min-width:0}input[type=checkbox]{accent-color:#8c85ff}
    #launch{pointer-events:auto;position:absolute;right:24px;bottom:24px;background:#6e64f2;box-shadow:0 6px 32px #0008;padding:12px 20px}
    #panel{pointer-events:auto;position:absolute;z-index:1;inset:0;overflow:auto;background:radial-gradient(ellipse at 85% 0,#252a5444,transparent 45%),#0b1220;padding:28px 32px}
    header,.actions,.toolbar,.stats,.detailhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}header{justify-content:space-between}h1{font-size:25px;letter-spacing:.2px;margin:0}h2{font-size:18px;margin:0 0 12px}h3{font-size:15px;margin:0 0 12px}
    .sub,.muted,small{color:#9baac1}.sub{margin:3px 0 0}small{display:block;font-size:12px}.actions{gap:8px}
    .config{margin-top:22px;padding:16px 18px;background:#121d30;border:1px solid #273650;border-radius:12px}.config .toolbar{margin-top:12px}.config label{display:flex;align-items:center;gap:8px}.config input[type=password]{width:240px}
    #status{margin:14px 0 0;white-space:pre-wrap;overflow-wrap:anywhere;color:#c1c8ff}#recovery{border:1px solid #a66b36;background:#3d291c;padding:14px;border-radius:10px;margin-top:15px}#recovery p{margin:0 0 10px}
    .stats{margin:20px 0;gap:14px}.stat{background:#121d30;border:1px solid #273650;border-radius:12px;padding:12px 20px;min-width:135px}.stat b{font-size:23px;display:block}.stat span{font-size:12px;color:#9baac1}
    .toolbar{justify-content:space-between}.toolbar input[type=search]{width:300px;max-width:100%}.tablewrap{overflow:auto;border:1px solid #273650;border-radius:12px;margin-top:14px;background:#101a2b}
    table{color:inherit;border-collapse:collapse;width:100%;text-align:left;white-space:nowrap}th,td{border-bottom:1px solid #25334b;padding:13px 14px;vertical-align:middle}th{color:#9baac1;font-size:12px;background:#172239;position:sticky;top:0;z-index:1}td:first-child{width:35px}td.name{min-width:210px;max-width:300px;white-space:normal;overflow-wrap:anywhere}td.verdict{min-width:240px;max-width:360px;white-space:normal;font-size:12px}tbody tr:hover{background:#18263b}tbody tr:last-child td{border-bottom:0}
    .tag{display:inline-block;padding:3px 8px;border-radius:6px;background:#26334c;font-size:12px}.ok{color:#86e2b3;background:#183b32}.warn{color:#f2cc84;background:#41351f}.error{color:#ffaaaa;background:#49282f}.score{font-size:19px;font-weight:700}.mono{font-family:ui-monospace,SFMono-Regular,monospace}.name button{padding:0;border:0;background:transparent;color:#b6b0ff;text-align:left}.empty{padding:50px;text-align:center;color:#9baac1}#progress{width:100%;height:5px;accent-color:#8c85ff;margin-top:14px}
    .inline-detail>td{padding:20px;white-space:normal;background:#0b1424}.inline-detail .detailgrid{min-width:0}.inline-detail .card{min-width:0}.inline-detail .detailhead h2{margin:0}.sort-button{padding:0;border:0;background:transparent;color:inherit;font-weight:600}.sort-button:hover{background:transparent;color:#e7edf8} .detailhead{justify-content:space-between;margin-bottom:24px}.detailgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}.card{border:1px solid #273650;background:#121d30;border-radius:12px;padding:20px;margin-bottom:15px}.card p{margin:8px 0}.hero{font-size:27px;font-weight:700;color:#bbb5ff}.kv{display:grid;grid-template-columns:150px 1fr;gap:14px;padding:7px 0;border-bottom:1px solid #24324a;overflow-wrap:anywhere}.kv:last-child{border-bottom:0}.kv>span:first-child{color:#9baac1}.kv>span:last-child{white-space:pre-wrap}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,monospace;max-height:600px;overflow:auto}summary{cursor:pointer;font-weight:600}.notice{font-size:12px;color:#9baac1;margin:15px 0}.source th,.source td{white-space:normal;min-width:160px;overflow-wrap:anywhere}
    @media(max-width:800px){#panel{padding:18px 14px}.inline-detail>td{padding:12px}h1{font-size:21px}.stat{min-width:100px;padding:10px 14px}.config label{flex-wrap:wrap}.kv{grid-template-columns:110px 1fr}.toolbar{gap:10px}}
  </style>
  <button id="launch" aria-expanded="false">◉ IP 检测</button>
  <section id="panel" role="dialog" aria-modal="true" aria-label="Clash 节点 IP 检测" hidden>
    <header><div><h1>节点 IP 检测</h1><p class="sub">Clash Verge Rev · 出口校验与 IP 质量报告</p></div><button id="close">关闭 · Esc</button></header>
    <div class="config">
      <div class="toolbar"><div class="actions"><label>控制器 <span class="mono">${esc(location.origin)}</span></label><label>Secret <input id="secret" type="password" autocomplete="off" placeholder="外部控制密钥；无密钥则留空"></label><button id="load">连接 / 刷新节点</button></div><span id="connection" class="muted">尚未连接</span></div>
      <p class="notice">检测期间临时切换全局模式与节点，可能影响其他联网应用；结束或停止后恢复。请启用 Verge Rev 的系统代理或 TUN。关闭面板会停止任务并恢复；刷新或关页后可用恢复按钮继续恢复。</p>
      <div id="recovery" hidden><p id="recoveryText"></p><button id="restore">恢复检测前的节点与模式</button></div>
      <div id="status" role="status" aria-live="polite">填写控制器密钥后连接；密钥仅保存在当前页面内存。</div><progress id="progress" value="0" max="1" hidden></progress>
    </div>
    <div class="stats"><div class="stat"><b id="count">0</b><span>节点总数</span></div><div class="stat"><b id="done">0</b><span>检测成功</span></div><div class="stat"><b id="failed">0</b><span>失败 / 未确认</span></div><div class="stat"><b id="unique">0</b><span>不同出口 IP</span></div></div>
    <div class="toolbar"><div class="actions"><button id="all" class="primary">检测全部节点</button><button id="chosen">检测所选</button><button id="stop" disabled>停止并恢复</button><button id="export">导出 JSON</button><button id="clearHistory">清空检测记录</button></div><div class="actions"><label for="region" class="muted">国家/地区</label><select id="region" aria-label="筛选国家或地区"><option value="">全部地区</option></select><input id="search" type="search" aria-label="筛选节点" placeholder="搜索节点 / IP / 国家 / 类型"></div></div>
    <p id="historyStatus" class="notice" role="status">检测结果自动保存在本机油猴扩展中，不保存 Secret。</p>
    <div class="tablewrap"><table><thead><tr><th><input id="selectAll" type="checkbox" aria-label="选择当前筛选的全部可检测节点"></th><th>节点 / 协议</th><th>状态</th><th>出口 IP / 地区</th><th id="qualityHeader" aria-sort="descending"><button id="qualitySort" class="sort-button" title="点击切换升序或降序">质量系数 ↓</button></th><th>类型 / 来源</th><th>风控 / AI</th><th>结论</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div>
    <p class="notice">系数、风控分与适用星级均采用检测站原始口径；独享倾向为推测，AI 友好度不代表实测解锁。站点结果可能缓存 1 小时。同 IP 在本轮复用报告。不会修改订阅或节点名称。</p>
  </section>`;
  document.documentElement.appendChild(host);
  const $ = s => root.querySelector(s);
  const status = s => { $('#status').textContent = s; };
  const api = (path, options = {}) => request(location.origin + path, { ...options, headers: { ...options.headers, ...($('#secret').value.trim() ? { Authorization: 'Bearer ' + $('#secret').value.trim() } : {}), 'Content-Type': 'application/json' } });
  const pathFor = name => '/proxies/' + encodeURIComponent(name);

  // Report history is separate from the safety-critical recovery journal.
  function saveHistory() {
    try {
      const previous = GM_getValue(HISTORY, null);
      const records = new Map(previous?.version === 1 && Array.isArray(previous.results) ? previous.results.map(r => [r.name, r]) : []);
      for (const [name, r] of state.results) if (r.finished) records.set(name, {
        name, status: r.status, ip: r.ip, data: r.data, evidence: r.evidence,
        error: r.error, finished: r.finished
      });
      const names = new Set(state.nodes.map(n => n.name));
      GM_setValue(HISTORY, { version: 1, savedAt: Date.now(),
        nodes: state.nodes.map(n => ({ name: n.name, type: n.type, archived: !!n.archived })),
        results: [...records.values()].filter(r => names.has(r.name)) });
      $('#historyStatus').textContent = '检测记录已自动保存；重新打开可直接查看。旧结果不代表当前出口，请按需重测。';
    } catch (e) {
      $('#historyStatus').textContent = '记录保存失败，请导出 JSON 备份：' + e.message;
    }
  }
  function restoreHistory() {
    try {
      const saved = GM_getValue(HISTORY, null);
      if (!saved) return;
      if (saved.version !== 1 || !Array.isArray(saved.nodes) || !Array.isArray(saved.results)) throw new Error('记录格式无效');
      // Never trust stored routes: a live controller connection is required to run.
      state.nodes = saved.nodes.filter(n => typeof n?.name === 'string' && typeof n.type === 'string')
        .map(n => ({ name: n.name, type: n.type, archived: !!n.archived, reason: '历史节点，请先连接 / 刷新节点再检测' }));
      const names = new Set(state.nodes.map(n => n.name));
      state.results = new Map(saved.results.filter(r => names.has(r?.name) && Number.isFinite(r.finished) &&
        ['完成', '失败 / 未确认', '已停止'].includes(r.status) &&
        (!r.data || r.data.derived && Array.isArray(r.data.sources)))
        .map(r => [r.name, { ...r, historical: true }]));
      $('#historyStatus').textContent = '已恢复历史记录；未重新检测，出口及质量可能已变化。连接控制器后可手动重测。';
    } catch (e) { $('#historyStatus').textContent = '无法读取历史记录，可清空后重试：' + e.message; }
  }

  function refreshRecovery() {
    state.journal = GM_getValue(KEY, null);
    $('#recovery').hidden = !state.journal;
    if (state.journal) $('#recoveryText').textContent = '有待恢复记录：原模式 ' + state.journal.mode + '，记录于 ' + new Date(state.journal.at).toLocaleString() + '。恢复前请保持密钥正确。';
    controls();
  }
  function controls() {
    for (const id of ['load', 'secret', 'all', 'chosen', 'restore', 'clearHistory']) $('#' + id).disabled = state.busy;
    for (const id of ['all', 'chosen']) $('#' + id).disabled ||= !!state.journal || !state.nodes.some(n => n.path);
    $('#stop').disabled = !state.busy || state.stop;
    root.querySelectorAll('[data-run]').forEach(b => { b.disabled = state.busy || !!state.journal || !state.nodes[Number(b.dataset.run)]?.path; });
  }
  function render() {
    const term = $('#search').value.toLowerCase().trim();
    const region = $('#region').value;
    const countryOf = n => state.results.get(n.name)?.data?.derived?.geo?.country || '';
    // Options come from detected exits, never guessed from node names.
    const countries = [...new Set(state.nodes.map(countryOf).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
    if (region && !countries.includes(region)) countries.push(region);
    $('#region').innerHTML = '<option value="">全部地区</option>' + countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
    $('#region').value = region;
    const scoreOf = n => {
      const value = state.results.get(n.name)?.data?.derived?.coefficient?.value;
      return (typeof value === 'number' || typeof value === 'string' && value.trim() !== '') && Number.isFinite(Number(value)) ? Number(value) : null;
    };
    // Keep original indexes for every action after filtering or sorting.
    const visible = state.nodes.map((n, i) => ({ n, i })).filter(({ n }) => {
      const r = state.results.get(n.name) || {}, d = r.data?.derived || {}, geo = d.geo || {};
      return (!region || countryOf(n) === region) && (!term || [n.name, n.type, r.ip, geo.country, geo.city, geo.isp, d.type].filter(Boolean).join(' ').toLowerCase().includes(term));
    }).sort((a, b) => {
      const x = scoreOf(a.n), y = scoreOf(b.n);
      if (x === null || y === null) return x === y ? a.i - b.i : x === null ? 1 : -1;
      return (state.sort === 'asc' ? x - y : y - x) || a.i - b.i;
    });
    state.visible = visible.map(({ n }) => n);
    $('#qualityHeader').setAttribute('aria-sort', state.sort === 'asc' ? 'ascending' : 'descending');
    $('#qualitySort').textContent = '质量系数 ' + (state.sort === 'asc' ? '↑' : '↓');
    $('#rows').innerHTML = visible.map(({ n, i }) => {
      const r = state.results.get(n.name) || {};
      const d = r.data?.derived || {};
      const geo = d.geo || {};
      const success = r.status === '完成';
      const expanded = state.expanded.has(n.name) && !!r.data;
      const disclosure = `data-detail="${i}" aria-expanded="${expanded}" aria-controls="node-detail-${i}" ${r.data ? '' : 'disabled'}`;
      return `<tr data-node="${i}"><td><input type="checkbox" data-select="${i}" aria-label="选择 ${esc(n.name)}" ${state.selected.has(n.name) ? 'checked' : ''} ${n.path ? '' : 'disabled'}></td>
        <td class="name"><button ${disclosure}>${esc(n.name)}</button><small>${esc(n.type)}</small>${n.archived ? '<small class="warn">不在当前订阅</small>' : ''}</td>
        <td><span class="tag ${success ? 'ok' : r.error ? 'error' : ''}">${esc(r.status || (n.path ? '待检测' : '不可切换'))}</span>${r.historical ? '<small>历史记录 · 未重新检测</small>' : ''}</td>
        <td class="mono">${esc(r.ip)}<small>${esc([geo.country, geo.city].filter(Boolean).join(' · '))}</small></td>
        <td><span class="score">${esc(d.coefficient?.value)}</span><small>${esc(d.coefficient?.band)}</small></td>
        <td>${esc(d.type)}<small>${esc(d.origin)}</small></td><td>${esc(d.risk == null ? null : d.risk + ' / 100')}<small>${esc(d.ai?.level)}</small></td>
        <td class="verdict">${esc(r.error || n.reason || d.verdict || '等待检测')}<small>${r.finished ? esc(new Date(r.finished).toLocaleString()) : ''}</small></td>
        <td><div class="actions"><button data-run="${i}">检测</button><button ${disclosure}>${expanded ? '收起详情' : '展开详情'}</button></div></td></tr>${expanded ? `<tr id="node-detail-${i}" class="inline-detail"><td colspan="9">${detail(n.name)}</td></tr>` : ''}`;
    }).join('') || '<tr><td colspan="9" class="empty">' + (state.nodes.length ? '没有符合条件的节点' : '连接控制器后显示节点') + '</td></tr>';
    const results = [...state.results.values()];
    $('#count').textContent = state.nodes.length;
    $('#done').textContent = results.filter(r => r.status === '完成').length;
    $('#failed').textContent = results.filter(r => r.error).length;
    $('#unique').textContent = new Set(results.filter(r => r.ip).map(r => r.ip)).size;
    const available = state.visible.filter(n => n.path);
    $('#selectAll').checked = !!available.length && available.every(n => state.selected.has(n.name));
    $('#selectAll').indeterminate = available.some(n => state.selected.has(n.name)) && !$('#selectAll').checked;
    controls();
  }
  async function load() {
    const [version, list] = await Promise.all([api('/version'), api('/proxies')]);
    if (!list?.proxies) throw new Error('控制器没有返回有效的节点列表。');
    const current = planNodes(list.proxies);
    const currentNames = new Set(current.map(n => n.name));
    // Retain reports from other subscriptions, but discard their executable routes.
    const archived = state.nodes.filter(n => !currentNames.has(n.name) && state.results.has(n.name))
      .map(n => ({ name: n.name, type: n.type, archived: true, reason: '不在当前订阅，仅可查看历史记录' }));
    for (const n of archived) state.results.get(n.name).historical = true;
    state.nodes = [...current, ...archived];
    saveHistory();
    state.selected = new Set([...state.selected].filter(name => state.nodes.some(n => n.name === name && n.path)));
    $('#connection').textContent = '已连接 · ' + show(version.version);
    render();
    return list.proxies;
  }
  async function saveJournal(mode, proxies, nodes) {
    const groups = new Map();
    for (const n of nodes) for (const step of n.path) {
      const p = proxies[step.group];
      if (!p || typeof p.now !== 'string') throw new Error('策略组状态不完整：' + step.group);
      // Old cores without fixed state cannot safely restore auto-group pinning.
      if (p.type !== 'Selector' && !Object.hasOwn(p, 'fixed')) throw new Error('核心未提供自动组 fixed 状态，无法安全恢复：' + step.group + '。请改用手动选择组。');
      groups.set(step.group, { name: step.group, type: p.type, now: p.now, fixed: p.fixed || '' });
    }
    state.journal = { origin: location.origin, at: Date.now(), mode, groups: [...groups.values()] };
    GM_setValue(KEY, state.journal);
    if (!GM_getValue(KEY, null)) throw new Error('无法保存恢复记录，已取消检测。');
    refreshRecovery();
  }
  async function retry(task) {
    let error;
    for (let i = 0; i < 3; i++) { try { return await task(); } catch (e) { error = e; if (i < 2) await sleep(350); } }
    throw error;
  }
  async function restore() {
    const j = GM_getValue(KEY, null);
    if (!j) return;
    // Both loopback aliases refer to the same controller; no secret is ever sent elsewhere.
    if (!['http://127.0.0.1:9097', 'http://localhost:9097'].includes(j.origin) || !Array.isArray(j.groups) || !['rule', 'global', 'direct'].includes(j.mode)) throw new Error('恢复记录无效，请在 Clash 手动恢复。');
    const errors = [];
    for (const group of [...j.groups].reverse()) {
      try {
        await retry(async () => {
          const pinned = group.type === 'Selector' || !!group.fixed;
          await api(pathFor(group.name), pinned ? { method: 'PUT', data: { name: group.fixed || group.now } } : { method: 'DELETE' });
          const check = await api(pathFor(group.name));
          if (group.type === 'Selector' ? check.now !== group.now : (check.fixed || '') !== group.fixed) throw new Error('恢复校验失败：' + group.name);
        });
      } catch (e) { errors.push(group.name + '：' + e.message); }
    }
    // Restore mode even when restoring a node failed.
    try { await retry(async () => { await api('/configs', { method: 'PATCH', data: { mode: j.mode } }); if ((await api('/configs')).mode !== j.mode) throw new Error('模式恢复校验失败'); }); }
    catch (e) { errors.push(e.message); }
    if (errors.length) throw new Error('自动恢复未完成，请点击恢复重试，或在 Clash 手动恢复。\n' + errors.join('\n'));
    GM_deleteValue(KEY);
    state.journal = null;
    refreshRecovery();
  }

  function checkStop() { if (state.stop) throw new Error('已停止'); }
  async function switchNode(node) {
    checkStop();
    // Deepest selection first; GLOBAL is changed last.
    for (const step of [...node.path].reverse()) {
      checkStop();
      await api(pathFor(step.group), { method: 'PUT', data: { name: step.child } });
    }
    await sleep(400);
    checkStop();
    const [cfg, list] = await Promise.all([api('/configs'), api('/proxies')]);
    if (cfg.mode !== 'global' || node.path.some(s => list.proxies?.[s.group]?.now !== s.child)) throw new Error('节点或模式被其他操作改变，本次出口无法确认。');
  }
  async function probeIP(node) {
    checkStop();
    // Close only this dedicated IP-echo host's connections, preventing old HTTP/2 sockets
    // from carrying a new probe through the previously selected node. Never DELETE /connections.
    const old = await api('/connections');
    for (const c of old.connections || []) if (c.metadata?.host?.toLowerCase() === PROBE) await api('/connections/' + encodeURIComponent(c.id), { method: 'DELETE' });
    checkStop();
    const started = Date.now();
    let seen = false;
    let wrong = false;
    let finished = false;
    let pollError = null;
    const ac = new AbortController();
    state.active = ac;
    // Poll while the exact echo request is active. If the connection cannot be observed,
    // fail closed instead of attributing the machine's direct IP to a node.
    const inspect = async () => {
      try {
        const list = await api('/connections', { timeout: 5000 });
        for (const c of list.connections || []) {
          if (c.metadata?.host?.toLowerCase() !== PROBE || !(Date.parse(c.start) >= started - 100)) continue;
          if (Array.isArray(c.chains) && c.chains.includes(node.name)) seen = true;
          else wrong = true;
        }
      } catch (e) { pollError = e; }
    };
    const poll = (async () => { do { await inspect(); if (!finished) await sleep(60); } while (!finished); })();
    let data;
    try { data = await request('https://' + PROBE + '/?format=json&_ipcheck=' + started + '-' + Math.random().toString(36).slice(2), { timeout: 18000, signal: ac.signal }); }
    finally { finished = true; state.active = null; await poll; }
    await inspect();
    checkStop();
    if (!isIP(data?.ip)) throw new Error('出口服务没有返回有效 IP。');
    if (wrong) throw new Error('出口探测连接未经过目标节点，已拒绝记录；请检查代理接管或其他程序切换。');
    if (!seen) throw new Error('无法在 Clash 连接中确认本次出口。请启用系统代理 / TUN；如已启用，重试本节点。' + (pollError ? ' 连接查询失败：' + pollError.message : ''));
    const [cfg, list] = await Promise.all([api('/configs'), api('/proxies')]);
    if (cfg.mode !== 'global' || node.path.some(s => list.proxies?.[s.group]?.now !== s.child)) throw new Error('检测期间代理选择发生变化，已拒绝记录。');
    return { ip: data.ip, verifiedAt: Date.now(), chainsInclude: node.name, source: 'https://' + PROBE };
  }
  async function lookup(ip) {
    checkStop();
    if (state.cache.has(ip)) return state.cache.get(ip);
    const ac = new AbortController();
    state.active = ac;
    try {
      const data = await request(SITE + 'api/check?ip=' + encodeURIComponent(ip), { timeout: 60000, signal: ac.signal });
      if (data?.ip !== ip || !data.derived || !Array.isArray(data.sources)) throw new Error(data?.error || '检测站返回的 IP 或报告结构不匹配。');
      state.cache.set(ip, data);
      return data;
    } finally { state.active = null; }
  }
  async function withLock(task) {
    if (!navigator.locks) throw new Error('当前浏览器不支持 Web Locks，请使用新版 Chrome / Edge。');
    return navigator.locks.request(LOCK, { ifAvailable: true }, async lock => {
      if (!lock) throw new Error('另一个面板正在检测或恢复，请先停止该面板。');
      return task();
    });
  }
  async function run(names) {
    if (state.busy) return;
    try { await withLock(async () => {
      refreshRecovery();
      if (state.journal) throw new Error('请先恢复上次检测前的配置。');
      state.busy = true; state.stop = false; state.cache.clear(); controls();
      let count = 0;
      let total = 0;
      let fatal = '';
      let restoreError = '';
      try {
        status('读取配置并保存恢复记录…');
        const proxies = await load();
        const nodes = state.nodes.filter(n => names.has(n.name) && n.path);
        total = nodes.length;
        if (!total) throw new Error('没有可检测节点，请先选择节点。');
        const cfg = await api('/configs');
        if (!['rule', 'global', 'direct'].includes(cfg.mode)) throw new Error('无法识别当前代理模式，已取消。');
        checkStop();
        await saveJournal(cfg.mode, proxies, nodes);
        await api('/configs', { method: 'PATCH', data: { mode: 'global' } });
        $('#progress').hidden = false; $('#progress').max = total; $('#progress').value = 0;
        for (const node of nodes) {
          if (state.stop) break;
          const result = { name: node.name, status: '切换中' };
          state.results.set(node.name, result); render();
          status('[' + (count + 1) + '/' + total + '] ' + node.name + ' · 切换节点');
          try {
            await switchNode(node);
            result.status = '读取出口'; render();
            const evidence = await probeIP(node);
            result.ip = evidence.ip; result.evidence = evidence;
            result.status = '查询报告'; render();
            status('[' + (count + 1) + '/' + total + '] ' + node.name + ' · ' + result.ip + ' · 查询 IP 报告');
            result.data = await lookup(result.ip);
            checkStop();
            result.status = '完成';
          } catch (e) {
            result.status = state.stop ? '已停止' : '失败 / 未确认';
            result.error = e.message;
            if (/429/.test(e.message)) { state.stop = true; fatal = '检测站限流，已停止批量检测。'; }
          } finally { result.finished = Date.now(); saveHistory(); count++; $('#progress').value = count; render(); }
          if (!state.stop) await sleep(800);
        }
      } catch (e) { fatal = e.message; }
      finally {
        status('正在恢复检测前的节点与模式…');
        try { await restore(); } catch (e) { restoreError = e.message; }
        state.busy = false; state.active = null; refreshRecovery(); render();
        status([fatal || (state.stop ? '已停止。' : '检测结束。') + '已处理 ' + count + ' / ' + total + ' 个节点。', restoreError || (count || total ? '已恢复检测前的节点与模式。' : '')].filter(Boolean).join('\n'));
      }
    }); } catch (e) { status(e.message); }
  }

  function kv(rows) { return rows.map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join(''); }
  function detail(name) {
    const r = state.results.get(name);
    if (!r?.data) return '';
    const data = r.data, d = data.derived, e = data.extra || {};
    const report = reportURL(r.ip);
    const sourceFields = [['国家', 'country'], ['地区', 'region'], ['城市', 'city'], ['运营商', 'isp'], ['组织', 'org'], ['ASN', 'asn'], ['类型', 'type'], ['风控分', 'risk'], ['代理标记', 'proxy'], ['机房标记', 'hosting'], ['移动网络', 'mobile'], ['时区', 'timezone'], ['纬度', 'lat'], ['经度', 'lon']];
    const lists = [['综合黑名单', e.dnsbl], ['邮件黑名单', e.dnsbl_mail]].map(([title, rows]) => `<div class="card"><h3>${title}</h3>${rows?.length ? rows.map(b => `<p><span class="tag ${b.status === 'listed' ? 'error' : b.status === 'clean' ? 'ok' : ''}">${esc(b.status === 'listed' ? '命中' : b.status === 'clean' ? '未命中' : '未知')}</span> ${esc(b.name)}</p>`).join('') : '无数据 / 该 IP 版本不支持'}</div>`).join('');
    return `<div class="detailhead"><div><h2>${esc(name)}</h2><span class="mono muted">${esc(r.ip)} · ${esc(new Date(r.finished).toLocaleString())}</span></div><div class="actions"><a class="link" href="${esc(report)}" target="_blank" rel="noopener noreferrer">打开原检测页 ↗</a></div></div>
      <div class="card"><div class="hero">${esc(d.coefficient?.value)} <span class="muted">/ 100</span> · ${esc(d.coefficient?.band)}</div><p>${esc(d.verdict)}</p><p>${(d.alerts || []).map(x => `<span class="tag warn">${esc(x)}</span> `).join('')}${(d.goods || []).map(x => `<span class="tag ok">${esc(x)}</span> `).join('')}</p><p class="notice">以下为检测站 JSON 接口完整报告，直接在当前节点下方展示；原页面的浏览器 WebRTC 交互不属于节点质量数据。</p></div>
      <div class="detailgrid"><div class="card"><h3>综合评估</h3>${kv([['风控分', d.risk], ['类型', d.type], ['来源属性', d.origin], ['代理标记', d.proxy_any], ['机房标记', d.hosting_any], ['AI 友好度（推测）', d.ai?.level], ['AI 判定依据', d.ai?.reason], ['独享倾向（推测）', d.share?.level], ['独享依据', d.share?.basis?.join('；')], ['类型依据', d.reasons?.join('；')]])}</div>
      <div class="card"><h3>地区与一致性</h3>${kv([['国家', d.geo?.country], ['城市', d.geo?.city], ['运营商', d.geo?.isp], ['定位存在分歧', d.disagreement], ['最大距离（km）', d.max_km], ['分歧数据源', d.far?.join(' / ')], ['国家一致性', d.consensus?.country?.join(' / ')], ['城市一致性', d.consensus?.city?.join(' / ')], ['出口校验', r.evidence?.chainsInclude], ['站点报告时间', data.checked_at ? new Date(data.checked_at * 1000).toLocaleString() : null]])}</div>
      <div class="card"><h3>适用场景（站点评估，非实测解锁）</h3>${kv((d.scenarios || []).map(s => [s.name, '★'.repeat(Math.max(0, Math.min(5, Number(s.stars) || 0))) + ' ' + s.stars + '/5']))}<h3 style="margin-top:18px">系数构成</h3>${kv((d.coefficient?.parts || []).map(p => [p.label, p.pts + ' 分']))}</div>
      <div class="card"><h3>注册与路由</h3>${kv([['IP 地址段', e.rdap?.start ? e.rdap.start + ' – ' + e.rdap.end : null], ['网段名称', e.rdap?.name], ['注册组织', e.rdap?.org], ['注册国家', e.rdap?.country], ['注册日期', e.rdap?.registered], ['反查域名', e.ptr], ['路由前缀', e.ripe?.prefix], ['宣告 AS', e.ripe?.asns?.join(' / ')], ['IP 数字形式', data.ipnum], ['Tor 出口', e.tor]])}</div>
      ${lists}<div class="card"><h3>Shodan InternetDB</h3>${e.idb?.ok ? kv([['开放端口', e.idb.ports?.join(', ')], ['服务标签', e.idb.tags?.join(' / ')], ['关联主机名', e.idb.hostnames?.join(' / ')], ['已知漏洞', Array.isArray(e.idb.vulns) ? e.idb.vulns.join(' / ') : e.idb.vulns]]) : '<p class="muted">无记录；不代表没有开放端口。</p>'}</div></div>
      <div class="card"><h3>数据源对比</h3><div class="tablewrap"><table class="source"><thead><tr><th>项目</th>${data.sources.map(s => `<th>${esc(s.source)}<small>${s.ok ? '查询成功' : '查询失败'}</small></th>`).join('')}</tr></thead><tbody>${sourceFields.map(([label, key]) => `<tr><td>${label}</td>${data.sources.map(s => `<td>${esc(s[key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div></div>
      <div class="card"><details><summary>完整原始 JSON（含所有额外字段）</summary><pre>${esc(JSON.stringify(data, null, 2))}</pre></details></div>`;
  }
  let lastFocus;
  let oldOverflow;
  function openPanel() {
    lastFocus = document.activeElement; oldOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = 'hidden';
    $('#panel').hidden = false; $('#launch').hidden = true; $('#launch').setAttribute('aria-expanded', 'true');
    refreshRecovery(); $('#secret').focus();
  }
  function stop() { state.stop = true; state.active?.abort(); controls(); status('正在停止；当前控制器操作结束后恢复配置…'); }
  function closePanel() {
    if (state.busy) stop();
    $('#panel').hidden = true; $('#launch').hidden = false; $('#launch').setAttribute('aria-expanded', 'false');
    document.documentElement.style.overflow = oldOverflow || ''; (lastFocus?.isConnected ? lastFocus : $('#launch')).focus();
  }
  $('#launch').onclick = openPanel;
  $('#close').onclick = closePanel;
  $('#stop').onclick = stop;
  $('#load').onclick = async () => { if (state.busy) return; state.busy = true; controls(); try { await load(); status('节点已加载。选择单个节点或开始批量检测。'); } catch (e) { status(e.message); } finally { state.busy = false; controls(); } };
  $('#all').onclick = () => run(new Set(state.nodes.filter(n => n.path).map(n => n.name)));
  $('#chosen').onclick = () => run(new Set(state.selected));
  $('#search').oninput = render;
  $('#region').onchange = render;
  $('#qualitySort').onclick = () => { state.sort = state.sort === 'desc' ? 'asc' : 'desc'; render(); $('#qualitySort').focus(); };
  $('#selectAll').onchange = event => { for (const n of state.visible.filter(n => n.path)) { if (event.target.checked) state.selected.add(n.name); else state.selected.delete(n.name); } render(); };
  $('#rows').onchange = event => { const n = state.nodes[Number(event.target.dataset.select)]; if (!n) return; if (event.target.checked) state.selected.add(n.name); else state.selected.delete(n.name); render(); };
  $('#rows').onclick = event => { const b = event.target.closest('button'); if (!b) return; if (b.dataset.run !== undefined) run(new Set([state.nodes[Number(b.dataset.run)].name])); if (b.dataset.detail !== undefined) { const n = state.nodes[Number(b.dataset.detail)]; if (!state.results.get(n.name)?.data) return; if (state.expanded.has(n.name)) state.expanded.delete(n.name); else state.expanded.add(n.name); const index = b.dataset.detail; render(); root.querySelector(`[data-node="${index}"] td:last-child [data-detail]`)?.focus({ preventScroll: true }); } };
  $('#restore').onclick = async () => {
    if (state.busy) return;
    try { await withLock(async () => { state.busy = true; controls(); status('正在恢复…'); try { await restore(); status('已恢复检测前的节点与模式。'); } finally { state.busy = false; refreshRecovery(); } }); }
    catch (e) { status(e.message); }
  };
  $('#clearHistory').onclick = () => {
    if (state.busy || !confirm('清空所有已保存的检测记录？不会删除节点或待恢复的代理配置。')) return;
    try {
      GM_deleteValue(HISTORY);
      state.results.clear(); state.cache.clear(); state.expanded.clear();
      $('#region').value = ''; $('#search').value = '';
      $('#historyStatus').textContent = '检测记录已清空。下次检测后会重新自动保存。';
      render();
    } catch (e) { $('#historyStatus').textContent = '清空失败：' + e.message; }
  };
  $('#export').onclick = () => {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), source: SITE, results: [...state.results.values()] }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'clash-ipcheck-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  root.addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); closePanel(); }
    if (event.key === 'Tab' && !$('#panel').hidden) {
      const area = $('#panel');
      const items = [...area.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),summary')].filter(el => el.getClientRects().length);
      const first = items[0], last = items.at(-1);
      if (event.shiftKey && root.activeElement === first) { last?.focus(); event.preventDefault(); }
      if (!event.shiftKey && root.activeElement === last) { first?.focus(); event.preventDefault(); }
    }
  });
  window.addEventListener('beforeunload', event => { if (state.busy && state.journal) { event.preventDefault(); event.returnValue = ''; } });
  restoreHistory(); refreshRecovery(); render();
})();
