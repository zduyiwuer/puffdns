'use strict';

/* puffdns panel — vanilla JS, no build step, no framework. */

(function () {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    view: 'dashboard',
    me: null,
    zones: [],
    zone: null,        // currently inspected zone
    meta: null,
    queries: null,
    health: null,
    recordFilter: { q: '', type: '' },
  };

  // ── API ──────────────────────────────────────────────────────────────

  async function api(method, path, body, opts = {}) {
    const init = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined && body !== null) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    if (res.status === 401 && !opts.allowAnon) {
      showLogin();
      throw new Error('登录已失效');
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error((data && data.error) || `HTTP ${res.status}`);
      err.status = res.status;
      err.details = data && data.details;
      throw err;
    }
    return data;
  }

  const GET = (p, o) => api('GET', p, null, o);
  const POST = (p, b, o) => api('POST', p, b, o);
  const PUT = (p, b) => api('PUT', p, b);
  const DEL = (p) => api('DELETE', p);

  // ── UI helpers ───────────────────────────────────────────────────────

  function toast(message, kind) {
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = message;
    $('#toast').appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity .2s';
      setTimeout(() => el.remove(), 220);
    }, kind === 'err' ? 5200 : 2600);
  }

  const esc = (s) =>
    String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );

  const fmtNum = (n) => (n === undefined || n === null ? '—' : Number(n).toLocaleString('en-US'));

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-CA', { hour12: false });
  }

  function relTime(iso) {
    if (!iso) return '从未';
    const diff = Date.now() - new Date(iso).getTime();
    if (Number.isNaN(diff)) return '—';
    const s = Math.floor(diff / 1000);
    if (s < 60) return `${s} 秒前`;
    if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
    if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
    return `${Math.floor(s / 86400)} 天前`;
  }

  function bytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function empty(icon, text, actionHtml) {
    return `<div class="empty"><div class="big">${icon}</div><p>${esc(text)}</p>${actionHtml || ''}</div>`;
  }

  // ── Modal ────────────────────────────────────────────────────────────

  let modalResolve = null;

  function openModal({ title, body, confirmText = '确定', danger = false, onConfirm, wide }) {
    return new Promise((resolve) => {
      $('#modal-title').textContent = title;
      $('#modal-body').innerHTML = body;
      const foot = $('#modal-foot');
      foot.innerHTML = '';

      const cancel = document.createElement('button');
      cancel.className = 'btn';
      cancel.textContent = '取消';
      cancel.onclick = () => closeModal(null);

      const ok = document.createElement('button');
      ok.className = 'btn ' + (danger ? 'btn-danger' : 'btn-primary');
      ok.textContent = confirmText;
      ok.onclick = async () => {
        if (!onConfirm) return closeModal(true);
        ok.disabled = true;
        const original = ok.textContent;
        ok.textContent = '处理中…';
        try {
          const result = await onConfirm($('#modal-body'));
          closeModal(result === undefined ? true : result);
        } catch (err) {
          toast(err.message, 'err');
          ok.disabled = false;
          ok.textContent = original;
        }
      };

      foot.append(cancel, ok);
      $('#modal').hidden = false;
      modalResolve = resolve;

      const first = $('#modal-body input, #modal-body select, #modal-body textarea');
      if (first) setTimeout(() => first.focus(), 40);
    });
  }

  function closeModal(value) {
    $('#modal').hidden = true;
    $('#modal-body').innerHTML = '';
    if (modalResolve) {
      const r = modalResolve;
      modalResolve = null;
      r(value);
    }
  }

  $('#modal-close').onclick = () => closeModal(null);
  $('#modal').addEventListener('mousedown', (e) => { if (e.target.id === 'modal') closeModal(null); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#modal').hidden) closeModal(null); });

  // ── Auth ─────────────────────────────────────────────────────────────

  function showLogin() {
    $('#app').hidden = true;
    $('#login').hidden = false;
    $('#login-pass').value = '';
    setTimeout(() => $('#login-user').focus(), 40);
  }

  function showApp(user) {
    state.me = user;
    $('#login').hidden = true;
    $('#app').hidden = false;
    $('#me').innerHTML = `<strong>${esc(user.username)}</strong>${esc(user.role)}`;
    if (user.role === 'viewer') {
      $$('#nav .nav-item[data-view="users"], #nav .nav-item[data-view="settings"]').forEach((b) => (b.hidden = true));
    }
    refreshHealth();
    render();
  }

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#login-btn');
    const errBox = $('#login-error');
    errBox.hidden = true;
    btn.disabled = true;
    btn.textContent = '登录中…';
    try {
      const res = await POST('/api/login', {
        username: $('#login-user').value.trim(),
        password: $('#login-pass').value,
      }, { allowAnon: true });
      showApp(res.user);
    } catch (err) {
      errBox.textContent = err.message;
      errBox.hidden = false;
      $('#login-pass').select();
    } finally {
      btn.disabled = false;
      btn.textContent = '登录';
    }
  });

  $('#logout').onclick = async () => {
    await POST('/api/logout').catch(() => {});
    state.me = null;
    showLogin();
  };

  // ── Health ───────────────────────────────────────────────────────────

  async function refreshHealth() {
    const pill = $('#health-pill');
    try {
      const h = await GET('/api/health', { allowAnon: true });
      state.health = h;
      pill.className = 'pill up';
      pill.innerHTML = `<span class="dot"></span>运行中 · ${h.uptime}s`;
    } catch {
      pill.className = 'pill down';
      pill.innerHTML = '<span class="dot"></span>无法连接';
    }
  }

  // ── Navigation ───────────────────────────────────────────────────────

  $$('#nav .nav-item').forEach((btn) => {
    btn.onclick = () => {
      state.view = btn.dataset.view;
      render();
    };
  });

  $('#refresh').onclick = () => { refreshHealth(); render(); toast('已刷新'); };

  const TITLES = {
    dashboard: '概览', zones: '域名', records: '解析记录',
    ddns: 'DDNS', queries: '查询日志', settings: '设置', users: '用户',
  };

  function render() {
    if (!state.me) return;
    $$('#nav .nav-item[data-view]').forEach((b) =>
      b.classList.toggle('active', b.dataset.view === state.view)
    );
    $('#view-title').textContent = TITLES[state.view] || state.view;
    const view = {
      dashboard: viewDashboard,
      zones: viewZones,
      records: viewRecords,
      ddns: viewDdns,
      queries: viewQueries,
      settings: viewSettings,
      users: viewUsers,
    }[state.view];
    if (view) view();
  }

  // ── Views ────────────────────────────────────────────────────────────

  // Dashboard
  async function viewDashboard() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      const meta = await GET('/api/meta');
      state.meta = meta;
      const s = meta.stats;
      const ql = meta.queryLog;
      const cache = s.cache;

      const hitRate = (cache.hitRate * 100).toFixed(1);

      c.innerHTML = `
        <div class="stats">
          <div class="stat">
            <div class="label">总查询数</div>
            <div class="value">${fmtNum(s.queries)}</div>
            <div class="sub">QPS ${ql.qps}</div>
          </div>
          <div class="stat">
            <div class="label">缓存命中率</div>
            <div class="value">${hitRate}%</div>
            <div class="sub">${fmtNum(cache.entries)} 条缓存 / ${fmtNum(cache.hits)} 命中</div>
          </div>
          <div class="stat">
            <div class="label">权威应答</div>
            <div class="value">${fmtNum(s.authoritative)}</div>
            <div class="sub">转发 ${fmtNum(s.forwarded)} · 缓存 ${fmtNum(s.cached)}</div>
          </div>
          <div class="stat">
            <div class="label">平均响应</div>
            <div class="value">${ql.latency.avg}<span style="font-size:15px"> ms</span></div>
            <div class="sub">P95 ${ql.latency.p95} ms · 成功率 ${ql.successRate}%</div>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-head">查询类型分布</div>
            <div class="card-body">${barList(ql.topTypes, '次')}</div>
          </div>
          <div class="card">
            <div class="card-head">响应状态</div>
            <div class="card-body">${barList(ql.topResponses.map((r) => ({ key: r.key, count: r.count })), '次', true)}</div>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-head">最常查询的客户端</div>
            <div class="card-body">${barList(ql.topClients, '次')}</div>
          </div>
          <div class="card">
            <div class="card-head">上游解析器</div>
            <div class="card-body">
              <table>
                <thead><tr><th>地址</th><th class="num">查询</th><th class="num">超时</th><th class="num">失败</th></tr></thead>
                <tbody>
                  ${meta.upstream.map((u) => `
                    <tr>
                      <td class="mono">${esc(u.host)}:${u.port}<span class="muted"> / ${esc(u.proto)}</span></td>
                      <td class="num">${fmtNum(s.upstream.udpQueries + s.upstream.tcpQueries)}</td>
                      <td class="num">${fmtNum(s.upstream.timeouts)}</td>
                      <td class="num">${fmtNum(s.upstream.failures)}</td>
                    </tr>`).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">系统信息</div>
          <div class="card-body">
            <table>
              <tbody>
                <tr><td class="muted">主机名</td><td class="mono">${esc(meta.system.hostname)}</td>
                    <td class="muted">运行时间</td><td>${fmtNum(ql.uptimeSeconds)} 秒</td></tr>
                <tr><td class="muted">平台</td><td class="mono">${esc(meta.system.platform)}</td>
                    <td class="muted">内存</td><td>${meta.system.memoryMB} MB</td></tr>
                <tr><td class="muted">Node</td><td class="mono">${esc(meta.system.nodeVersion)}</td>
                    <td class="muted">CPU 核心</td><td>${meta.system.cpus}</td></tr>
                <tr><td class="muted">域名 / 记录</td><td>${fmtNum(meta.zones)} / ${fmtNum(meta.records)}</td>
                    <td class="muted">默认 TTL</td><td>${meta.defaults.ttl}s</td></tr>
              </tbody>
            </table>
          </div>
        </div>`;
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  function barList(items, unit, colorByKey) {
    if (!items || !items.length) return empty('—', '暂无数据');
    const max = Math.max(...items.map((i) => i.count));
    return items.map((i) => {
      let color = 'var(--accent)';
      if (colorByKey) {
        if (i.key === 'NOERROR') color = 'var(--ok)';
        else if (i.key === 'NXDOMAIN') color = 'var(--warn)';
        else color = 'var(--err)';
      }
      return `
        <div class="bar-row">
          <div class="name" title="${esc(i.key)}">${esc(i.key)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(i.count / max) * 100}%;background:${color}"></div></div>
          <div class="val">${fmtNum(i.count)}</div>
        </div>`;
    }).join('');
  }

  // Zones
  async function viewZones() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      state.zones = await GET('/api/zones');
      c.innerHTML = `
        <div class="card">
          <div class="card-head">
            <span>域名列表 <span class="muted small">(${state.zones.length})</span></span>
            <button class="btn btn-primary btn-sm" id="add-zone">+ 添加域名</button>
          </div>
          <div class="card-body flush">
            ${
              state.zones.length === 0
                ? empty('▤', '还没有添加任何域名', '<button class="btn btn-primary" id="add-zone-empty">+ 添加第一个域名</button>')
                : `<table>
                    <thead><tr>
                      <th>域名</th><th>类型</th><th class="num">记录数</th><th>NS 服务器</th><th>更新于</th><th></th>
                    </tr></thead>
                    <tbody>
                      ${state.zones.map((z) => `
                        <tr>
                          <td><strong>${esc(z.name)}</strong></td>
                          <td><span class="tag accent">${esc(z.type)}</span></td>
                          <td class="num">${fmtNum(z.recordCount)}</td>
                          <td class="mono small">${(z.ns || []).map(esc).join(', ')}</td>
                          <td class="muted small nowrap">${relTime(z.updatedAt)}</td>
                          <td class="actions">
                            <button class="btn btn-sm" data-open="${esc(z.name)}">管理</button>
                            <button class="btn btn-sm btn-ghost" data-export="${esc(z.name)}">导出</button>
                            <button class="btn btn-sm btn-ghost" data-del="${esc(z.name)}">删除</button>
                          </td>
                        </tr>`).join('')}
                    </tbody></table>`
            }
          </div>
        </div>

        <div class="card">
          <div class="card-head">DNS 委派说明</div>
          <div class="card-body">
            <p class="small muted" style="margin-top:0">要让公网解析命中本服务器，请在域名注册商处把 NS 记录指向本机 IP：</p>
            <pre class="snippet">;; 在注册商的 NS 设置中填写：
${state.zones.map((z) => `${esc(z.name)}.  NS  ${esc((z.ns || [])[0] || `ns1.${z.name}`)}`).join('\n') || ';; 添加域名后这里会显示对应的 NS 记录'}

;; 同时确保本机 IP 可达 53/udp 与 53/tcp，例如 A 记录：
;; ${state.zones.map((z) => `${esc((z.ns || [])[0] || `ns1.${z.name}`)}  A  <你的公网IP>`).join('\n') || ''}</pre>
          </div>
        </div>`;

      const add = () => openZoneModal();
      $('#add-zone') && ($('#add-zone').onclick = add);
      $('#add-zone-empty') && ($('#add-zone-empty').onclick = add);
      $$('[data-open]', c).forEach((b) => (b.onclick = () => openZone(b.dataset.open)));
      $$('[data-export]', c).forEach((b) => (b.onclick = () => exportZone(b.dataset.export)));
      $$('[data-del]', c).forEach(
        (b) => (b.onclick = () =>
          openModal({
            title: '删除域名',
            body: `<p>确定要删除 <strong>${esc(b.dataset.del)}</strong> 及其全部 ${state.zones.find((z) => z.name === b.dataset.del).recordCount} 条记录吗？此操作不可撤销。</p>`,
            confirmText: '删除',
            danger: true,
            onConfirm: async () => { await DEL(`/api/zones/${encodeURIComponent(b.dataset.del)}`); toast('已删除', 'ok'); render(); },
          }))
      );
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  function openZoneModal(existing) {
    const z = existing || null;
    openModal({
      title: z ? `编辑 ${z.name}` : '添加域名',
      body: `
        <label class="field">
          <span>域名</span>
          <input type="text" id="z-name" value="${esc(z ? z.name : '')}" placeholder="example.com" ${z ? 'disabled' : ''}>
          ${z ? '<div class="hint">域名创建后不可修改</div>' : '<div class="hint">顶级域名，例如 example.com，不要带 http://</div>'}
        </label>
        <div class="row">
          <label class="field"><span>默认 TTL（秒）</span><input type="number" id="z-ttl" value="${z ? z.ttl : 300}" min="0"></label>
          <label class="field"><span>SOA 最小 TTL</span><input type="number" id="z-min" value="${z && z.soa ? z.soa.minimum : 60}" min="0"></label>
        </div>
        <label class="field">
          <span>NS 服务器（逗号分隔）</span>
          <input type="text" id="z-ns" value="${esc(z ? (z.ns || []).join(',') : '')}" placeholder="ns1.example.com, ns2.example.com">
        </label>
        <label class="field">
          <span>SOA 主机名</span>
          <input type="text" id="z-mname" value="${esc(z && z.soa ? z.soa.mname : '')}" placeholder="ns1.example.com">
        </label>
        <label class="field">
          <span>SOA 联系人</span>
          <input type="text" id="z-rname" value="${esc(z && z.soa ? z.soa.rname : '')}" placeholder="hostmaster.example.com">
        </label>`,
      confirmText: z ? '保存' : '创建',
      onConfirm: async (root) => {
        const name = $('#z-name', root).value.trim();
        const ns = $('#z-ns', root).value.split(',').map((s) => s.trim()).filter(Boolean);
        const payload = {
          ttl: Number($('#z-ttl', root).value) || 300,
          soa: {
            minimum: Number($('#z-min', root).value) || 60,
            mname: $('#z-mname', root).value.trim(),
            rname: $('#z-rname', root).value.trim(),
          },
        };
        if (ns.length) payload.ns = ns;

        if (z) {
          await PUT(`/api/zones/${encodeURIComponent(z.name)}`, payload);
          toast('已保存', 'ok');
        } else {
          if (!name) throw new Error('请填写域名');
          payload.name = name;
          if (!ns.length) payload.ns = [`ns1.${name}`];
          await POST('/api/zones', payload);
          toast('域名已创建', 'ok');
        }
        render();
      },
    });
  }

  async function exportZone(name) {
    try {
      const res = await fetch(`/api/zones/${encodeURIComponent(name)}export`);
      if (!res.ok) throw new Error('导出失败');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${name}.zone`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast('已导出', 'ok');
    } catch (err) {
      toast(err.message, 'err');
    }
  }

  // Records
  async function viewRecords() {
    const c = $('#content');
    if (!state.zones.length) {
      try { state.zones = await GET('/api/zones'); } catch { /* handled below */ }
    }
    if (!state.zones.length) {
      c.innerHTML = empty('▤', '请先添加一个域名');
      return;
    }
    if (!state.zone || !state.zones.find((z) => z.name === state.zone)) state.zone = state.zones[0].name;

    c.innerHTML = `
      <div class="card">
        <div class="card-head">
          <span>解析记录</span>
          <div style="display:flex;gap:8px;align-items:center">
            <select id="zone-pick">${state.zones.map((z) => `<option value="${esc(z.name)}"${z.name === state.zone ? ' selected' : ''}>${esc(z.name)}</option>`).join('')}</select>
            <button class="btn btn-sm" id="import-btn">批量导入</button>
            <button class="btn btn-primary btn-sm" id="add-record">+ 添加记录</button>
          </div>
        </div>
        <div class="card-body">
          <div class="filters">
            <input type="text" id="fq" placeholder="搜索名称或内容…" value="${esc(state.recordFilter.q)}">
            <select id="ft">
              <option value="">全部类型</option>
              ${['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'DNAME', 'SPF']
                .map((t) => `<option value="${t}"${state.recordFilter.type === t ? ' selected' : ''}>${t}</option>`).join('')}
            </select>
            <span class="muted small" id="rec-count"></span>
          </div>
          <div id="rec-table"><div class="empty"><span class="spin"></span></div></div>
        </div>
      </div>`;

    $('#zone-pick').onchange = (e) => { state.zone = e.target.value; loadRecords(); };
    $('#fq').oninput = debounce((e) => { state.recordFilter.q = e.target.value; paintRecords(); }, 200);
    $('#ft').onchange = (e) => { state.recordFilter.type = e.target.value; paintRecords(); };
    $('#add-record').onclick = () => openRecordModal();
    $('#import-btn').onclick = () => openImportModal();

    loadRecords();
  }

  async function loadRecords() {
    try {
      state.zoneData = await GET(`/api/zones/${encodeURIComponent(state.zone)}`);
      paintRecords();
    } catch (err) {
      $('#rec-table').innerHTML = empty('⚠', err.message);
    }
  }

  function paintRecords() {
    const box = $('#rec-table');
    if (!box || !state.zoneData) return;
    const { q, type } = state.recordFilter;
    const needle = q.trim().toLowerCase();
    const rows = state.zoneData.records.filter((r) => {
      if (type && r.type !== type) return false;
      if (!needle) return true;
      return (r.name + ' ' + r.data).toLowerCase().includes(needle);
    });

    $('#rec-count').textContent = `${rows.length} / ${state.zoneData.records.length} 条`;

    if (!rows.length) {
      box.innerHTML = empty('≡', state.zoneData.records.length ? '没有匹配的记录' : '该域名还没有解析记录',
        state.zoneData.records.length ? '' : '<button class="btn btn-primary" id="add-record-empty">+ 添加记录</button>');
      const b = $('#add-record-empty');
      if (b) b.onclick = () => openRecordModal();
      return;
    }

    box.innerHTML = `
      <table>
        <thead><tr>
          <th>名称</th><th>类型</th><th>内容</th><th class="num">TTL</th><th>备注</th><th></th>
        </tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td class="mono"><strong>${esc(r.name || '@')}</strong></td>
              <td><span class="tag">${esc(r.type)}</span></td>
              <td class="mono truncate" title="${esc(r.data)}">${esc(r.data)}</td>
              <td class="num">${r.ttl}</td>
              <td class="muted small truncate">${esc(r.note || '')}</td>
              <td class="actions">
                <button class="btn btn-sm" data-edit="${r.id}">编辑</button>
                <button class="btn btn-sm btn-ghost" data-rm="${r.id}">删除</button>
              </td>
            </tr>`).join('')}
        </tbody>
      </table>`;

    $$('[data-edit]', box).forEach((b) => (b.onclick = () => openRecordModal(state.zoneData.records.find((r) => r.id === b.dataset.edit))));
    $$('[data-rm]', box).forEach(
      (b) => (b.onclick = () =>
        openModal({
          title: '删除记录',
          body: '<p>确定删除这条解析记录吗？</p>',
          confirmText: '删除',
          danger: true,
          onConfirm: async () => { await DEL(`/api/records/${b.dataset.rm}`); toast('已删除', 'ok'); loadRecords(); },
        }))
    );
  }

  function recordFields(rec) {
    const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'DNAME', 'SPF'];
    return `
      <div class="row">
        <label class="field">
          <span>名称</span>
          <input type="text" id="r-name" value="${esc(rec ? rec.name : '')}" placeholder="@ 或 www">
          <div class="hint">@ 表示根域名，支持 *. 通配符</div>
        </label>
        <label class="field">
          <span>类型</span>
          <select id="r-type">${types.map((t) => `<option${rec && rec.type === t ? ' selected' : ''}>${t}</option>`).join('')}</select>
        </label>
      </div>
      <label class="field">
        <span>内容</span>
        <input type="text" id="r-data" value="${esc(rec ? rec.data : '')}" placeholder="依类型而定，例如 1.2.3.4">
        <div class="hint" id="r-hint"></div>
      </label>
      <div class="row">
        <label class="field"><span>TTL（秒）</span><input type="number" id="r-ttl" value="${rec ? rec.ttl : 300}" min="0"></label>
        <label class="field"><span>备注</span><input type="text" id="r-note" value="${esc(rec ? rec.note : '')}" placeholder="可选"></label>
      </div>`;
  }

  const HINTS = {
    A: 'IPv4 地址，例如 203.0.113.10',
    AAAA: 'IPv6 地址，例如 2001:db8::1',
    CNAME: '目标域名，例如 target.example.com',
    MX: '优先级 + 邮件服务器，例如 10 mail.example.com',
    TXT: '任意文本，常用于 SPF / 域名验证',
    NS: '子域的权威服务器，例如 ns1.example.com',
    SRV: '优先级 权重 端口 目标，例如 0 5 443 target.example.com',
    CAA: '标志 标签 值，例如 0 issue letsencrypt.org',
    PTR: '反向解析名称',
    DNAME: '重定向整个子域',
    SPF: 'SPF 记录文本，例如 v=spf1 -all',
  };

  function openRecordModal(rec) {
    const editing = !!rec;
    openModal({
      title: editing ? '编辑记录' : `为 ${state.zone} 添加记录`,
      body: recordFields(rec),
      confirmText: editing ? '保存' : '添加',
      onConfirm: async (root) => {
        const payload = {
          name: $('#r-name', root).value.trim(),
          type: $('#r-type', root).value,
          data: $('#r-data', root).value.trim(),
          ttl: Number($('#r-ttl', root).value) || 300,
          note: $('#r-note', root).value.trim(),
        };
        if (!payload.data) throw new Error('请填写记录内容');
        if (editing) await PUT(`/api/records/${rec.id}`, payload);
        else await POST(`/api/zones/${encodeURIComponent(state.zone)}/records`, payload);
        toast(editing ? '已保存' : '已添加', 'ok');
        loadRecords();
      },
    });

    const syncHint = () => { $('#r-hint').textContent = HINTS[$('#r-type').value] || ''; };
    setTimeout(() => { syncHint(); $('#r-type').onchange = syncHint; }, 30);
  }

  function openImportModal() {
    openModal({
      title: `批量导入到 ${state.zone}`,
      body: `
        <label class="field">
          <span>每行一条记录</span>
          <textarea id="i-text" placeholder="www 300 IN A 203.0.113.10&#10;@ 300 IN TXT &quot;v=spf1 -all&quot;&#10;mail 300 IN A 203.0.113.20"></textarea>
          <div class="hint">格式：<code class="inline">名称 [TTL] [IN] 类型 内容</code>，以 ; 开头的行会被忽略</div>
        </label>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px">
          <input type="checkbox" id="i-replace" style="width:auto"> 导入前清空该域名的现有记录
        </label>
        <div id="i-result" style="margin-top:12px"></div>`,
      confirmText: '导入',
      onConfirm: async (root) => {
        const lines = $('#i-text', root).value.split('\n').map((l) => l.trim()).filter(Boolean);
        if (!lines.length) throw new Error('请输入至少一行记录');
        const res = await POST(`/api/zones/${encodeURIComponent(state.zone)}/import`, {
          lines,
          replace: $('#i-replace', root).checked,
        });
        if (res.errors && res.errors.length) {
          $('#i-result').innerHTML =
            `<div class="tag warn">成功 ${res.added} 条，失败 ${res.errors.length} 条</div>` +
            res.errors.map((e) => `<div class="small muted">第 ${e.line} 行：${esc(e.error)}</div>`).join('');
        }
        toast(`导入完成，成功 ${res.added} 条`, 'ok');
        loadRecords();
        return false;
      },
    });
  }

  // DDNS
  async function viewDdns() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      const [tokens, health] = await Promise.all([GET('/api/tokens'), GET('/api/health', { allowAnon: true })]);
      const origin = location.origin;

      c.innerHTML = `
        <div class="card">
          <div class="card-head">
            <span>DDNS 令牌</span>
            <button class="btn btn-primary btn-sm" id="add-token">+ 新建令牌</button>
          </div>
          <div class="card-body flush">
            ${
              tokens.length === 0
                ? empty('↻', '还没有 DDNS 令牌')
                : `<table>
                    <thead><tr><th>名称</th><th>域名</th><th>主机名</th><th>令牌</th><th class="num">调用</th><th>最近使用</th><th></th></tr></thead>
                    <tbody>
                      ${tokens.map((t) => `
                        <tr>
                          <td><strong>${esc(t.name)}</strong></td>
                          <td class="mono small">${esc(t.zone)}</td>
                          <td class="mono small">${esc(t.hostname || '@')}</td>
                          <td class="mono small muted">${esc(t.preview)}</td>
                          <td class="num">${fmtNum(t.useCount)}</td>
                          <td class="muted small nowrap">${relTime(t.lastUsed)}</td>
                          <td class="actions">
                            <button class="btn btn-sm" data-use="${t.id}">用法</button>
                            <button class="btn btn-sm btn-ghost" data-rmtok="${t.id}">删除</button>
                          </td>
                        </tr>`).join('')}
                    </tbody></table>`
            }
          </div>
        </div>

        <div class="card">
          <div class="card-head">通用 DDNS 客户端配置</div>
          <div class="card-body">
            <p class="small muted" style="margin-top:0">大多数支持 HTTP 更新的客户端（ddns-go、inadyn、aliyun ddns 等）都可以直接使用下面的地址：</p>
            <pre class="snippet"># 上报 IPv4（客户端自动探测则省略 ipv4 参数）
curl "${origin}/api/ddns/update?token=&lt;TOKEN&gt;&amp;hostname=home.example.com&amp;ipv4=1.2.3.4"

# 同时上报 IPv4 与 IPv6
curl "${origin}/api/ddns/update?token=&lt;TOKEN&gt;&amp;ipv4=1.2.3.4&amp;ipv6=2001:db8::1"

# 清空该主机的 A / AAAA 记录
curl "${origin}/api/ddns/update?token=&lt;TOKEN&gt;&amp;hostname=home.example.com&amp;clear=true"</pre>
            <p class="small muted" style="margin-bottom:0">成功时返回 JSON，其中 <code class="inline">changes</code> 会列出每条记录的 created / updated / unchanged 状态。</p>
          </div>
        </div>`;

      $('#add-token').onclick = () => openTokenModal();
      $$('[data-use]', c).forEach((b) => (b.onclick = () => showTokenUsage(tokens.find((t) => t.id === b.dataset.use))));
      $$('[data-rmtok]', c).forEach(
        (b) => (b.onclick = () =>
          openModal({
            title: '删除令牌',
            body: '<p>删除后使用该令牌的 DDNS 客户端会立即失效，确定继续吗？</p>',
            confirmText: '删除',
            danger: true,
            onConfirm: async () => { await DEL(`/api/tokens/${b.dataset.rmtok}`); toast('已删除', 'ok'); render(); },
          }))
      );
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  function openTokenModal() {
    openModal({
      title: '新建 DDNS 令牌',
      body: `
        <label class="field"><span>名称（备注）</span><input type="text" id="t-name" placeholder="客厅路由器"></label>
        <label class="field">
          <span>域名</span>
          <select id="t-zone">${state.zones.map((z) => `<option value="${esc(z.name)}">${esc(z.name)}</option>`).join('') || '<option value="">请先添加域名</option>'}</select>
        </label>
        <label class="field">
          <span>限定主机名（可选）</span>
          <input type="text" id="t-host" placeholder="home（留空表示该域名下任意主机）">
          <div class="hint">填写后该令牌只能更新这一个主机名</div>
        </label>`,
      confirmText: '创建',
      onConfirm: async (root) => {
        const res = await POST('/api/tokens', {
          name: $('#t-name', root).value.trim(),
          zone: $('#t-zone', root).value,
          hostname: $('#t-host', root).value.trim(),
        });
        render();
        showTokenUsage(res, true);
      },
    });
  }

  function showTokenUsage(token, isNew) {
    if (!token) return;
    const host = token.hostname || '@';
    const fqdn = host === '@' ? token.zone : `${host}.${token.zone}`;
    openModal({
      title: isNew ? '令牌已创建' : token.name,
      body: `
        ${
          isNew
            ? '<div class="tag warn" style="display:block;margin-bottom:12px;padding:8px 10px">请立即保存此令牌，它只会显示这一次。</div>'
            : ''
        }
        <label class="field">
          <span>令牌</span>
          <input type="text" class="mono" value="${esc(token.token || '')}" readonly style="font-family:var(--mono)">
        </label>
        ${
          token.token
            ? `<pre class="snippet">curl "${location.origin}/api/ddns/update?token=${token.token}&amp;hostname=${fqdn}&amp;ipv4=1.2.3.4"</pre>`
            : '<p class="small muted">出于安全考虑，已创建的令牌不会再次显示明文。</p>'
        }`,
      confirmText: '知道了',
      onConfirm: () => true,
    });
  }

  // Query log
  async function viewQueries() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      state.queries = await GET('/api/queries?limit=300');
      const rows = state.queries.entries;
      c.innerHTML = `
        <div class="card">
          <div class="card-head">
            <span>最近查询 <span class="muted small">(${rows.length} / ${fmtNum(state.queries.stats.total)})</span></span>
            <button class="btn btn-sm btn-ghost" id="clear-q">清空</button>
          </div>
          <div class="card-body">
            <div class="filters">
              <input type="text" id="qq" placeholder="搜索域名 / 客户端…">
              <select id="qtype"><option value="">全部类型</option>
                ${[...new Set(rows.map((r) => r.type))].map((t) => `<option>${esc(t)}</option>`).join('')}</select>
              <select id="qsrc"><option value="">全部来源</option>
                ${[...new Set(rows.map((r) => r.source))].map((t) => `<option>${esc(t)}</option>`).join('')}</select>
            </div>
            <div id="q-table"></div>
          </div>
        </div>`;

      const paint = () => {
        const needle = $('#qq').value.trim().toLowerCase();
        const tf = $('#qtype').value;
        const sf = $('#qsrc').value;
        const filtered = rows.filter((r) => {
          if (tf && r.type !== tf) return false;
          if (sf && r.source !== sf) return false;
          if (!needle) return true;
          return (r.name + ' ' + r.client).toLowerCase().includes(needle);
        });
        const box = $('#q-table');
        if (!filtered.length) { box.innerHTML = empty('◷', '没有匹配的查询'); return; }
        box.innerHTML = `
          <table>
            <thead><tr><th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>状态</th><th>来源</th><th class="num">耗时</th></tr></thead>
            <tbody>${filtered.map((r) => `
              <tr>
                <td class="muted small nowrap">${fmtTime(r.time)}</td>
                <td class="mono small">${esc(r.client)}</td>
                <td class="mono truncate">${esc(r.name)}</td>
                <td><span class="tag">${esc(r.type)}</span></td>
                <td><span class="tag ${r.rcode === 'NOERROR' ? 'ok' : r.rcode === 'NXDOMAIN' ? 'warn' : 'err'}">${esc(r.rcode)}</span></td>
                <td class="small muted">${esc(r.source)}</td>
                <td class="num">${r.ms}ms</td>
              </tr>`).join('')}
            </tbody>
          </table>`;
      };

      paint();
      $('#qq').oninput = debounce(paint, 200);
      $('#qtype').onchange = paint;
      $('#qsrc').onchange = paint;
      $('#clear-q').onclick = () =>
        openModal({
          title: '清空查询日志',
          body: '<p>确定要清空缓冲区中的查询记录吗？统计数据也会一并重置。</p>',
          confirmText: '清空',
          danger: true,
          onConfirm: async () => { await DEL('/api/queries'); toast('已清空', 'ok'); render(); },
        });
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  // Settings
  async function viewSettings() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      const s = await GET('/api/settings');
      const h = await GET('/api/health', { allowAnon: true });
      c.innerHTML = `
        <div class="card">
          <div class="card-head">上游解析器</div>
          <div class="card-body">
            <label class="field">
              <span>上游服务器（逗号分隔）</span>
              <input type="text" id="s-upstream" value="${esc((s.upstreams || []).join(', '))}">
              <div class="hint">支持 udp://host:port、tcp://host:port 显式指定协议；留空默认使用 53 端口</div>
            </label>
            <label class="field">
              <span>访问控制（每行一条）</span>
              <textarea id="s-acl" placeholder="192.168.1.0/24 allow&#10;10.0.0.5 deny">${esc((s.accessRules || []).map((r) => `${r.cidr} ${r.action || 'allow'}`).join('\n'))}</textarea>
              <div class="hint">留空表示允许所有客户端。deny 规则优先于 allow。</div>
            </label>
          </div>
        </div>

        <div class="card">
          <div class="card-head">运行参数</div>
          <div class="card-body">
            <div class="row">
              <label class="field"><span>默认 TTL（秒）</span><input type="number" id="s-ttl" value="${s.defaultTtl || 300}" min="0"></label>
              <label class="field"><span>缓存条目上限</span><input type="number" id="s-cache" value="${s.cacheMaxEntries || 20000}" min="100"></label>
            </div>
            <div class="row">
              <label class="field"><span>查询日志缓冲条数</span><input type="number" id="s-qsize" value="${s.queryLogSize || 1000}" min="10" max="100000"></label>
              <div class="field"><span>开关</span>
                <label style="display:flex;gap:7px;align-items:center;padding-top:7px"><input type="checkbox" id="s-cache-on" style="width:auto" ${s.cacheEnabled !== false ? 'checked' : ''}> 启用缓存</label>
                <label style="display:flex;gap:7px;align-items:center;padding-top:6px"><input type="checkbox" id="s-qlog-on" style="width:auto" ${s.queryLogEnabled !== false ? 'checked' : ''}> 记录查询日志</label>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">连接信息</div>
          <div class="card-body">
            <table><tbody>
              <tr><td class="muted">DNS 端口</td><td class="mono">${h.ports ? esc(h.ports.dns) : '53'} / udp + tcp</td>
                  <td class="muted">Web 面板</td><td class="mono">${esc(location.origin)}</td></tr>
              <tr><td class="muted">DoH 端点</td><td class="mono">${esc(location.origin)}/dns-query</td>
                  <td class="muted">数据目录</td><td class="mono">./data</td></tr>
            </tbody></table>
            <p class="small muted" style="margin-bottom:0">修改 DNS 端口或监听地址需要重启容器，环境变量见 <code class="inline">.env.example</code>。</p>
          </div>
        </div>

        <div style="display:flex;gap:10px">
          <button class="btn btn-primary" id="save-settings">保存设置</button>
          <button class="btn" id="change-pass">修改密码</button>
        </div>`;

      $('#save-settings').onclick = async () => {
        const btn = $('#save-settings');
        btn.disabled = true;
        try {
          const acl = $('#s-acl').value.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
            const [cidr, action] = line.split(/\s+/);
            return { cidr: cidr.trim(), action: (action || 'allow').toLowerCase() };
          });
          await PUT('/api/settings', {
            upstreams: $('#s-upstream').value.split(',').map((s) => s.trim()).filter(Boolean),
            accessRules: acl,
            defaultTtl: Number($('#s-ttl').value) || 300,
            cacheMaxEntries: Number($('#s-cache').value) || 20000,
            cacheEnabled: $('#s-cache-on').checked,
            queryLogEnabled: $('#s-qlog-on').checked,
            queryLogSize: Number($('#s-qsize').value) || 1000,
          });
          toast('设置已保存', 'ok');
          render();
        } catch (err) {
          toast(err.message, 'err');
        } finally {
          btn.disabled = false;
        }
      };

      $('#change-pass').onclick = () =>
        openModal({
          title: '修改密码',
          body: `
            <label class="field"><span>当前密码</span><input type="password" id="p-cur" autocomplete="current-password"></label>
            <label class="field"><span>新密码</span><input type="password" id="p-new" autocomplete="new-password">
              <div class="hint">至少 8 个字符</div></label>`,
          confirmText: '修改',
          onConfirm: async (root) => {
            await POST('/api/me/password', {
              currentPassword: $('#p-cur', root).value,
              newPassword: $('#p-new', root).value,
            });
            toast('密码已修改', 'ok');
          },
        });
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  // Users
  async function viewUsers() {
    const c = $('#content');
    c.innerHTML = '<div class="empty"><span class="spin"></span></div>';
    try {
      const users = await GET('/api/users');
      c.innerHTML = `
        <div class="card">
          <div class="card-head">
            <span>用户 <span class="muted small">(${users.length})</span></span>
            <button class="btn btn-primary btn-sm" id="add-user">+ 添加用户</button>
          </div>
          <div class="card-body flush">
            <table>
              <thead><tr><th>用户名</th><th>角色</th><th>邮箱</th><th>创建时间</th><th>最近登录</th><th></th></tr></thead>
              <tbody>
                ${users.map((u) => `
                  <tr>
                    <td><strong>${esc(u.username)}</strong>${u.username === state.me.username ? ' <span class="tag accent">当前</span>' : ''}</td>
                    <td><span class="tag ${u.role === 'admin' ? 'accent' : ''}">${esc(u.role)}</span></td>
                    <td class="muted small">${esc(u.email || '—')}</td>
                    <td class="muted small nowrap">${fmtTime(u.createdAt)}</td>
                    <td class="muted small nowrap">${relTime(u.lastLogin)}</td>
                    <td class="actions">
                      ${u.username === state.me.username ? '' : `<button class="btn btn-sm btn-ghost" data-rmu="${esc(u.username)}">删除</button>`}
                    </td>
                  </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-head">角色说明</div>
          <div class="card-body">
            <table><tbody>
              <tr><td><span class="tag accent">admin</span></td><td>全部权限，包括删除域名、管理用户与设置</td></tr>
              <tr><td><span class="tag">operator</span></td><td>可增删改记录、DDNS 令牌，不能删除域名或修改设置</td></tr>
              <tr><td><span class="tag">viewer</span></td><td>只读，可查看所有域名与记录</td></tr>
            </tbody></table>
          </div>
        </div>`;

      $('#add-user').onclick = () =>
        openModal({
          title: '添加用户',
          body: `
            <label class="field"><span>用户名</span><input type="text" id="u-name" placeholder="3-32 位字母数字"></label>
            <label class="field"><span>密码</span><input type="password" id="u-pass"><div class="hint">至少 8 个字符</div></label>
            <label class="field"><span>角色</span><select id="u-role">
              <option value="viewer">viewer — 只读</option>
              <option value="operator">operator — 可编辑记录</option>
              <option value="admin">admin — 管理员</option>
            </select></label>
            <label class="field"><span>邮箱（可选）</span><input type="text" id="u-email"></label>`,
          confirmText: '创建',
          onConfirm: async (root) => {
            await POST('/api/users', {
              username: $('#u-name', root).value.trim(),
              password: $('#u-pass', root).value,
              role: $('#u-role', root).value,
              email: $('#u-email', root).value.trim(),
            });
            toast('用户已创建', 'ok');
            render();
          },
        });

      $$('[data-rmu]', c).forEach(
        (b) => (b.onclick = () =>
          openModal({
            title: '删除用户',
            body: `<p>确定删除用户 <strong>${esc(b.dataset.rmu)}</strong>？</p>`,
            confirmText: '删除',
            danger: true,
            onConfirm: async () => { await DEL(`/api/users/${encodeURIComponent(b.dataset.rmu)}`); toast('已删除', 'ok'); render(); },
          }))
      );
    } catch (err) {
      c.innerHTML = empty('⚠', err.message);
    }
  }

  // ── Utilities ───────────────────────────────────────────────────────

  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  // ── Boot ─────────────────────────────────────────────────────────────

  (async function boot() {
    try {
      const me = await GET('/api/me', { allowAnon: true });
      showApp(me);
    } catch {
      showLogin();
    }
  })();
})();
