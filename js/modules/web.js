import { webData, icons } from '../data.js';

let activeTab = 'endpoints';

export function renderWeb() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Web Analysis</div><div class="page-subtitle">HTTP/HTTPS reconnaissance and vulnerability analysis</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.play} Re-scan</button>
      </div>
    </div>
    ${renderTarget()}
    <div class="tab-bar" id="web-tabs">
      <div class="tab-item ${activeTab==='endpoints'?'active':''}" data-tab="endpoints">Endpoints <span class="tab-count">${webData.endpoints.length}</span></div>
      <div class="tab-item ${activeTab==='headers'?'active':''}" data-tab="headers">Headers</div>
      <div class="tab-item ${activeTab==='cookies'?'active':''}" data-tab="cookies">Cookies <span class="tab-count">${webData.cookies.length}</span></div>
      <div class="tab-item ${activeTab==='tech'?'active':''}" data-tab="tech">Technologies</div>
      <div class="tab-item ${activeTab==='comments'?'active':''}" data-tab="comments">Comments <span class="tab-count">${webData.comments.length}</span></div>
    </div>
    <div id="web-content">${renderWebTab(activeTab)}</div>
  </div>`;
  bindWebEvents();
}

function renderTarget() {
  return `<div class="web-target">
    <div style="display:flex;align-items:center;gap:var(--sp-3)">
      <span class="badge badge-dot badge-success">Online</span>
      <span class="mono" style="font-size:var(--text-sm)">${webData.target}</span>
    </div>
    <div class="topbar-spacer"></div>
    <div class="text-xs text-muted">Technologies: ${webData.technologies.join(' · ')}</div>
  </div>`;
}

function renderWebTab(tab) {
  switch(tab) {
    case 'endpoints': return renderEndpoints();
    case 'headers': return renderHeaders();
    case 'cookies': return renderCookies();
    case 'tech': return renderTech();
    case 'comments': return renderComments();
    default: return '';
  }
}

function renderEndpoints() {
  const rows = webData.endpoints.map(e => {
    const methodClass = e.method === 'POST' ? 'color:var(--high)' : 'color:var(--accent)';
    const statusClass = e.status >= 400 ? 'color:var(--error)' : e.status >= 300 ? 'color:var(--warning)' : 'color:var(--success)';
    return `<tr class="clickable">
      <td class="mono" style="font-size:var(--text-xs)">${e.path}</td>
      <td><span class="badge badge-outline" style="${methodClass};border-color:currentColor">${e.method}</span></td>
      <td class="mono" style="font-size:var(--text-xs);${statusClass}">${e.status}</td>
      <td class="mono text-muted" style="font-size:var(--text-xs)">${e.params || '—'}</td>
      <td class="text-muted">${e.note}</td>
    </tr>`;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Discovered Endpoints</div>
    </div>
    <table class="data-table">
      <thead><tr><th>Path</th><th>Method</th><th>Status</th><th>Parameters</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderHeaders() {
  const rows = webData.headers.map(h => {
    const isMissing = h.value === 'MISSING';
    return `<tr>
      <td class="mono font-medium" style="font-size:var(--text-xs)">${h.header}</td>
      <td class="mono ${isMissing ? '' : 'text-secondary'}" style="font-size:var(--text-xs);${isMissing?'color:var(--error);font-weight:600':''}">${h.value}</td>
      <td class="text-muted">${h.note}</td>
    </tr>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">Response Headers</div>
    <table class="data-table">
      <thead><tr><th>Header</th><th>Value</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderCookies() {
  const rows = webData.cookies.map(c => `<tr>
    <td class="mono font-medium" style="font-size:var(--text-xs)">${c.name}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.value}</td>
    <td>${c.flags ? `<span class="badge badge-info">${c.flags}</span>` : '<span class="text-muted">—</span>'}</td>
    <td><span class="badge ${c.secure?'badge-success':'badge-error'}">${c.secure?'Yes':'No'}</span></td>
    <td class="text-muted">${c.note}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Cookies</div>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Value</th><th>Flags</th><th>Secure</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderTech() {
  const techs = webData.technologies.map(t => `<div class="osint-entity">
    <div class="osint-entity-type">Technology</div>
    <div class="osint-entity-value">${t}</div>
  </div>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Detected Technologies</div>
    <div class="osint-entities">${techs}</div>
  </div>`;
}

function renderComments() {
  const rows = webData.comments.map(c => `<tr>
    <td class="mono text-secondary" style="font-size:var(--text-xs)">${c.file}</td>
    <td class="text-muted">Line ${c.line}</td>
    <td class="mono" style="font-size:var(--text-xs)">${c.text}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Interesting Comments</div>
    <table class="data-table">
      <thead><tr><th>File</th><th>Line</th><th>Comment</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function bindWebEvents() {
  document.querySelectorAll('#web-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab;
      renderWeb();
    });
  });
}
