import { cases, icons, formatDate } from '../data.ts';

export function renderCases(view?: string) {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Cases</div><div class="page-subtitle">Manage investigation cases and switch between challenges</div></div>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm">${icons.plus} New Case</button>
      </div>
    </div>
    ${view !== 'workspace' ? renderCaseList() : ''}
    ${view !== 'all' ? renderCaseDetail() : ''}
  </div>`;
}

function renderCaseList() {
  const items = cases.map(c => {
    const isActive = c.id === 'case-004';
    const statusCls = c.status === 'open' ? 'open' : 'closed';
    return `<div class="case-card ${isActive ? 'active' : ''}">
      <div class="case-card-status ${statusCls}"></div>
      <div class="case-card-info">
        <div class="case-card-name">${c.name} — ${c.challenge}</div>
        <div class="case-card-meta">${formatDate(c.created)} · ${c.status}</div>
      </div>
      <div class="case-card-stats">
        <span>${c.files} files</span>
        <span>${c.findings} findings</span>
        <span>${c.flags} flags</span>
      </div>
    </div>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">All Cases</div>
    <div class="case-list">${items}</div>
  </div>`;
}

function renderCaseDetail() {
  const c = cases[0];
  return `<div class="section">
    <div class="section-title mb-4">Active Case Details</div>
    <div class="tab-bar">
      <div class="tab-item active">Overview</div>
      <div class="tab-item">Artifacts <span class="tab-count">${c.files}</span></div>
      <div class="tab-item">Findings <span class="tab-count">${c.findings}</span></div>
      <div class="tab-item">Flags <span class="tab-count">${c.flags}</span></div>
      <div class="tab-item">Credentials</div>
      <div class="tab-item">Notes</div>
      <div class="tab-item">Timeline</div>
    </div>
    <div class="split-h split-h-2-1">
      <div>
        <div class="panel"><div class="panel-body">
          <div class="kv-list">
            <div class="kv-key">Case</div><div class="kv-value">${c.name}</div>
            <div class="kv-key">Challenge</div><div class="kv-value">${c.challenge}</div>
            <div class="kv-key">Status</div><div class="kv-value"><span class="badge badge-dot badge-success">Open</span></div>
            <div class="kv-key">Created</div><div class="kv-value">${formatDate(c.created)}</div>
            <div class="kv-key">Artifacts</div><div class="kv-value">${c.files}</div>
            <div class="kv-key">Findings</div><div class="kv-value">${c.findings}</div>
            <div class="kv-key">Flags Found</div><div class="kv-value">${c.flags}</div>
          </div>
        </div></div>
      </div>
      <div>
        <div class="section-title mb-4">Captured Flags</div>
        <div class="panel">
          <div class="panel-body">
            <div class="flex flex-col gap-3">
              <div style="padding:var(--sp-2) var(--sp-3);background:var(--success-bg);border-radius:var(--radius-sm);border:1px solid var(--success)">
                <div class="mono" style="font-size:var(--text-xs);color:var(--success)">CTF{sh4d0w_pr0t0c0l_br34ch}</div>
              </div>
              <div style="padding:var(--sp-2) var(--sp-3);background:var(--success-bg);border-radius:var(--radius-sm);border:1px solid var(--success)">
                <div class="mono" style="font-size:var(--text-xs);color:var(--success)">CTF{d3l3t3d_but_n0t_g0n3}</div>
              </div>
              <div style="padding:var(--sp-2) var(--sp-3);background:var(--success-bg);border-radius:var(--radius-sm);border:1px solid var(--success)">
                <div class="mono" style="font-size:var(--text-xs);color:var(--success)">CTF{cr1pt0_ch41n_m4st3r}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}


