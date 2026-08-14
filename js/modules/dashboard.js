import { activeCase, artifacts, findings, timeline, evidenceGraph, icons, icon, formatTime, severityClass, statusClass } from '../data.js';

export function renderDashboard() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    ${renderStats()}
    <div class="split-h split-h-2-1">
      <div>
        ${renderArtifacts()}
        ${renderFindings()}
      </div>
      <div>
        ${renderEvidenceGraph()}
        ${renderTimeline()}
      </div>
    </div>
  </div>`;
  bindEvents();
}

function renderStats() {
  return `<div class="dashboard-stats">
    <div class="stat-row">
      <div class="stat-item">
        <div class="stat-label">Active Case</div>
        <div class="stat-value" style="font-size:var(--text-md)">${activeCase.challenge}</div>
        <div class="stat-meta">${activeCase.name}</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Files</div>
        <div class="stat-value">${activeCase.files}</div>
        <div class="stat-meta">artifacts loaded</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Findings</div>
        <div class="stat-value">${activeCase.findings}</div>
        <div class="stat-meta">${findings.filter(f=>f.severity==='high').length} high severity</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Potential Flags</div>
        <div class="stat-value">${activeCase.flags}</div>
        <div class="stat-meta">candidates identified</div>
      </div>
      <div class="stat-item">
        <div class="stat-label">Running Jobs</div>
        <div class="stat-value">${activeCase.runningJobs}</div>
        <div class="stat-meta">analysis in progress</div>
      </div>
    </div>
  </div>`;
}

function renderArtifacts() {
  const rows = artifacts.map(a => `
    <tr class="clickable">
      <td><span class="mono" style="font-size:var(--text-xs)">${a.name}</span></td>
      <td class="text-secondary">${a.type}</td>
      <td class="text-muted">${a.size}</td>
      <td class="text-secondary">${a.analyzer}</td>
      <td><span class="badge badge-dot ${statusClass(a.status)}">${a.status}</span></td>
      <td class="text-secondary">${a.findings}</td>
    </tr>
  `).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Investigation Artifacts</div>
      <button class="btn btn-sm btn-secondary">${icons.upload} Upload</button>
    </div>
    <table class="data-table">
      <thead><tr>
        <th class="sortable">File</th><th class="sortable">Type</th><th class="sortable">Size</th>
        <th>Analyzer</th><th class="sortable">Status</th><th class="sortable">Findings</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderFindings() {
  const rows = findings.map(f => `
    <tr class="clickable">
      <td><span class="badge badge-dot ${severityClass(f.severity)}">${f.severity.toUpperCase()}</span></td>
      <td>${f.title}</td>
      <td class="mono text-muted" style="font-size:var(--text-xs)">${f.source}</td>
      <td class="text-secondary">${f.confidence}%</td>
      <td class="text-secondary">${f.module}</td>
      <td class="mono text-muted" style="font-size:var(--text-xs)">${formatTime(f.timestamp)}</td>
    </tr>
  `).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Findings</div>
      <div class="filter-bar" style="margin-bottom:0">
        <span class="filter-chip filter-critical active" data-filter="all">All</span>
        <span class="filter-chip filter-high" data-filter="high">High</span>
        <span class="filter-chip filter-medium" data-filter="medium">Medium</span>
        <span class="filter-chip filter-low" data-filter="low">Low</span>
        <span class="filter-chip filter-info" data-filter="info">Info</span>
      </div>
    </div>
    <table class="data-table" id="findings-table">
      <thead><tr>
        <th class="sortable">Severity</th><th class="sortable">Finding</th><th>Source</th>
        <th class="sortable">Confidence</th><th>Module</th><th class="sortable">Timestamp</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderEvidenceGraph() {
  const g = evidenceGraph;
  const w = 800;
  const h = 190;

  const typeColors = { artifact: '#2563eb', finding: '#d97706', file: '#6b7280', flag: '#16a34a' };
  const typeBg = { artifact: '#eff6ff', finding: '#fffbeb', file: '#f3f4f6', flag: '#f0fdf4' };

  let edges = '';
  for (const e of g.edges) {
    const from = g.nodes.find(n => n.id === e.from);
    const to = g.nodes.find(n => n.id === e.to);
    if (from && to) {
      edges += `<line x1="${from.x + 50}" y1="${from.y + 14}" x2="${to.x}" y2="${to.y + 14}" stroke="#d1d5db" stroke-width="1"/>`;
    }
  }

  let nodes = '';
  for (const n of g.nodes) {
    const c = typeColors[n.type];
    const bg = typeBg[n.type];
    nodes += `
      <g transform="translate(${n.x},${n.y})">
        <rect width="${n.label.length * 7.5 + 16}" height="28" rx="3" fill="${bg}" stroke="${c}" stroke-width="1"/>
        <text x="8" y="18" font-family="var(--font-mono)" font-size="10" fill="${c}">${n.label}</text>
      </g>
    `;
  }

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Evidence Graph</div>
      <span class="text-xs text-muted">Artifact relationships</span>
    </div>
    <div class="evidence-graph">
      <svg viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg" style="font-family:var(--font-mono)">
        ${edges}
        ${nodes}
      </svg>
    </div>
  </div>`;
}

function renderTimeline() {
  const items = timeline.map(t => {
    const dotClass = t.type === 'success' ? 'dot-success' : t.type === 'warning' ? 'dot-warning' : t.type === 'error' ? 'dot-error' : 'dot-info';
    return `
      <div class="timeline-item">
        <div class="timeline-dot ${dotClass}"></div>
        <div class="timeline-content">${t.event}</div>
        <div class="timeline-time">${formatTime(t.time)} · ${t.module}</div>
      </div>
    `;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Analysis Timeline</div>
    </div>
    <div class="timeline">${items}</div>
  </div>`;
}

function bindEvents() {
  // Filter chips
  document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const filter = chip.dataset.filter;
      const table = document.getElementById('findings-table');
      if (!table) return;
      table.querySelectorAll('tbody tr').forEach(row => {
        if (filter === 'all') { row.style.display = ''; return; }
        const badge = row.querySelector('.badge');
        const sev = badge ? badge.textContent.trim().toLowerCase() : '';
        row.style.display = sev === filter ? '' : 'none';
      });
    });
  });
}
