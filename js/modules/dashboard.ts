import {
  activeCase,
  artifacts,
  evidenceGraph,
  findings,
  formatTime,
  icons,
  severityClass,
  statusClass,
  timeline,
} from '../data.ts';

type DashboardView = 'findings' | 'artifacts' | 'evidence';
type SeverityFilter = 'all' | 'high' | 'medium' | 'low' | 'info';

let activeView: DashboardView = 'findings';
let severityFilter: SeverityFilter = 'all';

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing dashboard element: #${id}`);
  return element as T;
}

export function renderDashboard(view?: string): void {
  if (view === 'findings' || view === 'artifacts' || view === 'evidence') activeView = view;
  const main = byId<HTMLElement>('main');
  const highSeverityCount = findings.filter((finding) => finding.severity === 'high').length;

  main.innerHTML = `<div class="main-content dashboard-page">
    <section class="dashboard-hero" aria-labelledby="dashboard-title">
      <div class="dashboard-hero-copy">
        <div class="dashboard-eyebrow"><span class="status-pulse"></span> Active investigation</div>
        <h1 id="dashboard-title">${activeCase.challenge}</h1>
        <p>${activeCase.name} <span aria-hidden="true">·</span> Started ${formatTime(activeCase.created)}</p>
      </div>
      <div class="dashboard-actions">
        <button class="btn btn-secondary" data-action="upload">${icons.upload} Add evidence</button>
        <button class="btn btn-primary" data-route="autotriage">Run auto triage</button>
      </div>
    </section>

    <section class="dashboard-metrics" aria-label="Case summary">
      ${renderMetric('Potential flags', activeCase.flags, 'Ready to review', 'flag', 'accent')}
      ${renderMetric('High severity', highSeverityCount, 'Needs attention', 'alert', 'warning')}
      ${renderMetric('Analysis jobs', activeCase.runningJobs, 'Currently running', 'activity', 'info')}
      ${renderMetric('Evidence files', activeCase.files, `${artifacts.filter((item) => item.status === 'complete').length} analyzed`, 'files', 'neutral')}
    </section>

    <div class="dashboard-layout">
      <section class="dashboard-workspace" aria-labelledby="workspace-title">
        <div class="dashboard-section-heading">
          <div>
            <h2 id="workspace-title">Investigation workspace</h2>
            <p>Review the most useful case data without leaving the dashboard.</p>
          </div>
          <button class="btn btn-sm btn-ghost" data-route="reports">Open report</button>
        </div>
        <div class="dashboard-tabs" role="tablist" aria-label="Investigation data">
          ${renderTab('findings', 'Findings', findings.length)}
          ${renderTab('artifacts', 'Evidence', artifacts.length)}
          ${renderTab('evidence', 'Relationships')}
        </div>
        <div id="dashboard-workspace-content"></div>
      </section>

      <aside class="dashboard-rail" aria-label="Investigation priorities">
        ${renderPriorityQueue()}
        ${renderRecentActivity()}
      </aside>
    </div>
  </div>`;

  renderWorkspace();
  bindDashboardEvents();
}

function renderMetric(label: string, value: number, meta: string, symbol: string, tone: string): string {
  const symbols: Record<string, string> = {
    flag: '⚑',
    alert: '!',
    activity: '↗',
    files: '▱',
  };

  return `<article class="dashboard-metric dashboard-metric-${tone}">
    <div class="dashboard-metric-icon" aria-hidden="true">${symbols[symbol]}</div>
    <div>
      <div class="dashboard-metric-label">${label}</div>
      <div class="dashboard-metric-value">${value}</div>
      <div class="dashboard-metric-meta">${meta}</div>
    </div>
  </article>`;
}

function renderTab(view: DashboardView, label: string, count?: number): string {
  const selected = activeView === view;
  return `<button class="dashboard-tab ${selected ? 'active' : ''}" role="tab"
    aria-selected="${selected}" data-view="${view}">
    ${label}${count === undefined ? '' : `<span>${count}</span>`}
  </button>`;
}

function renderWorkspace(): void {
  const content = byId<HTMLElement>('dashboard-workspace-content');
  if (activeView === 'artifacts') content.innerHTML = renderArtifacts();
  else if (activeView === 'evidence') content.innerHTML = renderEvidenceGraph();
  else content.innerHTML = renderFindings();

  bindWorkspaceEvents();
}

function renderFindings(): string {
  const filteredFindings = severityFilter === 'all'
    ? findings
    : findings.filter((finding) => finding.severity === severityFilter);
  const rows = filteredFindings.map((finding) => `
    <tr class="clickable">
      <td><span class="badge badge-dot ${severityClass(finding.severity)}">${finding.severity.toUpperCase()}</span></td>
      <td><strong class="dashboard-row-title">${finding.title}</strong><span class="dashboard-row-meta">${finding.source}</span></td>
      <td class="text-secondary dashboard-hide-mobile">${finding.module}</td>
      <td class="text-secondary">${finding.confidence}%</td>
      <td class="mono text-muted dashboard-hide-tablet">${formatTime(finding.timestamp)}</td>
    </tr>`).join('');

  return `<div class="dashboard-table-toolbar">
    <div class="filter-bar" aria-label="Filter findings by severity">
      ${(['all', 'high', 'medium', 'low', 'info'] as SeverityFilter[]).map((filter) =>
        `<button class="filter-chip ${severityFilter === filter ? 'active' : ''}" data-filter="${filter}">${filter === 'all' ? 'All findings' : filter}</button>`,
      ).join('')}
    </div>
    <span class="dashboard-result-count">${filteredFindings.length} results</span>
  </div>
  <div class="dashboard-table-wrap">
    <table class="data-table dashboard-table">
      <thead><tr><th>Severity</th><th>Finding</th><th class="dashboard-hide-mobile">Module</th><th>Confidence</th><th class="dashboard-hide-tablet">Detected</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderArtifacts(): string {
  const rows = artifacts.map((artifact) => `
    <tr class="clickable">
      <td><strong class="dashboard-row-title mono">${artifact.name}</strong><span class="dashboard-row-meta">${artifact.type} · ${artifact.size}</span></td>
      <td class="text-secondary">${artifact.analyzer}</td>
      <td><span class="badge badge-dot ${statusClass(artifact.status)}">${artifact.status}</span></td>
      <td class="text-secondary dashboard-hide-mobile">${artifact.findings}</td>
    </tr>`).join('');

  return `<div class="dashboard-table-toolbar">
    <span class="dashboard-result-count">${artifacts.length} evidence files</span>
    <button class="btn btn-sm btn-secondary" data-action="upload">${icons.upload} Add evidence</button>
  </div>
  <div class="dashboard-table-wrap">
    <table class="data-table dashboard-table">
      <thead><tr><th>File</th><th>Analyzer</th><th>Status</th><th class="dashboard-hide-mobile">Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderEvidenceGraph(): string {
  const typeColors: Record<string, string> = { artifact: '#2563eb', finding: '#d97706', file: '#64748b', flag: '#16a34a' };
  const typeBackgrounds: Record<string, string> = { artifact: '#eff6ff', finding: '#fffbeb', file: '#f8fafc', flag: '#f0fdf4' };
  const edges = evidenceGraph.edges.map((edge) => {
    const from = evidenceGraph.nodes.find((node) => node.id === edge.from);
    const to = evidenceGraph.nodes.find((node) => node.id === edge.to);
    return from && to
      ? `<line x1="${from.x + 50}" y1="${from.y + 14}" x2="${to.x}" y2="${to.y + 14}" stroke="#cbd5e1" stroke-width="1.5"/>`
      : '';
  }).join('');
  const nodes = evidenceGraph.nodes.map((node) => `
    <g transform="translate(${node.x},${node.y})">
      <rect width="${node.label.length * 7.5 + 16}" height="28" rx="5" fill="${typeBackgrounds[node.type]}" stroke="${typeColors[node.type]}"/>
      <text x="8" y="18" font-family="JetBrains Mono, monospace" font-size="10" fill="${typeColors[node.type]}">${node.label}</text>
    </g>`).join('');

  return `<div class="dashboard-graph-intro">
      <p>Follow the chain from uploaded evidence to candidate flags.</p>
      <span>Drag-to-explore is available in the full graph view.</span>
    </div>
    <div class="evidence-graph dashboard-evidence-graph">
      <svg viewBox="0 0 800 190" xmlns="http://www.w3.org/2000/svg" aria-label="Evidence relationship graph">${edges}${nodes}</svg>
    </div>`;
}

function renderPriorityQueue(): string {
  const priorityFindings = findings.filter((finding) => finding.severity === 'high').slice(0, 3);
  return `<section class="dashboard-rail-card">
    <div class="dashboard-rail-heading">
      <div><span class="dashboard-eyebrow">Next up</span><h2>Needs attention</h2></div>
      <span class="dashboard-count">${priorityFindings.length}</span>
    </div>
    <div class="dashboard-priority-list">
      ${priorityFindings.map((finding) => `<button class="dashboard-priority-item" data-view-findings>
        <span class="dashboard-priority-marker"></span>
        <span><strong>${finding.title}</strong><small>${finding.source} · ${finding.confidence}% confidence</small></span>
        <span aria-hidden="true">›</span>
      </button>`).join('')}
    </div>
    <button class="dashboard-text-link" data-view-findings>Review all findings <span aria-hidden="true">→</span></button>
  </section>`;
}

function renderRecentActivity(): string {
  return `<section class="dashboard-rail-card">
    <div class="dashboard-rail-heading">
      <div><span class="dashboard-eyebrow">Live feed</span><h2>Recent activity</h2></div>
    </div>
    <div class="dashboard-activity-list">
      ${timeline.slice(0, 5).map((item) => `<div class="dashboard-activity-item">
        <span class="dashboard-activity-dot dashboard-activity-${item.type}"></span>
        <div><strong>${item.event}</strong><small>${formatTime(item.time)} · ${item.module}</small></div>
      </div>`).join('')}
    </div>
  </section>`;
}

function bindDashboardEvents(): void {
  document.querySelectorAll<HTMLElement>('[data-route]').forEach((element) => {
    element.addEventListener('click', () => { window.location.hash = element.dataset.route ?? 'dashboard'; });
  });

  document.querySelectorAll<HTMLElement>('[data-view-findings]').forEach((element) => {
    element.addEventListener('click', () => {
      activeView = 'findings';
      severityFilter = 'all';
      renderDashboard();
      byId<HTMLElement>('workspace-title').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  document.querySelectorAll<HTMLElement>('[data-action="upload"]').forEach((element) => {
    element.addEventListener('click', () => { window.location.hash = 'autotriage'; });
  });
}

function bindWorkspaceEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('.dashboard-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      activeView = (tab.dataset.view ?? 'findings') as DashboardView;
      document.querySelectorAll<HTMLButtonElement>('.dashboard-tab').forEach((item) => {
        const selected = item.dataset.view === activeView;
        item.classList.toggle('active', selected);
        item.setAttribute('aria-selected', String(selected));
      });
      renderWorkspace();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-filter]').forEach((chip) => {
    chip.addEventListener('click', () => {
      severityFilter = (chip.dataset.filter ?? 'all') as SeverityFilter;
      renderWorkspace();
    });
  });
}
