import { icons } from '../data.ts';

type DashboardView = 'findings' | 'artifacts' | 'evidence';

let activeView: DashboardView = 'findings';

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing dashboard element: #${id}`);
  return element as T;
}

export function renderDashboard(view?: string): void {
  if (view === 'findings' || view === 'artifacts' || view === 'evidence') activeView = view;

  const main = byId<HTMLElement>('main');
  main.innerHTML = `<div class="main-content dashboard-page">
    <section class="dashboard-hero" aria-labelledby="dashboard-title">
      <div class="dashboard-hero-copy">
        <div class="dashboard-eyebrow">Analysis overview</div>
        <h1 id="dashboard-title">Dashboard</h1>
        <p>Real findings and evidence will appear here after an analysis is run.</p>
      </div>
      <div class="dashboard-actions">
        <button class="btn btn-primary" data-route="autotriage/new">${icons.upload} Start analysis</button>
      </div>
    </section>

    <section class="dashboard-metrics" aria-label="Analysis summary">
      ${renderMetric('Potential flags', '—', 'No analysis data', 'flag', 'accent')}
      ${renderMetric('High severity', '—', 'No analysis data', 'alert', 'warning')}
      ${renderMetric('Analysis jobs', '—', 'No analysis data', 'activity', 'info')}
      ${renderMetric('Evidence files', '—', 'No analysis data', 'files', 'neutral')}
    </section>

    <section class="dashboard-workspace" aria-labelledby="workspace-title">
      <div class="dashboard-section-heading">
        <div>
          <h2 id="workspace-title">Analysis workspace</h2>
          <p>Only results produced by the backend are shown.</p>
        </div>
      </div>
      <div class="dashboard-tabs" role="tablist" aria-label="Analysis data">
        ${renderTab('findings', 'Findings')}
        ${renderTab('artifacts', 'Evidence')}
        ${renderTab('evidence', 'Relationships')}
      </div>
      <div id="dashboard-workspace-content"></div>
    </section>
  </div>`;

  renderWorkspace();
  bindDashboardEvents();
}

function renderMetric(label: string, value: string, meta: string, symbol: string, tone: string): string {
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

function renderTab(view: DashboardView, label: string): string {
  const selected = activeView === view;
  return `<button class="dashboard-tab ${selected ? 'active' : ''}" role="tab"
    aria-selected="${selected}" data-view="${view}">${label}</button>`;
}

function renderWorkspace(): void {
  const content = byId<HTMLElement>('dashboard-workspace-content');
  const emptyStates: Record<DashboardView, { title: string; text: string }> = {
    findings: {
      title: 'No findings yet',
      text: 'Run an analysis to populate this dashboard with findings returned by the backend.',
    },
    artifacts: {
      title: 'No evidence files yet',
      text: 'Evidence files used in an analysis will appear here.',
    },
    evidence: {
      title: 'No relationships yet',
      text: 'Evidence relationships will appear when they are derived from analysis results.',
    },
  };
  const state = emptyStates[activeView];

  content.innerHTML = `<div class="empty-state">
    <div class="empty-state-icon">${icons.search}</div>
    <div class="empty-state-title">${state.title}</div>
    <div class="empty-state-text">${state.text}</div>
  </div>`;
}

function bindDashboardEvents(): void {
  document.querySelectorAll<HTMLElement>('[data-route]').forEach((element) => {
    element.addEventListener('click', () => {
      window.location.hash = element.dataset.route ?? 'autotriage/new';
    });
  });

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
}
