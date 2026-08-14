import { icons } from '../data.js';

export function renderReports() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Reports</div><div class="page-subtitle">Generate and export investigation reports</div></div>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm">${icons.plus} New Report</button>
      </div>
    </div>
    ${renderReportList()}
    ${renderReportConfig()}
  </div>`;
}

function renderReportList() {
  const reports = [
    { name: 'Hack4Gov 2026 — Challenge 04 Report', format: 'PDF', created: '2026-08-14 10:45', pages: 12, status: 'ready' },
    { name: 'Challenge 03 — Hidden Layers Summary', format: 'PDF', created: '2026-08-13 16:30', pages: 8, status: 'ready' },
    { name: 'CyberStorm CTF — Full Write-up', format: 'Markdown', created: '2026-08-10 18:00', pages: 24, status: 'draft' },
  ];

  const items = reports.map(r => `<div class="report-card">
    <div style="color:var(--accent)">${icons.reports}</div>
    <div class="report-card-info">
      <div class="report-card-name">${r.name}</div>
      <div class="report-card-meta">${r.format} · ${r.pages} pages · ${r.created}</div>
    </div>
    <span class="badge badge-dot ${r.status==='ready'?'badge-success':'badge-info'}">${r.status}</span>
    <button class="btn btn-sm btn-secondary">${icons.download} Download</button>
  </div>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Generated Reports</div>
    ${items}
  </div>`;
}

function renderReportConfig() {
  return `<div class="section">
    <div class="section-title mb-4">Generate New Report</div>
    <div class="panel"><div class="panel-body">
      <div class="split-h split-h-1-1">
        <div>
          <div class="settings-field">
            <div class="settings-field-label">Report Title</div>
            <input class="input" type="text" value="Hack4Gov 2026 — Challenge 04 Report" />
          </div>
          <div class="settings-field">
            <div class="settings-field-label">Format</div>
            <select class="select w-full">
              <option>PDF</option>
              <option>Markdown</option>
              <option>HTML</option>
              <option>JSON</option>
            </select>
          </div>
          <div class="settings-field">
            <div class="settings-field-label">Case</div>
            <select class="select w-full">
              <option>Hack4Gov 2026 — Challenge 04</option>
              <option>Hack4Gov 2026 — Challenge 03</option>
              <option>CyberStorm CTF — Memory Lane</option>
            </select>
          </div>
        </div>
        <div>
          <div class="settings-field">
            <div class="settings-field-label">Include Sections</div>
            <div class="flex flex-col gap-2">
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Executive Summary</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Artifacts Overview</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Findings (sorted by severity)</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Evidence Graph</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Timeline</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Credentials & Flags</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" /> Raw Analysis Data</label>
              <label class="flex items-center gap-2 text-sm"><input type="checkbox" /> Appendix: Full Strings</label>
            </div>
          </div>
          <button class="btn btn-primary mt-4">${icons.play} Generate Report</button>
        </div>
      </div>
    </div></div>
  </div>`;
}
