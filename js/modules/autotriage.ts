import { icons } from '../data.ts';

export function renderAutoTriage(view?: string) {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Auto Triage</div><div class="page-subtitle">Automated file analysis and classification</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary">${icons.settings} Configure Analyzers</button>
      </div>
    </div>
    ${view === 'queue' ? renderTriageQueue() : view === 'actions' ? renderTriageActions() : `<div class="triage-workspace">
      <div>${renderDropZone()}${renderAnalysisProgress()}</div>
      <div class="triage-right">${renderTriageQueue()}${renderTriageActions()}</div>
    </div>`}
  </div>`;
  bindDropZone();
}

function renderDropZone() {
  return `<div class="section">
    <div class="section-title mb-4">File Input</div>
    <div class="drop-zone" id="drop-zone">
      <div class="drop-zone-icon">${icons.upload}</div>
      <div class="drop-zone-text">Drop challenge files here</div>
      <div class="drop-zone-hint">PCAP, ZIP, images, disk images, memory dumps, binaries, documents</div>
      <div class="drop-zone-hint mt-4" style="color:var(--accent)">or click to browse</div>
    </div>
  </div>`;
}

function renderAnalysisProgress() {
  const stages = [
    { name: 'File identification', status: 'completed', time: '0.2s' },
    { name: 'Metadata extraction', status: 'completed', time: '0.8s' },
    { name: 'Signature analysis', status: 'completed', time: '1.4s' },
    { name: 'Stream reconstruction', status: 'completed', time: '3.2s' },
    { name: 'Embedded file extraction', status: 'running', time: '...' },
    { name: 'Credential search', status: 'pending', time: '' },
    { name: 'Flag pattern search', status: 'pending', time: '' },
    { name: 'Evidence correlation', status: 'pending', time: '' },
  ];

  const stageHTML = stages.map(s => {
    let iconSvg;
    if (s.status === 'completed') iconSvg = `<span style="color:var(--success)">${icons.check}</span>`;
    else if (s.status === 'running') iconSvg = `<span class="spin" style="color:var(--accent)">${icons.loader}</span>`;
    else iconSvg = `<span style="color:var(--text-muted)">${icons.circle}</span>`;

    return `<div class="progress-stage ${s.status}">
      <div class="progress-stage-icon">${iconSvg}</div>
      <div class="progress-stage-label">${s.name}</div>
      <div class="progress-stage-meta">${s.time}</div>
    </div>`;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Analysis Progress</div>
      <span class="badge badge-dot badge-warning">Running</span>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span><span class="mono" style="font-size:var(--text-xs)">challenge.zip</span></span>
        <span class="text-xs text-muted">5 / 8 stages</span>
      </div>
      <div class="panel-body">
        <div class="progress-stages">${stageHTML}</div>
      </div>
    </div>
  </div>`;
}

function renderTriageQueue() {
  const queue = [
    { name: 'capture.pcap', type: 'PCAP', size: '14.2 MB', status: 'complete', findings: 8 },
    { name: 'challenge.zip', type: 'Archive', size: '2.1 MB', status: 'running', findings: 4 },
    { name: 'suspicious.png', type: 'Image', size: '342 KB', status: 'queued', findings: 0 },
    { name: 'filesystem.dd', type: 'Disk Image', size: '512 MB', status: 'queued', findings: 0 },
  ];

  const rows = queue.map(q => {
    const sc = q.status === 'complete' ? 'badge-success' : q.status === 'running' ? 'badge-warning' : 'badge-info';
    return `<tr>
      <td class="mono" style="font-size:var(--text-xs)">${q.name}</td>
      <td class="text-secondary">${q.type}</td>
      <td class="text-muted">${q.size}</td>
      <td><span class="badge badge-dot ${sc}">${q.status}</span></td>
      <td class="text-secondary">${q.findings}</td>
    </tr>`;
  }).join('');

  return `<div class="section triage-queue">
    <div class="section-title mb-4">Triage Queue</div>
    <table class="data-table">
      <thead><tr><th>File</th><th>Type</th><th>Size</th><th>Status</th><th>Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderTriageActions() {
  return `<div class="section">
    <div class="section-title mb-4">Actions</div>
    <div class="flex flex-col gap-3">
      <button class="btn btn-primary w-full">${icons.play} Auto Analyze</button>
      <button class="btn btn-secondary w-full">${icons.settings} Select Analyzer</button>
      <button class="btn btn-secondary w-full">${icons.plus} Add to Case</button>
    </div>
  </div>`;
}

function bindDropZone() {
  const dz = document.getElementById('drop-zone');
  if (!dz) return;
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragover'); });
}


