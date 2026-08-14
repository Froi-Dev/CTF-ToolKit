import { forensicsData, icons } from '../data.js';

let activeTab = 'overview';

export function renderForensics() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Forensics</div><div class="page-subtitle">filesystem.dd — ext4 disk image — 512 MB</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.download} Export Evidence</button>
      </div>
    </div>
    <div class="tab-bar" id="forensics-tabs">
      <div class="tab-item ${activeTab==='overview'?'active':''}" data-tab="overview">Overview</div>
      <div class="tab-item ${activeTab==='files'?'active':''}" data-tab="files">Files</div>
      <div class="tab-item ${activeTab==='deleted'?'active':''}" data-tab="deleted">Deleted Files <span class="tab-count">3</span></div>
      <div class="tab-item ${activeTab==='metadata'?'active':''}" data-tab="metadata">Metadata</div>
      <div class="tab-item ${activeTab==='strings'?'active':''}" data-tab="strings">Strings <span class="tab-count">${forensicsData.strings.length}</span></div>
      <div class="tab-item ${activeTab==='timeline'?'active':''}" data-tab="timeline">Timeline</div>
      <div class="tab-item ${activeTab==='carved'?'active':''}" data-tab="carved">Carved Files</div>
      <div class="tab-item ${activeTab==='evidence'?'active':''}" data-tab="evidence">Evidence</div>
    </div>
    <div id="forensics-content">${renderForensicsTab(activeTab)}</div>
  </div>`;
  bindForensicsEvents();
}

function renderForensicsTab(tab) {
  switch(tab) {
    case 'overview': return renderOverview();
    case 'files': return renderFileTree();
    case 'deleted': return renderDeleted();
    case 'metadata': return renderMetadata();
    case 'strings': return renderStrings();
    case 'timeline': return renderForensicsTimeline();
    case 'carved': return renderCarved();
    case 'evidence': return renderEvidence();
    default: return '';
  }
}

function renderOverview() {
  return `<div class="forensics-layout">
    <div>
      <div class="section-title mb-4">File System</div>
      <div class="forensics-tree">${renderTreeHTML(forensicsData.fileTree, 0)}</div>
    </div>
    <div>
      ${renderMetadata()}
      ${renderStrings()}
    </div>
  </div>`;
}

function renderTreeHTML(nodes, depth) {
  return nodes.map(node => {
    const indent = '<span class="tree-indent"></span>'.repeat(depth);
    const name = node.path.split('/').pop() || '/';
    const isDir = node.type === 'dir';
    const iconStr = isDir
      ? `<span class="tree-icon folder">${icons.folder}</span>`
      : `<span class="tree-icon file">${icons.file}</span>`;
    const meta = !isDir ? `<span class="tree-meta">${node.size || ''}</span>` : '';
    const deletedCls = node.deleted ? 'tree-deleted' : '';
    const deletedTag = node.deleted ? ' <span class="badge badge-error" style="font-size:9px;padding:0 3px">deleted</span>' : '';
    const interestingTag = node.interesting && !node.deleted ? ' <span class="badge badge-warning" style="font-size:9px;padding:0 3px">★</span>' : '';

    let html = `<div class="tree-node ${deletedCls}">
      ${indent}${iconStr}
      <span class="tree-label">${name}${deletedTag}${interestingTag}</span>
      ${meta}
    </div>`;

    if (isDir && node.children) {
      html += renderTreeHTML(node.children, depth + 1);
    }
    return html;
  }).join('');
}

function renderFileTree() {
  return `<div class="section">
    <div class="section-title mb-4">File System Tree</div>
    <div class="forensics-tree" style="max-height:600px">${renderTreeHTML(forensicsData.fileTree, 0)}</div>
  </div>`;
}

function renderDeleted() {
  const deleted = [
    { path: '/home/user/secret.txt', size: '1.2 KB', modified: '2026-08-12 22:14:02', recoverable: true, content: 'CTF{d3l3t3d_but_n0t_g0n3}' },
    { path: '/home/user/Downloads/tool.exe', size: '1.8 MB', modified: '2026-08-11 15:30:44', recoverable: true, content: '(binary data)' },
    { path: '/var/log/auth.log.1', size: '12 KB', modified: '2026-08-10 08:00:00', recoverable: false, content: '' },
  ];

  const rows = deleted.map(d => `<tr class="clickable">
    <td class="mono" style="font-size:var(--text-xs);color:var(--error)">${d.path}</td>
    <td class="text-muted">${d.size}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${d.modified}</td>
    <td><span class="badge ${d.recoverable?'badge-success':'badge-error'}">${d.recoverable?'Yes':'No'}</span></td>
    <td><button class="btn btn-sm btn-secondary">${icons.download} Recover</button></td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Deleted Files</div>
    <table class="data-table">
      <thead><tr><th>Path</th><th>Size</th><th>Modified</th><th>Recoverable</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderMetadata() {
  const kvs = forensicsData.metadata.map(m =>
    `<div class="kv-key">${m.key}</div><div class="kv-value mono">${m.value}</div>`
  ).join('');
  return `<div class="section">
    <div class="section-title mb-4">Image Metadata</div>
    <div class="panel"><div class="panel-body"><div class="kv-list">${kvs}</div></div></div>
  </div>`;
}

function renderStrings() {
  const rows = forensicsData.strings.map(s => `<tr class="clickable">
    <td class="mono text-muted" style="font-size:var(--text-xs)">${s.offset}</td>
    <td class="mono" style="font-size:var(--text-xs)">${s.value}</td>
    <td class="text-muted">${s.context}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Interesting Strings</div>
      <span class="text-xs text-muted">${forensicsData.strings.length} results</span>
    </div>
    <table class="data-table">
      <thead><tr><th>Offset</th><th>Value</th><th>Context</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderForensicsTimeline() {
  const events = [
    { time: '2026-08-12 23:14:02', event: 'File system last mounted', type: 'info' },
    { time: '2026-08-12 22:14:02', event: 'secret.txt deleted (content recovered)', type: 'warning' },
    { time: '2026-08-12 21:45:30', event: 'hidden_script.sh created in /tmp', type: 'warning' },
    { time: '2026-08-11 15:30:44', event: 'tool.exe downloaded and deleted', type: 'error' },
    { time: '2026-08-11 14:22:18', event: 'SSH login from 192.168.1.105', type: 'info' },
    { time: '2026-08-11 14:20:00', event: 'Failed login attempts (3x)', type: 'warning' },
  ];

  const items = events.map(e => {
    const dotClass = e.type === 'warning' ? 'dot-warning' : e.type === 'error' ? 'dot-error' : 'dot-info';
    return `<div class="timeline-item">
      <div class="timeline-dot ${dotClass}"></div>
      <div class="timeline-content">${e.event}</div>
      <div class="timeline-time">${e.time}</div>
    </div>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">Activity Timeline</div>
    <div class="timeline">${items}</div>
  </div>`;
}

function renderCarved() {
  const carved = [
    { name: 'carved_001.zip', type: 'ZIP Archive', offset: '0x3A2F0', size: '48 KB', source: 'suspicious.png' },
    { name: 'carved_002.jpg', type: 'JPEG Image', offset: '0x8F100', size: '12 KB', source: 'unallocated space' },
  ];
  const rows = carved.map(c => `<tr>
    <td class="mono" style="font-size:var(--text-xs)">${c.name}</td>
    <td class="text-secondary">${c.type}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${c.offset}</td>
    <td class="text-muted">${c.size}</td>
    <td class="text-muted">${c.source}</td>
    <td><button class="btn btn-sm btn-secondary">${icons.download}</button></td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Carved Files</div>
    <table class="data-table">
      <thead><tr><th>File</th><th>Type</th><th>Offset</th><th>Size</th><th>Source</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderEvidence() {
  return `<div class="section">
    <div class="section-title mb-4">Evidence Items</div>
    <table class="data-table">
      <thead><tr><th>Item</th><th>Type</th><th>Source</th><th>Relevance</th></tr></thead>
      <tbody>
        <tr><td>Deleted secret.txt</td><td>File</td><td>filesystem.dd</td><td><span class="badge badge-high">High</span></td></tr>
        <tr><td>Bash history commands</td><td>Log</td><td>filesystem.dd</td><td><span class="badge badge-high">High</span></td></tr>
        <tr><td>/etc/shadow hashes</td><td>Credentials</td><td>filesystem.dd</td><td><span class="badge badge-high">High</span></td></tr>
        <tr><td>Hidden script in /tmp</td><td>Malware</td><td>filesystem.dd</td><td><span class="badge badge-medium">Medium</span></td></tr>
      </tbody>
    </table>
  </div>`;
}

function bindForensicsEvents() {
  document.querySelectorAll('#forensics-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab;
      renderForensics();
    });
  });
}
