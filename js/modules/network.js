import { pcapData, icons, formatTime } from '../data.js';

let activeTab = 'overview';
let activeStreamTab = 'ascii';

export function renderNetwork() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Network / PCAP Analysis</div><div class="page-subtitle">capture.pcap — ${pcapData.summary.totalPackets.toLocaleString()} packets</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.download} Export</button>
        <button class="btn btn-secondary btn-sm">${icons.filter} Filters</button>
      </div>
    </div>
    ${renderPcapStats()}
    <div class="tab-bar" id="network-tabs">
      <div class="tab-item ${activeTab==='overview'?'active':''}" data-tab="overview">Overview</div>
      <div class="tab-item ${activeTab==='protocols'?'active':''}" data-tab="protocols">Protocols</div>
      <div class="tab-item ${activeTab==='conversations'?'active':''}" data-tab="conversations">Conversations</div>
      <div class="tab-item ${activeTab==='streams'?'active':''}" data-tab="streams">TCP Streams <span class="tab-count">${pcapData.streams.length}</span></div>
      <div class="tab-item ${activeTab==='raw'?'active':''}" data-tab="raw">Raw Viewer</div>
    </div>
    <div id="network-content">${renderNetworkTab(activeTab)}</div>
  </div>`;
  bindNetworkEvents();
}

function renderPcapStats() {
  const s = pcapData.summary;
  return `<div class="pcap-stats">
    <div class="stat-row">
      <div class="stat-item"><div class="stat-label">Total Packets</div><div class="stat-value">${s.totalPackets.toLocaleString()}</div></div>
      <div class="stat-item"><div class="stat-label">Duration</div><div class="stat-value">${s.duration}</div></div>
      <div class="stat-item"><div class="stat-label">Unique Hosts</div><div class="stat-value">${s.uniqueHosts}</div></div>
      <div class="stat-item"><div class="stat-label">TCP Streams</div><div class="stat-value">${s.tcpStreams}</div></div>
      <div class="stat-item"><div class="stat-label">DNS Requests</div><div class="stat-value">${s.dnsRequests}</div></div>
      <div class="stat-item"><div class="stat-label">HTTP Requests</div><div class="stat-value">${s.httpRequests}</div></div>
    </div>
  </div>`;
}

function renderNetworkTab(tab) {
  switch(tab) {
    case 'overview': return renderOverview();
    case 'protocols': return renderProtocols();
    case 'conversations': return renderConversations();
    case 'streams': return renderStreams();
    case 'raw': return renderRawViewer();
    default: return '';
  }
}

function renderOverview() {
  return `<div class="split-h split-h-1-1">
    <div>${renderProtocols()}</div>
    <div>${renderConversations()}</div>
  </div>`;
}

function renderProtocols() {
  const rows = pcapData.protocols.map(p => {
    const barWidth = p.pct;
    return `<tr>
      <td class="font-medium">${p.protocol}</td>
      <td class="mono text-secondary" style="font-size:var(--text-xs)">${p.packets.toLocaleString()}</td>
      <td>
        <div class="flex items-center gap-3">
          <div style="width:100px;height:4px;background:var(--bg-tertiary);border-radius:2px;overflow:hidden">
            <div style="width:${barWidth}%;height:100%;background:var(--accent);border-radius:2px"></div>
          </div>
          <span class="text-xs text-muted">${p.pct}%</span>
        </div>
      </td>
    </tr>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">Protocol Distribution</div>
    <table class="data-table">
      <thead><tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderConversations() {
  const rows = pcapData.conversations.map(c => `
    <tr class="clickable">
      <td class="mono" style="font-size:var(--text-xs)">${c.src}</td>
      <td class="mono" style="font-size:var(--text-xs)">${c.dst}</td>
      <td class="text-secondary">${c.protocol}</td>
      <td class="text-secondary">${c.packets.toLocaleString()}</td>
      <td class="mono text-muted" style="font-size:var(--text-xs)">${c.bytes}</td>
      <td class="text-muted">${c.note}</td>
    </tr>
  `).join('');

  return `<div class="section">
    <div class="section-title mb-4">Conversations</div>
    <table class="data-table">
      <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderStreams() {
  const rows = pcapData.streams.map(s => {
    const flagBadges = s.flags.map(f => `<span class="badge badge-dot badge-warning">${f}</span>`).join(' ');
    return `<tr class="clickable" data-stream="${s.id}">
      <td class="mono text-muted" style="font-size:var(--text-xs)">#${s.id}</td>
      <td class="mono" style="font-size:var(--text-xs)">${s.src}</td>
      <td class="mono" style="font-size:var(--text-xs)">${s.dst}</td>
      <td class="text-secondary">${s.protocol}</td>
      <td class="mono text-muted" style="font-size:var(--text-xs)">${s.bytes}</td>
      <td>${flagBadges || '<span class="text-muted">—</span>'}</td>
    </tr>`;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">TCP Streams</div>
      <span class="text-xs text-muted">Click to view in Raw Viewer</span>
    </div>
    <table class="data-table">
      <thead><tr><th>Stream</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Indicators</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderRawViewer() {
  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Raw Stream Viewer</div>
      <span class="text-xs text-muted">Stream #0 — FTP Session</span>
    </div>
    <div class="raw-viewer">
      <div class="raw-viewer-toolbar">
        <div class="tab-bar" style="border:none;margin:0">
          <div class="tab-item ${activeStreamTab==='ascii'?'active':''}" data-stab="ascii" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">ASCII</div>
          <div class="tab-item ${activeStreamTab==='hex'?'active':''}" data-stab="hex" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">HEX</div>
        </div>
        <div class="topbar-spacer"></div>
        <div class="topbar-search" style="width:180px">
          ${icons.search}
          <input type="text" placeholder="Search stream..." style="font-size:var(--text-xs)" />
        </div>
        <button class="btn btn-sm btn-ghost">${icons.copy} Copy</button>
        <button class="btn btn-sm btn-ghost">${icons.download} Export</button>
        <button class="btn btn-sm btn-ghost">${icons.flag} Detect Flags</button>
      </div>
      <div class="raw-viewer-content" id="raw-content">${activeStreamTab === 'hex' ? renderHexContent() : renderAsciiContent()}</div>
    </div>
  </div>`;
}

function renderAsciiContent() {
  const lines = pcapData.rawStream.ascii.split('\r\n');
  return lines.map((line, i) => {
    let highlighted = line;
    // Highlight credentials and interesting strings
    highlighted = highlighted.replace(/(USER\s+\S+)/g, '<span class="code-highlight">$1</span>');
    highlighted = highlighted.replace(/(PASS\s+\S+)/g, '<span class="code-highlight">$1</span>');
    highlighted = highlighted.replace(/(RETR\s+\S+)/g, '<span class="code-highlight">$1</span>');
    return `<div class="code-line"><span class="code-line-num">${i + 1}</span><span class="code-line-content">${highlighted}</span></div>`;
  }).join('\n');
}

function renderHexContent() {
  return pcapData.rawStream.hex;
}

function bindNetworkEvents() {
  document.querySelectorAll('#network-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab;
      renderNetwork();
    });
  });

  document.querySelectorAll('[data-stab]').forEach(tab => {
    tab.addEventListener('click', () => {
      activeStreamTab = tab.dataset.stab;
      const content = document.getElementById('raw-content');
      if (content) {
        content.innerHTML = activeStreamTab === 'hex' ? renderHexContent() : renderAsciiContent();
      }
      document.querySelectorAll('[data-stab]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
    });
  });

  document.querySelectorAll('[data-stream]').forEach(row => {
    row.addEventListener('click', () => {
      activeTab = 'raw';
      renderNetwork();
    });
  });
}
