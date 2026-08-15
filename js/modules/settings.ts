import { icons } from '../data.ts';

let activeSection = 'general';

export function renderSettings(view?: string) {
  if (['general', 'analyzers', 'integrations', 'backend', 'appearance'].includes(view || '')) activeSection = view || 'general';
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Settings</div><div class="page-subtitle">Configure CTFKit preferences and integrations</div></div>
    </div>
    <div class="settings-layout">
      <div class="settings-nav" id="settings-nav">
        <div class="settings-nav-item ${activeSection==='general'?'active':''}" data-section="general">General</div>
        <div class="settings-nav-item ${activeSection==='analyzers'?'active':''}" data-section="analyzers">Analyzers</div>
        <div class="settings-nav-item ${activeSection==='integrations'?'active':''}" data-section="integrations">Integrations</div>
        <div class="settings-nav-item ${activeSection==='backend'?'active':''}" data-section="backend">Backend</div>
        <div class="settings-nav-item ${activeSection==='appearance'?'active':''}" data-section="appearance">Appearance</div>
      </div>
      <div id="settings-content">${renderSettingsSection(activeSection)}</div>
    </div>
  </div>`;
  bindSettingsEvents();
}

function renderSettingsSection(section: string): string {
  switch(section) {
    case 'general': return renderGeneral();
    case 'analyzers': return renderAnalyzers();
    case 'integrations': return renderIntegrations();
    case 'backend': return renderBackend();
    case 'appearance': return renderAppearance();
    default: return '';
  }
}

function renderGeneral() {
  return `
    <div class="settings-section">
      <div class="settings-section-title">General Settings</div>
      <div class="settings-section-desc">Configure basic CTFKit preferences</div>
      <div class="settings-field">
        <div class="settings-field-label">Default Case Name Prefix</div>
        <input class="input" type="text" value="CTF-" style="max-width:300px" />
      </div>
      <div class="settings-field">
        <div class="settings-field-label">Auto-save interval</div>
        <select class="select" style="max-width:200px">
          <option>Every 30 seconds</option>
          <option selected>Every 1 minute</option>
          <option>Every 5 minutes</option>
          <option>Manual only</option>
        </select>
      </div>
      <div class="settings-field">
        <div class="settings-field-label">Flag Patterns</div>
        <textarea class="textarea" rows="3" style="max-width:400px">CTF{.*}
FLAG{.*}
flag{.*}</textarea>
        <div class="settings-field-hint">Regular expressions to detect flag patterns (one per line)</div>
      </div>
      <div class="settings-field">
        <div class="settings-field-label">Max file upload size</div>
        <select class="select" style="max-width:200px">
          <option>256 MB</option>
          <option selected>512 MB</option>
          <option>1 GB</option>
          <option>2 GB</option>
        </select>
      </div>
    </div>
  `;
}

function renderAnalyzers() {
  const analyzers = [
    { name: 'Network Analyzer', desc: 'PCAP parsing, stream extraction, protocol analysis', enabled: true },
    { name: 'Forensics Engine', desc: 'Disk image analysis, file recovery, timeline generation', enabled: true },
    { name: 'Stego Detector', desc: 'LSB analysis, file carving, metadata extraction', enabled: true },
    { name: 'Crypto Decoder', desc: 'Encoding detection, cipher analysis, key search', enabled: true },
    { name: 'Binary Analyzer', desc: 'ELF/PE parsing, string extraction, disassembly', enabled: true },
    { name: 'Web Scanner', desc: 'HTTP analysis, endpoint discovery, technology detection', enabled: false },
    { name: 'Malware Sandbox', desc: 'Behavioral analysis, IOC extraction', enabled: false },
  ];

  const rows = analyzers.map(a => `<tr>
    <td class="font-medium">${a.name}</td>
    <td class="text-secondary" style="font-size:var(--text-xs)">${a.desc}</td>
    <td><span class="badge badge-dot ${a.enabled?'badge-success':'badge-info'}">${a.enabled?'enabled':'disabled'}</span></td>
    <td><button class="btn btn-sm btn-ghost">${icons.settings}</button></td>
  </tr>`).join('');

  return `<div class="settings-section">
    <div class="settings-section-title">Analyzers</div>
    <div class="settings-section-desc">Configure analysis engines and modules</div>
    <table class="data-table">
      <thead><tr><th>Analyzer</th><th>Description</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderIntegrations() {
  return `<div class="settings-section">
    <div class="settings-section-title">Integrations</div>
    <div class="settings-section-desc">Connect CTFKit to external services</div>
    <div class="settings-field">
      <div class="settings-field-label">VirusTotal API Key</div>
      <input class="input" type="password" value="••••••••••••••••" style="max-width:400px;font-family:var(--font-mono)" />
    </div>
    <div class="settings-field">
      <div class="settings-field-label">Shodan API Key</div>
      <input class="input" type="password" placeholder="Enter API key..." style="max-width:400px;font-family:var(--font-mono)" />
    </div>
    <div class="settings-field">
      <div class="settings-field-label">CyberChef Instance URL</div>
      <input class="input" type="text" value="https://gchq.github.io/CyberChef/" style="max-width:400px;font-family:var(--font-mono)" />
    </div>
    <button class="btn btn-primary mt-4">Save Integrations</button>
  </div>`;
}

function renderBackend() {
  return `<div class="settings-section">
    <div class="settings-section-title">Backend Configuration</div>
    <div class="settings-section-desc">Configure the CTFKit analysis backend</div>
    <div class="panel"><div class="panel-body">
      <div class="kv-list">
        <div class="kv-key">Status</div><div class="kv-value"><span class="badge badge-dot badge-success">Connected</span></div>
        <div class="kv-key">Endpoint</div><div class="kv-value mono" style="font-size:var(--text-xs)">http://localhost:8080</div>
        <div class="kv-key">Version</div><div class="kv-value mono">v2.4.1</div>
        <div class="kv-key">Workers</div><div class="kv-value">4 / 4 active</div>
        <div class="kv-key">Queue</div><div class="kv-value">2 jobs pending</div>
        <div class="kv-key">Storage</div><div class="kv-value">12.4 GB / 50 GB used</div>
        <div class="kv-key">Uptime</div><div class="kv-value mono">3d 14h 22m</div>
      </div>
    </div></div>
  </div>`;
}

function renderAppearance() {
  return `<div class="settings-section">
    <div class="settings-section-title">Appearance</div>
    <div class="settings-section-desc">Customize the look and feel of CTFKit</div>
    <div class="settings-field">
      <div class="settings-field-label">Theme</div>
      <select class="select" style="max-width:200px">
        <option selected>Light</option>
        <option>Dark</option>
        <option>System</option>
      </select>
    </div>
    <div class="settings-field">
      <div class="settings-field-label">Font Size</div>
      <select class="select" style="max-width:200px">
        <option>12px</option>
        <option selected>13px</option>
        <option>14px</option>
      </select>
    </div>
    <div class="settings-field">
      <div class="settings-field-label">Monospace Font</div>
      <select class="select" style="max-width:200px">
        <option selected>JetBrains Mono</option>
        <option>Fira Code</option>
        <option>Cascadia Code</option>
        <option>Consolas</option>
      </select>
    </div>
    <div class="settings-field">
      <div class="settings-field-label">Sidebar Width</div>
      <select class="select" style="max-width:200px">
        <option>Compact (160px)</option>
        <option selected>Default (200px)</option>
        <option>Wide (240px)</option>
      </select>
    </div>
    <button class="btn btn-primary mt-4">Save Appearance</button>
  </div>`;
}

function bindSettingsEvents() {
  document.querySelectorAll<HTMLElement>('#settings-nav .settings-nav-item').forEach(item => {
    item.addEventListener('click', () => {
      activeSection = item.dataset.section ?? 'general';
      renderSettings();
    });
  });
}


