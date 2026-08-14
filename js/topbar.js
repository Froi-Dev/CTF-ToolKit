import { activeCase, icons, icon } from './data.js';

const moduleLabels = {
  dashboard: 'Dashboard', cases: 'Cases', autotriage: 'Auto Triage',
  web: 'Web', crypto: 'Cryptography', forensics: 'Forensics',
  network: 'Network / PCAP', osint: 'OSINT', stego: 'Steganography',
  reverse: 'Reverse Eng.', binary: 'Binary / Pwn', malware: 'Malware Analysis',
  hashes: 'Hashes / Passwords', wordlists: 'Wordlists', reports: 'Reports', settings: 'Settings',
};

export function renderTopbar(activeModule) {
  const topbar = document.getElementById('topbar');
  const label = moduleLabels[activeModule] || 'Dashboard';
  topbar.innerHTML = `
    <div class="topbar-breadcrumb">
      <span style="font-weight:600;color:var(--text-primary)">CTFKit</span>
      <span class="topbar-breadcrumb-sep">/</span>
      <span>${label}</span>
    </div>
    <div class="topbar-case">
      <span class="topbar-case-dot"></span>
      <span>${activeCase.name} — ${activeCase.challenge}</span>
      ${icons.chevronDown}
    </div>
    <div class="topbar-spacer"></div>
    <div class="topbar-search">
      ${icons.search}
      <input type="text" placeholder="Search findings, files, flags..." />
      <kbd>⌘K</kbd>
    </div>
    <div class="topbar-status">
      <span class="topbar-status-dot online"></span>
      <span>Backend connected</span>
    </div>
    <div class="topbar-status">
      <span class="topbar-status-dot busy"></span>
      <span>2 workers active</span>
    </div>
    <button class="topbar-icon-btn" title="Notifications">${icons.bell}</button>
    <button class="topbar-icon-btn" title="Settings" onclick="window.location.hash='settings'">${icons.settings}</button>
    <div class="topbar-avatar" title="Profile">PR</div>
  `;
}
