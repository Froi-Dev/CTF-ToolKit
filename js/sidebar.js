import { icons } from './data.js';

const navItems = [
  { section: 'Overview', items: [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { id: 'cases', label: 'Cases', icon: 'cases' },
    { id: 'autotriage', label: 'Auto Triage', icon: 'triage' },
  ]},
  { section: 'Analysis', items: [
    { id: 'web', label: 'Web', icon: 'web' },
    { id: 'crypto', label: 'Cryptography', icon: 'crypto' },
    { id: 'forensics', label: 'Forensics', icon: 'forensics' },
    { id: 'network', label: 'Network / PCAP', icon: 'network' },
    { id: 'osint', label: 'OSINT', icon: 'osint' },
    { id: 'stego', label: 'Steganography', icon: 'stego' },
    { id: 'reverse', label: 'Reverse Eng.', icon: 'reverse' },
    { id: 'binary', label: 'Binary / Pwn', icon: 'binary' },
    { id: 'malware', label: 'Malware Analysis', icon: 'malware' },
  ]},
  { section: 'Tools', items: [
    { id: 'hashes', label: 'Hashes / Passwords', icon: 'hashes' },
    { id: 'wordlists', label: 'Wordlists', icon: 'wordlists' },
  ]},
  { section: '', items: [
    { id: 'reports', label: 'Reports', icon: 'reports' },
    { id: 'settings', label: 'Settings', icon: 'settings' },
  ]},
];

export function renderSidebar(activeModule) {
  const sidebar = document.getElementById('sidebar');
  let html = `
    <div class="sidebar-brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
      <span class="sidebar-brand-name">CTFKit</span>
    </div>
    <nav class="sidebar-nav">
  `;

  for (const section of navItems) {
    html += '<div class="sidebar-section">';
    if (section.section) {
      html += `<div class="sidebar-section-label">${section.section}</div>`;
    }
    for (const item of section.items) {
      const isActive = item.id === activeModule;
      html += `
        <div class="sidebar-item ${isActive ? 'active' : ''}" data-module="${item.id}">
          ${icons[item.icon]}
          <span>${item.label}</span>
        </div>
      `;
    }
    html += '</div>';
  }

  html += '</nav>';
  sidebar.innerHTML = html;

  // Bind click events
  sidebar.querySelectorAll('.sidebar-item').forEach(el => {
    el.addEventListener('click', () => {
      const mod = el.dataset.module;
      window.location.hash = mod;
    });
  });
}
