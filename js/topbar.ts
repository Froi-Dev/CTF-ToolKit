import { activeCase, icons } from './data.ts';
import type { ResolvedNavigation } from './navigation.ts';

export function renderTopbar(activeRoute: ResolvedNavigation): void {
  const topbar = document.getElementById('topbar');
  if (!topbar) return;
  topbar.innerHTML = `
    <div class="topbar-breadcrumb">
      <span style="font-weight:600;color:var(--text-primary)">CTFKit</span>
      <span class="topbar-breadcrumb-sep">/</span>
      <span>${activeRoute.parent.label}</span>
      <span class="topbar-breadcrumb-sep">/</span>
      <span class="topbar-breadcrumb-current">${activeRoute.child.label}</span>
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
    <button class="topbar-icon-btn" title="Settings" onclick="window.location.hash='settings/general'">${icons.settings}</button>
    <div class="topbar-avatar" title="Profile">PR</div>
  `;
}
