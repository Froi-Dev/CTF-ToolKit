import type { ResolvedNavigation } from './navigation.ts';

export function renderTopbar(activeRoute: ResolvedNavigation): void {
  const topbar = document.getElementById('topbar');
  if (!topbar) return;
  topbar.innerHTML = `
    <div class="topbar-breadcrumb">
      <span style="font-weight:600;color:var(--text-primary)">Pr0y1 ToolKit</span>
      <span class="topbar-breadcrumb-sep">/</span>
      <span>${activeRoute.parent.label}</span>
      <span class="topbar-breadcrumb-sep">/</span>
      <span class="topbar-breadcrumb-current">${activeRoute.child.label}</span>
    </div>
  `;
}
