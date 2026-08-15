import { icons } from './data.ts';
import { navigationSections, resolveNavigation } from './navigation.ts';

let expandedItem: string | null = null;

export function renderSidebar(activePath: string): void {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;

  const activeRoute = resolveNavigation(activePath);
  expandedItem = activeRoute.parent.id;

  let html = `
    <div class="sidebar-brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
      <span class="sidebar-brand-name">CTFKit</span>
    </div>
    <nav class="sidebar-nav" aria-label="Primary navigation">
  `;

  for (const [sectionIndex, section] of navigationSections.entries()) {
    const sectionLabelId = `sidebar-section-${sectionIndex}`;
    html += `<div class="sidebar-section" aria-labelledby="${sectionLabelId}">`;
    html += `<div class="sidebar-section-label" id="${sectionLabelId}">${section.label}</div>`;

    for (const item of section.items) {
      const isActiveGroup = item.id === activeRoute.parent.id;
      const isExpanded = expandedItem === item.id;
      const submenuId = `submenu-${item.id}`;
      html += `
        <button class="sidebar-item sidebar-parent ${isActiveGroup ? 'has-active-child' : ''}" type="button"
          data-nav-parent="${item.id}" data-default-route="${item.children[0].route}"
          aria-expanded="${isExpanded}" aria-controls="${submenuId}" title="${item.label}">
          ${icons[item.icon as keyof typeof icons]}
          <span class="sidebar-item-label">${item.label}</span>
          <span class="sidebar-chevron" aria-hidden="true">${icons.chevronDown}</span>
        </button>
        <div class="sidebar-submenu" id="${submenuId}" ${isExpanded ? '' : 'hidden'} role="group" aria-label="${item.label}">
          ${item.children.map(itemChild => `<a class="sidebar-subitem ${itemChild.route === activeRoute.path ? 'active' : ''}"
            href="#${itemChild.route}" ${itemChild.route === activeRoute.path ? 'aria-current="page"' : ''}>${itemChild.label}</a>`).join('')}
        </div>
      `;
    }
    html += '</div>';
  }

  html += '</nav>';
  sidebar.innerHTML = html;

  sidebar.querySelectorAll<HTMLButtonElement>('[data-nav-parent]').forEach(button => {
    button.addEventListener('click', () => {
      const itemId = button.dataset.navParent;
      const submenu = itemId ? document.getElementById(`submenu-${itemId}`) : null;
      if (!itemId || !submenu) return;

      if (window.matchMedia('(max-width: 760px)').matches) {
        window.location.hash = button.dataset.defaultRoute || 'dashboard/findings';
        return;
      }

      const willExpand = expandedItem !== itemId;
      sidebar.querySelectorAll<HTMLButtonElement>('[data-nav-parent]').forEach(otherButton => {
        const otherId = otherButton.dataset.navParent;
        const otherSubmenu = otherId ? document.getElementById(`submenu-${otherId}`) : null;
        otherButton.setAttribute('aria-expanded', 'false');
        if (otherSubmenu) otherSubmenu.hidden = true;
      });
      expandedItem = willExpand ? itemId : null;
      button.setAttribute('aria-expanded', String(willExpand));
      submenu.hidden = !willExpand;
    });
  });
}
