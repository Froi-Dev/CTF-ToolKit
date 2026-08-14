import { osintData, icons } from '../data.js';

export function renderOsint() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">OSINT</div><div class="page-subtitle">Open-source intelligence research workspace</div></div>
    </div>
    ${renderSearch()}
    ${renderEntities()}
    ${renderRelationships()}
  </div>`;
}

function renderSearch() {
  return `<div class="osint-search">
    <input class="input" type="text" placeholder="Search username, email, IP, domain..." value="admin_shadow" />
    <select class="select">
      <option>All Types</option>
      <option>Username</option>
      <option>Email</option>
      <option>IP Address</option>
      <option>Domain</option>
    </select>
    <button class="btn btn-primary">${icons.search} Search</button>
  </div>`;
}

function renderEntities() {
  const rows = osintData.entities.map(e => {
    let extra = '';
    if (e.platforms) extra = `<div class="text-xs text-muted mt-4">Platforms: ${e.platforms.join(', ')}</div>`;
    if (e.location) extra = `<div class="text-xs text-muted mt-4">${e.location} · ${e.asn}</div>`;
    if (e.registrar) extra = `<div class="text-xs text-muted mt-4">${e.registrar} · Created ${e.created}</div>`;
    const note = e.note ? `<div class="badge badge-warning mt-4" style="font-size:9px">${e.note}</div>` : '';

    return `<div class="osint-entity">
      <div class="osint-entity-type">${e.type}</div>
      <div class="osint-entity-value">${e.value}</div>
      <div class="text-xs text-muted" style="margin-top:var(--sp-2)">Source: ${e.source}</div>
      ${extra}${note}
    </div>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">Entities</div>
    <div class="osint-entities">${rows}</div>
  </div>`;
}

function renderRelationships() {
  const rows = osintData.relationships.map(r => `<tr>
    <td class="mono" style="font-size:var(--text-xs)">${r.from}</td>
    <td class="text-secondary">${r.relation}</td>
    <td class="mono" style="font-size:var(--text-xs)">${r.to}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Relationships</div>
    <table class="data-table">
      <thead><tr><th>From</th><th>Relationship</th><th>To</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}
