import { ApiError } from '../api/client.ts';
import {
  investigateOsintTarget,
  type OsintInvestigationResponse,
  type OsintTargetType,
} from '../api/osint.ts';
import { icons } from '../data.ts';
import {
  availableIdentityPivots,
  cleanUsername,
  commonDorks,
  googleSearchUrl,
  identityCategories,
  normalizeDorkDomain,
  type IdentityContext,
  type IdentityPivot,
  type SearchReference,
} from './osint-dorks.ts';

let result: OsintInvestigationResponse | null = null;
let running = false;
let message = 'Enter a public domain, IP address, username, or URL.';
let isError = false;
let activeRequest: AbortController | null = null;
let dorkTarget = '';
let dorkError = '';
let identitySubject = '';
let identityName = '';
let identityEmail = '';
let identityAfterDate = '';
let identityBeforeDate = '';
let identitySearchType = 'profiles';

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function entityById(data: OsintInvestigationResponse, id: string): string {
  return data.entities.find(item => item.id === id)?.value || id;
}

export function renderOsint(view = 'website'): void {
  activeRequest?.abort();
  activeRequest = null;
  if (view === 'google-dorks') {
    renderGoogleDorks();
    return;
  }
  if (view === 'username') {
    renderUsernameSearch();
    return;
  }
  result = null;
  running = false;
  message = 'Enter a public domain, IP address, username, or URL.';
  isError = false;
  renderWebsiteShell();
}

function renderWebsiteShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content-wide" id="osint-page">
    <div class="page-header">
      <div><div class="page-title">Website OSINT</div><div class="page-subtitle">Passive public-data collection with source provenance and entity correlation</div></div>
      ${result ? `<button class="btn btn-secondary btn-sm" id="osint-export">${icons.download} Export JSON</button>` : ''}
    </div>
    <div class="panel mb-4"><div class="panel-body">
      <form class="osint-search" id="osint-form">
        <input class="input" id="osint-target" type="text" maxlength="2048" placeholder="example.com, 8.8.8.8, username, or https://example.com/" required>
        <select class="select" id="osint-type">
          <option value="auto">Auto detect</option><option value="domain">Domain</option><option value="ip">IP address</option><option value="username">Username</option><option value="url">URL metadata</option>
        </select>
        <label class="flex items-center gap-2 text-xs text-muted" title="Requires existing Google Programmable Search credentials on the backend"><input id="osint-live-search" type="checkbox"> Live Google results</label>
        <button class="btn btn-primary" type="submit" ${running ? 'disabled' : ''}>${running ? `${icons.loader} Collectingâ€¦` : `${icons.search} Investigate`}</button>
      </form>
      <div class="text-xs ${isError ? '' : 'text-muted'}" ${isError ? 'style="color:var(--error)"' : ''}>${escapeHtml(message)}</div>
      <div class="text-xs text-muted mt-4">Only public records and public profile endpoints are queried. Generated Google dorks are available without credentials; live results use the official configured API.</div>
    </div></div>
    ${result ? renderResults(result) : renderEmpty()}
  </div>`;
  bindEvents();
}

function renderEmpty(): string {
  return `<div class="section"><div class="empty-state"><div class="empty-state-icon">${icons.search}</div><div class="empty-state-title">No investigation results</div><div class="empty-state-text">Results are derived from live public providers. No sample entities or relationships are shown.</div></div></div>`;
}

function renderResults(data: OsintInvestigationResponse): string {
  const successful = data.providers.filter(item => item.status === 'success').length;
  return `${data.warnings.length ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Provider warnings</div><div class="panel-body text-xs">${data.warnings.map(item => `<div>Â· ${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
    <div class="pcap-stats"><div class="stat-row">
      <div class="stat-item"><div class="stat-label">Target type</div><div class="stat-value">${escapeHtml(data.target_type)}</div></div>
      <div class="stat-item"><div class="stat-label">Providers</div><div class="stat-value">${successful}/${data.providers.length}</div></div>
      <div class="stat-item"><div class="stat-label">Entities</div><div class="stat-value">${data.entities.length}</div></div>
      <div class="stat-item"><div class="stat-label">Relationships</div><div class="stat-value">${data.relationships.length}</div></div>
      <div class="stat-item"><div class="stat-label">DNS records</div><div class="stat-value">${data.dns_records.length}</div></div>
      <div class="stat-item"><div class="stat-label">Certificates</div><div class="stat-value">${data.certificates.length}</div></div>
    </div></div>
    ${renderProviders(data)}${renderProfilesAndMetadata(data)}${renderEntities(data)}${renderRelationships(data)}${renderDns(data)}${renderCertificates(data)}${renderSearch(data)}`;
}

function renderProviders(data: OsintInvestigationResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Provider runs</div><span class="text-xs text-muted">Each result retains its source</span></div><table class="data-table"><thead><tr><th>Provider</th><th>Status</th><th>Records</th><th>Duration</th><th>Source</th></tr></thead><tbody>${data.providers.map(item => `<tr><td>${escapeHtml(item.name)}</td><td><span class="badge ${item.status === 'success' ? 'badge-success' : item.status === 'no_data' ? 'badge-info' : 'badge-warning'}">${escapeHtml(item.status)}</span></td><td>${item.record_count}</td><td>${item.duration_ms} ms</td><td class="mono text-xs">${escapeHtml(item.source)}</td></tr>`).join('')}</tbody></table></div>`;
}

function renderProfilesAndMetadata(data: OsintInvestigationResponse): string {
  const profiles = data.username_profiles.length ? `<div class="section"><div class="section-title mb-4">Username adapters</div><div class="osint-entities">${data.username_profiles.map(item => `<div class="osint-entity"><div class="osint-entity-type">${escapeHtml(item.platform)} Â· ${item.exists ? 'observed' : 'not observed'}</div><div class="osint-entity-value">${escapeHtml(item.username)}</div><div class="text-xs text-muted mt-4">${escapeHtml(item.display_name || item.bio || 'No public profile metadata returned.')}</div><a class="text-xs" href="${escapeHtml(item.profile_url)}" target="_blank" rel="noopener noreferrer">Open public profile</a></div>`).join('')}</div></div>` : '';
  const metadata = data.web_metadata ? `<div class="section"><div class="section-title mb-4">Web metadata</div><div class="panel"><div class="panel-body"><div class="kv-list"><div class="kv-key">Title</div><div class="kv-value">${escapeHtml(data.web_metadata.title || 'â€”')}</div><div class="kv-key">Description</div><div class="kv-value">${escapeHtml(data.web_metadata.description || 'â€”')}</div><div class="kv-key">Canonical</div><div class="kv-value mono">${escapeHtml(data.web_metadata.canonical_url || 'â€”')}</div><div class="kv-key">JSON-LD types</div><div class="kv-value">${escapeHtml(data.web_metadata.json_ld_types.join(', ') || 'â€”')}</div></div></div></div></div>` : '';
  return profiles + metadata;
}

function renderEntities(data: OsintInvestigationResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Entities</div><span class="text-xs text-muted">Evidence-backed, deduplicated values</span></div><div class="osint-entities">${data.entities.map(item => `<div class="osint-entity"><div class="osint-entity-type">${escapeHtml(item.entity_type)}</div><div class="osint-entity-value">${escapeHtml(item.value)}</div><div class="text-xs text-muted mt-4">Sources: ${escapeHtml(item.sources.join(', '))}</div></div>`).join('')}</div></div>`;
}

function renderRelationships(data: OsintInvestigationResponse): string {
  return `<div class="section"><div class="section-title mb-4">Entity relationships</div><table class="data-table"><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th><th>Sources</th></tr></thead><tbody>${data.relationships.length ? data.relationships.map(item => `<tr><td class="mono text-xs">${escapeHtml(entityById(data, item.source_id))}</td><td>${escapeHtml(item.relationship)}</td><td class="mono text-xs">${escapeHtml(entityById(data, item.target_id))}</td><td>${Math.round(item.confidence * 100)}%</td><td>${escapeHtml(item.sources.join(', '))}</td></tr>`).join('') : '<tr><td colspan="5" class="text-muted">No relationships were derived.</td></tr>'}</tbody></table></div>`;
}

function renderDns(data: OsintInvestigationResponse): string {
  if (!data.dns_records.length && !data.ip_metadata.length) return '';
  return `<div class="section"><div class="section-title mb-4">DNS and IP metadata</div><table class="data-table"><thead><tr><th>Type</th><th>Name / Address</th><th>Value / Prefix</th><th>TTL / ASN</th></tr></thead><tbody>${data.dns_records.map(item => `<tr><td>${escapeHtml(item.record_type)}</td><td class="mono">${escapeHtml(item.name)}</td><td class="mono">${escapeHtml(item.value)}</td><td>${item.ttl ?? 'â€”'}</td></tr>`).join('')}${data.ip_metadata.map(item => `<tr><td>IP metadata</td><td class="mono">${escapeHtml(item.address)}</td><td class="mono">${escapeHtml(item.prefix || item.reverse_dns || 'â€”')}</td><td>${escapeHtml(item.asns.map(asn => `AS${asn}`).join(', ') || 'â€”')}</td></tr>`).join('')}</tbody></table></div>`;
}

function renderCertificates(data: OsintInvestigationResponse): string {
  if (!data.certificates.length) return '';
  return `<div class="section"><div class="section-header"><div class="section-title">Certificate Transparency</div><span class="text-xs text-muted">Public crt.sh observations</span></div><table class="data-table"><thead><tr><th>ID</th><th>Names</th><th>Issuer</th><th>Validity</th></tr></thead><tbody>${data.certificates.map(item => `<tr><td class="mono">${escapeHtml(item.certificate_id)}</td><td class="mono text-xs">${escapeHtml(item.dns_names.join(', '))}</td><td>${escapeHtml(item.issuer || 'â€”')}</td><td class="text-xs">${escapeHtml(item.not_before || 'â€”')} â†’ ${escapeHtml(item.not_after || 'â€”')}</td></tr>`).join('')}</tbody></table></div>`;
}

function renderSearch(data: OsintInvestigationResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Google dork queries</div><span class="text-xs text-muted">Open manually or configure the official API for live results</span></div><table class="data-table"><thead><tr><th>Purpose</th><th>Query</th><th></th></tr></thead><tbody>${data.search_queries.map(item => `<tr><td>${escapeHtml(item.label)}</td><td class="mono text-xs">${escapeHtml(item.query)}</td><td><a class="btn btn-secondary btn-sm" href="${escapeHtml(item.google_url)}" target="_blank" rel="noopener noreferrer">Open</a></td></tr>`).join('')}</tbody></table></div>${data.search_results.length ? `<div class="section"><div class="section-title mb-4">Live search results</div>${data.search_results.map(item => `<div class="panel mb-4"><div class="panel-body"><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)}</a><div class="text-xs text-muted mt-4">${escapeHtml(item.snippet || item.display_link || '')}</div></div></div>`).join('')}</div>` : ''}`;
}

function bindEvents(): void {
  document.getElementById('osint-form')?.addEventListener('submit', event => {
    event.preventDefault();
    void runInvestigation();
  });
  document.getElementById('osint-export')?.addEventListener('click', exportResult);
}

async function runInvestigation(): Promise<void> {
  if (running) return;
  const input = document.getElementById('osint-target') as HTMLInputElement | null;
  const select = document.getElementById('osint-type') as HTMLSelectElement | null;
  const liveSearch = document.getElementById('osint-live-search') as HTMLInputElement | null;
  const target = input?.value.trim() || '';
  if (!target) return;
  const controller = new AbortController();
  activeRequest?.abort();
  activeRequest = controller;
  running = true;
  isError = false;
  message = 'Querying bounded public-data providersâ€¦';
  renderWebsiteShell();
  try {
    result = await investigateOsintTarget(target, (select?.value || 'auto') as OsintTargetType, Boolean(liveSearch?.checked), controller.signal);
    message = `Investigation ${result.analysis_id} completed with ${result.providers.length} provider runs.`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    isError = true;
    message = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'OSINT investigation failed.';
  } finally {
    if (activeRequest === controller) {
      activeRequest = null;
      running = false;
      if (document.getElementById('osint-page')) renderWebsiteShell();
    }
  }
}

function renderGoogleDorks(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const exampleTarget = dorkTarget || 'example.com';
  main.innerHTML = `<div class="main-content-wide" id="osint-dorks-page">
    <div class="page-header">
      <div><div class="page-title">Common Google Dorks</div><div class="page-subtitle">Reusable search operators for public, indexed information</div></div>
    </div>
    <div class="panel mb-8"><div class="panel-body">
      <form class="osint-tool-form" id="osint-dork-form">
        <div class="osint-field"><label for="osint-dork-target">Website or domain</label><input class="input" id="osint-dork-target" type="text" maxlength="253" value="${escapeHtml(dorkTarget)}" placeholder="example.com" required></div>
        <button class="btn btn-primary" type="submit">${icons.search} Build queries</button>
      </form>
      ${dorkError ? `<div class="text-xs mt-4" style="color:var(--error)">${escapeHtml(dorkError)}</div>` : ''}
      <div class="text-xs text-muted mt-4">Use these searches only for public information and systems you are authorized to assess. The links open Google in a new tab.</div>
    </div></div>
    <div class="section"><div class="section-header"><div class="section-title">Most-used operators</div><span class="text-xs text-muted">${dorkTarget ? `Queries prepared for ${escapeHtml(dorkTarget)}` : 'Examples use example.com'}</span></div>
      <div class="osint-reference-grid">${commonDorks.map(item => renderSearchReference(item, exampleTarget)).join('')}</div>
    </div>
  </div>`;
  document.getElementById('osint-dork-form')?.addEventListener('submit', event => {
    event.preventDefault();
    const input = document.getElementById('osint-dork-target') as HTMLInputElement | null;
    const normalized = normalizeDorkDomain(input?.value || '');
    dorkError = normalized ? '' : 'Enter a valid fully qualified domain such as example.com.';
    if (normalized) dorkTarget = normalized;
    renderGoogleDorks();
  });
  bindCopyButtons();
}

function renderUsernameSearch(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const year = new Date().getFullYear();
  const afterDate = identityAfterDate || `${year - 4}-01-01`;
  const beforeDate = identityBeforeDate || `${year + 1}-01-01`;
  const username = cleanUsername(identitySubject);
  const context: IdentityContext = {
    username,
    name: identityName.trim().replace(/"/g, ''),
    subject: identityName.trim().replace(/"/g, '') || username,
    email: identityEmail.trim().replace(/"/g, ''),
    afterDate,
    beforeDate,
  };
  const availableSearches = availableIdentityPivots(context);
  const searches = identitySearchType === 'all'
    ? availableSearches
    : availableSearches.filter(item => item.category === identitySearchType);
  main.innerHTML = `<div class="main-content-wide" id="osint-username-page">
    <div class="page-header">
      <div><div class="page-title">User OSINT</div><div class="page-subtitle">Pivot from a username into public profiles, connections, posts, comments, and documents</div></div>
    </div>
    <div class="panel mb-8"><div class="panel-body">
      <form class="osint-tool-form osint-identity-form" id="osint-identity-form">
        <div class="osint-field"><label for="osint-identity-subject">Username / handle</label><input class="input" id="osint-identity-subject" type="text" maxlength="100" value="${escapeHtml(identitySubject)}" placeholder="proylan24" required></div>
        <div class="osint-field"><label for="osint-identity-name">Full name (optional)</label><input class="input" id="osint-identity-name" type="text" maxlength="150" value="${escapeHtml(identityName)}" placeholder="First Last"></div>
        <div class="osint-field"><label for="osint-identity-email">Email (optional)</label><input class="input" id="osint-identity-email" type="email" maxlength="254" value="${escapeHtml(identityEmail)}" placeholder="name@example.com"></div>
        <div class="osint-field"><label for="osint-identity-after">After date</label><input class="input" id="osint-identity-after" type="date" value="${escapeHtml(afterDate)}"></div>
        <div class="osint-field"><label for="osint-identity-before">Before date</label><input class="input" id="osint-identity-before" type="date" value="${escapeHtml(beforeDate)}"></div>
        <div class="osint-field"><label for="osint-identity-type">Search category</label><select class="select" id="osint-identity-type"><option value="all" ${identitySearchType === 'all' ? 'selected' : ''}>All categories</option>${identityCategories.map(item => `<option value="${item.id}" ${identitySearchType === item.id ? 'selected' : ''}>${escapeHtml(item.label)}</option>`).join('')}</select></div>
        <button class="btn btn-primary" type="submit">${icons.search} Build searches</button>
      </form>
      <div class="text-xs text-muted mt-4">Facebook, Instagram, TikTok, and LinkedIn are the primary profile checks. Direct profile links do not depend on Google indexing; the remaining pivots only surface public, indexed pages. Verify every identity match with corroborating evidence.</div>
    </div></div>
    ${identitySubject ? renderIdentityGroups(searches, context) : `<div class="section"><div class="empty-state"><div class="empty-state-icon">${icons.search}</div><div class="empty-state-title">Enter a username</div><div class="empty-state-text">Use a copied handle for direct profiles, then pivot into public connections, posts, comments, correlation clues, PDFs, and resumes.</div></div></div>`}
  </div>`;
  document.getElementById('osint-identity-form')?.addEventListener('submit', event => {
    event.preventDefault();
    const subject = document.getElementById('osint-identity-subject') as HTMLInputElement | null;
    const name = document.getElementById('osint-identity-name') as HTMLInputElement | null;
    const email = document.getElementById('osint-identity-email') as HTMLInputElement | null;
    const after = document.getElementById('osint-identity-after') as HTMLInputElement | null;
    const before = document.getElementById('osint-identity-before') as HTMLInputElement | null;
    const searchType = document.getElementById('osint-identity-type') as HTMLSelectElement | null;
    identitySubject = cleanUsername(subject?.value || '');
    identityName = name?.value.trim() || '';
    identityEmail = email?.value.trim() || '';
    identityAfterDate = after?.value || '';
    identityBeforeDate = before?.value || '';
    identitySearchType = searchType?.value || 'profiles';
    renderUsernameSearch();
  });
  bindCopyButtons();
}

function renderIdentityGroups(searches: IdentityPivot[], context: IdentityContext): string {
  return identityCategories.map(category => {
    const categorySearches = searches.filter(item => item.category === category.id);
    if (!categorySearches.length) return '';
    return `<div class="section"><div class="section-header"><div><div class="section-title">${escapeHtml(category.label)}</div><div class="text-xs text-muted mt-4">${escapeHtml(category.description)}</div></div><span class="text-xs text-muted">${categorySearches.length} pivots</span></div><div class="osint-reference-grid">${categorySearches.map(item => renderIdentityDestination(item, context)).join('')}</div></div>`;
  }).join('');
}

function renderSearchReference(item: SearchReference, target: string): string {
  const query = item.query(target);
  return `<article class="osint-reference-card">
    <div class="osint-reference-heading"><div><div class="osint-reference-title">${escapeHtml(item.label)}</div><div class="text-xs text-muted">${escapeHtml(item.description)}</div></div></div>
    <code class="osint-query">${escapeHtml(query)}</code>
    <div class="osint-reference-actions"><button class="btn btn-secondary btn-sm osint-copy-query" type="button" data-query="${escapeHtml(query)}">${icons.copy} Copy</button><a class="btn btn-primary btn-sm" href="${escapeHtml(googleSearchUrl(query))}" target="_blank" rel="noopener noreferrer">${icons.search} Search</a></div>
  </article>`;
}

function renderIdentityDestination(item: IdentityPivot, context: IdentityContext): string {
  const destination = item.destination(context);
  return `<article class="osint-reference-card">
    <div class="osint-reference-heading"><div><div class="osint-reference-title">${escapeHtml(item.label)}</div><div class="text-xs text-muted">${escapeHtml(item.description)}</div></div></div>
    <code class="osint-query">${escapeHtml(destination.display)}</code>
    <div class="osint-reference-actions"><button class="btn btn-secondary btn-sm osint-copy-query" type="button" data-query="${escapeHtml(destination.display)}">${icons.copy} Copy</button><a class="btn btn-primary btn-sm" href="${escapeHtml(destination.url)}" target="_blank" rel="noopener noreferrer">${icons.search} ${escapeHtml(destination.action)}</a></div>
  </article>`;
}

function bindCopyButtons(): void {
  document.querySelectorAll<HTMLButtonElement>('.osint-copy-query').forEach(button => {
    button.addEventListener('click', async () => {
      const query = button.dataset.query || '';
      try {
        await navigator.clipboard.writeText(query);
        button.textContent = 'Copied';
        window.setTimeout(() => { button.innerHTML = `${icons.copy} Copy`; }, 1200);
      } catch {
        button.textContent = 'Copy unavailable';
      }
    });
  });
}

function exportResult(): void {
  if (!result) return;
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `osint-${result.normalized_target.replace(/[^a-z0-9.-]/gi, '_')}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

