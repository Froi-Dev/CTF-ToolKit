import { ApiError } from '../api/client.ts';
import {
  analyzeWebTarget, startActiveRecon,
  type TargetScope, type WebAnalysisResponse, type ActiveReconResponse,
  type ActiveReconInput,
} from '../api/web.ts';
import { icons } from '../data.ts';

type WebTab = 'overview' | 'endpoints' | 'http' | 'discovery' | 'auth' | 'jwt';
type ReconTab = 'recon-overview' | 'crawl-map' | 'dir-scan' | 'param-analysis' | 'xss-findings' | 'browser-capture' | 'flags';
type WebMode = 'passive' | 'active';

let webMode: WebMode = 'passive';
let activeTab: WebTab = 'overview';
let reconTab: ReconTab = 'recon-overview';
let result: WebAnalysisResponse | null = null;
let reconResult: ActiveReconResponse | null = null;
let activeRequest: AbortController | null = null;
let analyzing = false;
let statusMessage = 'Enter an authorized CTF, lab, or owned target.';
let statusIsError = false;

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function emptyRow(columns: number, message: string): string {
  return `<tr><td colspan="${columns}" class="text-muted">${escapeHtml(message)}</td></tr>`;
}

function severityBadge(severity: string): string {
  const map: Record<string, string> = { high: 'badge-error', medium: 'badge-warning', low: 'badge-info', info: 'badge-outline' };
  return `<span class="badge ${map[severity] || 'badge-outline'}">${escapeHtml(severity)}</span>`;
}

export function renderWeb(view?: string): void {
  activeRequest?.abort();
  activeRequest = null;
  activeTab = 'overview';
  reconTab = 'recon-overview';
  result = null;
  reconResult = null;
  analyzing = false;
  statusMessage = 'Enter an authorized CTF, lab, or owned target.';
  statusIsError = false;
  webMode = view === 'active' ? 'active' : 'passive';
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content-wide" id="web-page">
    <div class="page-header"><div><div class="page-title">Web Analysis</div><div class="page-subtitle">${webMode === 'passive' ? 'Bounded passive HTTP inspection' : 'Active recon, XSS testing, and browser analysis'} for authorized targets</div></div>
      <div class="page-actions">${webMode === 'active' && reconResult ? `<button class="btn btn-secondary btn-sm" id="web-export">${icons.download} Export JSON</button>` : ''}${webMode === 'passive' && result ? `<button class="btn btn-secondary btn-sm" id="web-export">${icons.download} Export JSON</button>` : ''}<button class="btn btn-primary btn-sm" id="web-run" ${analyzing ? 'disabled' : ''}>${analyzing ? `${icons.loader} ${webMode === 'active' ? 'Scanning…' : 'Analyzing…'}` : `${icons.play} ${webMode === 'active' ? 'Start Recon' : 'Analyze'}`}</button></div>
    </div>
    ${renderModeToggle()}
    ${webMode === 'passive' ? renderPassiveMode() : renderActiveMode()}
  </div>`;
  bindEvents();
}

function renderModeToggle(): string {
  return `<div class="web-mode-toggle mb-4">
    <button class="web-mode-btn ${webMode === 'passive' ? 'active' : ''}" data-mode="passive">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
      Passive Analysis
    </button>
    <button class="web-mode-btn ${webMode === 'active' ? 'active' : ''}" data-mode="active">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      Active Recon
    </button>
  </div>`;
}

// =========================================================================
// PASSIVE MODE (existing functionality)
// =========================================================================

function renderPassiveMode(): string {
  return `${renderPassiveForm()}
    <div class="text-xs ${statusIsError ? '' : 'text-muted'} mb-4" ${statusIsError ? 'style="color:var(--error)"' : ''}>${escapeHtml(statusMessage)}</div>
    ${result ? renderPassiveResults(result) : renderEmptyState('No Web evidence loaded', 'No sample endpoints, tokens, cookies, or findings are shown. Run an authorized analysis to populate this module.')}`;
}

function renderPassiveForm(): string {
  return `<div class="panel mb-4"><div class="panel-header">Authorized target</div><div class="panel-body">
    <div class="flex gap-4 mb-4" style="align-items:flex-end;flex-wrap:wrap"><div style="flex:3;min-width:300px"><label class="text-xs text-muted" for="web-url">HTTP/HTTPS URL</label><input class="input mono mt-4" id="web-url" type="url" placeholder="http://127.0.0.1:8080/" value="${escapeHtml(result?.exchange.url || '')}"></div>
      <div style="flex:1;min-width:150px"><label class="text-xs text-muted" for="web-scope">Scope</label><select class="select mt-4" id="web-scope"><option value="ctf">CTF challenge</option><option value="lab">Lab</option><option value="owned">User-owned</option></select></div>
      <div style="min-width:110px"><label class="text-xs text-muted" for="web-method">Method</label><select class="select mt-4" id="web-method"><option>GET</option><option>HEAD</option></select></div></div>
    <div class="flex gap-4 mb-4" style="flex-wrap:wrap"><div style="flex:1;min-width:280px"><label class="text-xs text-muted" for="web-auth">Authorization header (optional)</label><input class="input mono mt-4" id="web-auth" autocomplete="off" placeholder="Bearer … or Basic …"></div>
      <div style="flex:1;min-width:280px"><label class="text-xs text-muted" for="web-cookies">Request cookies (optional)</label><input class="input mono mt-4" id="web-cookies" autocomplete="off" placeholder="session=value; role=user"></div></div>
    <div class="flex items-center gap-4" style="flex-wrap:wrap">
      <label class="text-xs"><input id="web-authorized" type="checkbox"> I confirm this is an authorized CTF, lab, or system I own</label>
      <label class="text-xs"><input id="web-js" type="checkbox" checked> Fetch same-origin JavaScript/source maps</label>
      <label class="text-xs"><input id="web-compare" type="checkbox"> Compare without supplied authentication</label>
    </div>
    <div class="text-xs text-muted mt-4">GET/HEAD only. Redirects and every fetched resource are revalidated; cloud metadata and link-local destinations are blocked.</div>
  </div></div>`;
}

function renderEmptyState(title: string, text: string): string {
  return `<div class="section"><div class="empty-state"><div class="empty-state-icon">${icons.search}</div><div class="empty-state-title">${escapeHtml(title)}</div><div class="empty-state-text">${escapeHtml(text)}</div></div></div>`;
}

function renderPassiveResults(data: WebAnalysisResponse): string {
  const tabs: Array<[WebTab, string, number | null]> = [
    ['overview', 'Overview', null], ['endpoints', 'Endpoints & Parameters', data.endpoints.length],
    ['http', 'Headers & Cookies', data.cookies.length], ['discovery', 'Discovery', data.documents.length + data.comments.length],
    ['auth', 'Authentication', data.authentication.login_forms.length], ['jwt', 'JWTs', data.jwts.length],
  ];
  return `<div class="web-target"><span class="badge badge-dot ${data.exchange.status_code < 400 ? 'badge-success' : 'badge-warning'}">HTTP ${data.exchange.status_code}</span><span class="mono text-sm">${escapeHtml(data.exchange.url)}</span><div class="topbar-spacer"></div><span class="text-xs text-muted">${data.exchange.elapsed_ms} ms · ${formatBytes(data.exchange.body_bytes)} · ${escapeHtml(data.target_scope)}</span></div>
    <div class="tab-bar" id="web-tabs">${tabs.map(([id, label, count]) => `<div class="tab-item ${activeTab === id ? 'active' : ''}" data-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}</div>
    <div id="web-content">${renderPassiveTab(data)}</div>`;
}

function renderPassiveTab(data: WebAnalysisResponse): string {
  if (activeTab === 'endpoints') return renderEndpoints(data);
  if (activeTab === 'http') return renderHttp(data);
  if (activeTab === 'discovery') return renderDiscovery(data);
  if (activeTab === 'auth') return renderAuth(data);
  if (activeTab === 'jwt') return renderJwt(data);
  return renderOverview(data);
}

function renderOverview(data: WebAnalysisResponse): string {
  const comparison = data.comparison.performed
    ? `<div class="panel"><div class="panel-header">Response comparison</div><div class="panel-body"><div class="kv-list"><div class="kv-key">Authenticated status</div><div class="kv-value">${data.comparison.baseline_status ?? '—'}</div><div class="kv-key">Without auth</div><div class="kv-value">${data.comparison.comparison_status ?? '—'}</div><div class="kv-key">Body similarity</div><div class="kv-value">${data.comparison.body_similarity === null ? '—' : `${Math.round(data.comparison.body_similarity * 100)}%`}</div></div><div class="text-xs text-muted mt-4">${escapeHtml(data.comparison.authentication_effect || data.comparison.error || '')}</div></div></div>`
    : '<div class="panel"><div class="panel-header">Response comparison</div><div class="panel-body text-sm text-muted">Not requested.</div></div>';
  return `${data.warnings.length ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${data.warnings.map(item => `<div>· ${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
    <div class="network-evidence-grid mb-8"><div class="panel"><div class="panel-header">Evidence summary</div><div class="panel-body"><div class="kv-list"><div class="kv-key">Endpoints</div><div class="kv-value">${data.endpoints.length}</div><div class="kv-key">Parameters</div><div class="kv-value">${data.parameters.length}</div><div class="kv-key">Scripts</div><div class="kv-value">${data.scripts.length}</div><div class="kv-key">HTML comments</div><div class="kv-value">${data.comments.length}</div><div class="kv-key">Technologies</div><div class="kv-value">${data.technologies.length}</div><div class="kv-key">JWT candidates</div><div class="kv-value">${data.jwts.length}</div></div></div></div>${comparison}</div>
    <div class="section"><div class="section-title mb-4">Technology fingerprinting</div><div class="osint-entities">${data.technologies.length ? data.technologies.map(item => `<div class="osint-entity"><div class="osint-entity-type">${Math.round(item.confidence * 100)}% confidence</div><div class="osint-entity-value">${escapeHtml(item.name)} ${escapeHtml(item.version || '')}</div><div class="text-xs text-muted mt-4">${escapeHtml(item.evidence.join(' · '))}</div></div>`).join('') : '<span class="text-sm text-muted">No technology signatures were identified.</span>'}</div></div>`;
}

function renderEndpoints(data: WebAnalysisResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Discovered endpoints</div><span class="text-xs text-muted">Evidence only; endpoints were not brute-forced</span></div><table class="data-table"><thead><tr><th>Path</th><th>Method</th><th>Parameters</th><th>Evidence</th></tr></thead><tbody>${data.endpoints.length ? data.endpoints.map(item => `<tr><td class="mono">${escapeHtml(item.path)}</td><td><span class="badge badge-outline">${escapeHtml(item.method)}</span></td><td class="mono text-muted">${escapeHtml(item.parameters.join(', ') || '—')}</td><td class="text-muted">${escapeHtml(item.sources.join(', '))}</td></tr>`).join('') : emptyRow(4, 'No endpoints were extracted.')}</tbody></table></div>
    <div class="section"><div class="section-title mb-4">Parameter discovery</div><table class="data-table"><thead><tr><th>Name</th><th>Locations</th><th>Sources</th></tr></thead><tbody>${data.parameters.length ? data.parameters.map(item => `<tr><td class="mono">${escapeHtml(item.name)}</td><td>${escapeHtml(item.locations.join(', '))}</td><td class="text-muted">${escapeHtml(item.sources.join(', '))}</td></tr>`).join('') : emptyRow(3, 'No parameters were extracted.')}</tbody></table></div>`;
}

function renderHttp(data: WebAnalysisResponse): string {
  const raw = (title: string, headers: Array<{ name: string; value: string }>) => `<div class="section"><div class="section-title mb-4">${title}</div><table class="data-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${headers.map(item => `<tr><td class="mono">${escapeHtml(item.name)}</td><td class="mono text-muted" style="word-break:break-all">${escapeHtml(item.value)}</td></tr>`).join('')}</tbody></table></div>`;
  return `${raw('HTTP request inspection', data.exchange.request_headers)}${raw('HTTP response headers', data.exchange.response_headers)}<div class="section"><div class="section-title mb-4">Header assessments</div><table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Assessment</th></tr></thead><tbody>${data.headers.map(item => `<tr><td class="mono">${escapeHtml(item.name)}</td><td><span class="badge ${item.status === 'missing' ? 'badge-error' : 'badge-info'}">${escapeHtml(item.status)}</span></td><td class="mono text-muted">${escapeHtml(item.value || '—')}</td><td class="text-muted">${escapeHtml(item.note)}</td></tr>`).join('')}</tbody></table></div>
    <div class="section"><div class="section-title mb-4">Cookies</div><table class="data-table"><thead><tr><th>Name</th><th>Source</th><th>Flags</th><th>Value</th><th>Issues</th></tr></thead><tbody>${data.cookies.length ? data.cookies.map(item => `<tr><td class="mono">${escapeHtml(item.name)}</td><td>${item.source}</td><td>${[item.secure && 'Secure', item.http_only && 'HttpOnly', item.same_site && `SameSite=${item.same_site}`].filter(Boolean).map(flag => `<span class="badge badge-info">${escapeHtml(flag)}</span>`).join(' ') || '—'}</td><td class="mono" style="max-width:280px;word-break:break-all">${escapeHtml(item.value)}</td><td class="text-muted">${escapeHtml(item.issues.join(' ') || 'None detected')}</td></tr>`).join('') : emptyRow(5, 'No request or response cookies were observed.')}</tbody></table></div>`;
}

function renderDiscovery(data: WebAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">robots.txt and sitemap evidence</div><div class="split-h split-h-1-1"><div><div class="text-xs text-muted mb-4">robots.txt directives</div><pre class="mono text-xs">${escapeHtml(data.robots_rules.join('\n') || 'No directives discovered.')}</pre></div><div><div class="text-xs text-muted mb-4">Sitemap URLs</div><pre class="mono text-xs">${escapeHtml(data.sitemap_urls.join('\n') || 'No sitemap URLs discovered.')}</pre></div></div></div>
    <div class="section"><div class="section-title mb-4">Fetched discovery documents</div><table class="data-table"><thead><tr><th>Kind</th><th>URL</th><th>Status</th><th>Size</th><th>Result</th></tr></thead><tbody>${data.documents.length ? data.documents.map(item => `<tr><td>${escapeHtml(item.kind)}</td><td class="mono">${escapeHtml(item.url)}</td><td>${item.status_code ?? '—'}</td><td>${formatBytes(item.size)}</td><td class="text-muted">${escapeHtml(item.error || (item.truncated ? 'Truncated at limit' : 'Fetched'))}</td></tr>`).join('') : emptyRow(5, 'No discovery documents were requested.')}</tbody></table></div>
    <div class="section"><div class="section-title mb-4">JavaScript discovery and source maps</div><table class="data-table"><thead><tr><th>Script</th><th>Status</th><th>Size</th><th>Source maps</th></tr></thead><tbody>${data.scripts.length ? data.scripts.map(item => `<tr><td class="mono">${escapeHtml(item.url || 'inline script')}</td><td>${item.status_code ?? 'inline'}</td><td>${formatBytes(item.size)}</td><td class="mono text-muted">${escapeHtml(item.source_maps.join(', ') || '—')}</td></tr>`).join('') : emptyRow(4, 'No scripts were discovered.')}</tbody></table></div>
    <div class="section"><div class="section-title mb-4">HTML comments</div><table class="data-table"><thead><tr><th>Source</th><th>Line</th><th>Comment</th></tr></thead><tbody>${data.comments.length ? data.comments.map(item => `<tr><td class="mono">${escapeHtml(item.source)}</td><td>${item.line}</td><td class="mono">${escapeHtml(item.text)}</td></tr>`).join('') : emptyRow(3, 'No HTML comments were found.')}</tbody></table></div>`;
}

function renderAuth(data: WebAnalysisResponse): string {
  return `<div class="network-evidence-grid mb-8"><div class="panel"><div class="panel-header">Authentication inspection</div><div class="panel-body"><div class="kv-list"><div class="kv-key">Request scheme</div><div class="kv-value">${escapeHtml(data.authentication.request_authorization_scheme || 'None')}</div><div class="kv-key">Challenges</div><div class="kv-value">${escapeHtml(data.authentication.response_challenges.join(', ') || 'None')}</div><div class="kv-key">Session cookies</div><div class="kv-value">${escapeHtml(data.authentication.session_cookie_names.join(', ') || 'None')}</div></div>${data.authentication.observations.map(item => `<div class="text-xs text-muted mt-4">· ${escapeHtml(item)}</div>`).join('')}</div></div>
    <div class="panel"><div class="panel-header">Response comparison</div><div class="panel-body"><div class="text-sm">${escapeHtml(data.comparison.authentication_effect || data.comparison.error || 'Not requested.')}</div>${data.comparison.differing_headers.length ? `<div class="text-xs text-muted mt-4">Differing headers: ${escapeHtml(data.comparison.differing_headers.join(', '))}</div>` : ''}</div></div></div>
    <div class="section"><div class="section-title mb-4">Login forms</div><table class="data-table"><thead><tr><th>Action</th><th>Method</th><th>Username fields</th><th>Password fields</th></tr></thead><tbody>${data.authentication.login_forms.length ? data.authentication.login_forms.map(item => `<tr><td class="mono">${escapeHtml(item.action)}</td><td>${escapeHtml(item.method)}</td><td class="mono">${escapeHtml(item.username_fields.join(', ') || '—')}</td><td class="mono">${escapeHtml(item.password_fields.join(', '))}</td></tr>`).join('') : emptyRow(4, 'No password-bearing forms were found.')}</tbody></table></div>`;
}

function renderJwt(data: WebAnalysisResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">JWT analysis</div><span class="text-xs text-muted">Claims are decoded, never signature-verified</span></div>${data.jwts.length ? data.jwts.map(item => `<div class="panel mb-4"><div class="panel-header"><span class="mono">${escapeHtml(item.token_preview)}</span><span class="badge ${item.algorithm?.toLowerCase() === 'none' ? 'badge-error' : 'badge-info'}">alg: ${escapeHtml(item.algorithm || 'missing')}</span></div><div class="panel-body"><div class="text-xs text-muted mb-4">Source: ${escapeHtml(item.source)} · signature present: ${item.signature_present ? 'yes' : 'no'} · signature verified: no${item.expires_at ? ` · expires ${escapeHtml(item.expires_at)}` : ''}</div><div class="split-h split-h-1-1"><pre class="mono text-xs">${escapeHtml(JSON.stringify(item.header, null, 2))}</pre><pre class="mono text-xs">${escapeHtml(JSON.stringify(item.payload, null, 2))}</pre></div>${item.issues.map(issue => `<div class="text-xs mt-4" style="color:var(--warning)">· ${escapeHtml(issue)}</div>`).join('')}</div></div>`).join('') : '<div class="text-sm text-muted">No structurally valid JWT was found in submitted headers/cookies or the primary response.</div>'}</div>`;
}

// =========================================================================
// ACTIVE RECON MODE
// =========================================================================

function renderActiveMode(): string {
  return `${renderActiveForm()}
    <div class="text-xs ${statusIsError ? '' : 'text-muted'} mb-4" ${statusIsError ? 'style="color:var(--error)"' : ''}>${escapeHtml(statusMessage)}</div>
    ${reconResult ? renderReconResults(reconResult) : renderEmptyState('No active recon data', 'Configure your target and scan parameters, then click Start Recon. Active testing requires separate confirmation.')}`;
}

function renderActiveForm(): string {
  return `<div class="panel mb-4"><div class="panel-header"><span>Active Recon Configuration</span><span class="badge badge-warning" style="margin-left:8px">Active testing</span></div><div class="panel-body">
    <div class="flex gap-4 mb-4" style="align-items:flex-end;flex-wrap:wrap">
      <div style="flex:3;min-width:300px"><label class="text-xs text-muted" for="recon-url">Target URL</label><input class="input mono mt-4" id="recon-url" type="url" placeholder="http://target:8080/" value="${escapeHtml(reconResult?.target_url || '')}"></div>
      <div style="flex:1;min-width:150px"><label class="text-xs text-muted" for="recon-scope">Scope</label><select class="select mt-4" id="recon-scope"><option value="ctf">CTF challenge</option><option value="lab">Lab</option><option value="owned">User-owned</option></select></div>
    </div>
    <div class="flex gap-4 mb-4" style="flex-wrap:wrap">
      <div style="flex:1;min-width:280px"><label class="text-xs text-muted" for="recon-auth">Authorization header (optional)</label><input class="input mono mt-4" id="recon-auth" autocomplete="off" placeholder="Bearer … or Basic …"></div>
      <div style="flex:1;min-width:280px"><label class="text-xs text-muted" for="recon-cookies">Request cookies (optional)</label><input class="input mono mt-4" id="recon-cookies" autocomplete="off" placeholder="session=value; role=user"></div>
    </div>

    <div class="recon-modules-grid mb-4">
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" id="recon-crawl" checked><span class="recon-module-name">🕷️ Spider / Crawl</span></label>
        <div class="recon-module-opts">
          <label class="text-xs text-muted">Depth <input class="input input-sm" id="recon-crawl-depth" type="number" value="3" min="1" max="10" style="width:60px"></label>
          <label class="text-xs text-muted">Max pages <input class="input input-sm" id="recon-crawl-pages" type="number" value="50" min="1" max="500" style="width:70px"></label>
        </div>
      </div>
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" id="recon-dirbust" checked><span class="recon-module-name">📂 Dir Buster</span></label>
        <div class="recon-module-opts">
          <label class="text-xs text-muted">Wordlist <select class="select select-sm" id="recon-wordlist"><option value="small">Small (~100)</option><option value="common">Common (~250)</option><option value="medium">Medium (~250+)</option></select></label>
          <label class="text-xs text-muted">Concurrency <input class="input input-sm" id="recon-concurrency" type="number" value="10" min="1" max="50" style="width:60px"></label>
          <label class="text-xs text-muted">Rate/s <input class="input input-sm" id="recon-rate" type="number" value="10" min="1" max="100" style="width:60px"></label>
        </div>
      </div>
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" id="recon-fuzz" checked><span class="recon-module-name">🔍 Param Fuzzer</span></label>
        <div class="text-xs text-muted" style="padding:4px 0">Tests discovered parameters with unique canaries</div>
      </div>
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" id="recon-browser" checked><span class="recon-module-name">🌐 Browser Engine</span></label>
        <div class="text-xs text-muted" style="padding:4px 0">Playwright Chromium — full JS, DOM, console, storage</div>
      </div>
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" id="recon-xss" checked><span class="recon-module-name">⚡ XSS Scanner</span></label>
        <div class="text-xs text-muted" style="padding:4px 0">Reflected + DOM-based XSS detection via canary injection</div>
      </div>
      <div class="recon-module-card">
        <label class="recon-module-toggle"><input type="checkbox" checked disabled><span class="recon-module-name">🏴 Flag Detector</span></label>
        <div class="text-xs text-muted" style="padding:4px 0">Always active — scans all evidence for flag patterns</div>
      </div>
    </div>

    <div class="flex gap-4 mb-4" style="flex-wrap:wrap">
      <div style="flex:1;min-width:320px"><label class="text-xs text-muted" for="recon-flags">Flag patterns (regex, one per line)</label><textarea class="input mono mt-4" id="recon-flags" rows="3" style="resize:vertical;font-size:11px">CTF\\{[^}]+\\}\nFLAG\\{[^}]+\\}\nflag\\{[^}]+\\}\nTHM\\{[^}]+\\}\nDICT\\{[^}]+\\}\nH4G\\{[^}]+\\}</textarea></div>
      <div style="flex:1;min-width:320px"><label class="text-xs text-muted" for="recon-extensions">Dir bust extensions (comma separated)</label><input class="input mono mt-4" id="recon-extensions" value=".php,.html,.txt,.bak,.old,.js" placeholder=".php,.html,.txt,.bak"></div>
    </div>

    <div class="recon-confirm-section">
      <label class="text-xs"><input id="recon-authorized" type="checkbox"> I confirm this is an authorized CTF, lab, or system I own</label>
      <label class="text-xs recon-active-confirm"><input id="recon-active-confirm" type="checkbox"> I confirm active testing — this will send crafted requests to the target</label>
    </div>
    <div class="text-xs text-muted mt-4">Active recon sends automated requests to the target. Scope enforcement is applied — only the exact host you specify will be tested. Cloud metadata and link-local destinations are blocked.</div>
  </div></div>`;
}

function renderReconResults(data: ActiveReconResponse): string {
  const crawlCount = data.crawl?.total_pages ?? 0;
  const dirCount = data.dirbust?.total_found ?? 0;
  const fuzzCount = data.param_fuzz?.total_reflected ?? 0;
  const xssCount = data.xss?.findings?.length ?? 0;
  const flagCount = data.flags?.matches?.length ?? 0;

  const tabs: Array<[ReconTab, string, number | null]> = [
    ['recon-overview', 'Overview', null],
    ['crawl-map', 'Crawl Map', crawlCount],
    ['dir-scan', 'Dir Scan', dirCount],
    ['param-analysis', 'Parameters', fuzzCount],
    ['xss-findings', 'XSS', xssCount],
    ['browser-capture', 'Browser', data.browser ? 1 : 0],
    ['flags', 'Flags', flagCount],
  ];

  return `<div class="web-target"><span class="badge badge-dot ${data.status === 'completed' ? 'badge-success' : 'badge-error'}">${escapeHtml(data.status)}</span><span class="mono text-sm">${escapeHtml(data.target_url)}</span><div class="topbar-spacer"></div><span class="text-xs text-muted">${data.elapsed_ms} ms · ${escapeHtml(data.target_scope)} · ${escapeHtml(data.scan_id.slice(0, 8))}</span></div>
    ${data.warnings.length ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${data.warnings.map(w => `<div>· ${escapeHtml(w)}</div>`).join('')}</div></div>` : ''}
    <div class="tab-bar" id="recon-tabs">${tabs.map(([id, label, count]) => `<div class="tab-item ${reconTab === id ? 'active' : ''}" data-rtab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}</div>
    <div id="recon-content">${renderReconTab(data)}</div>`;
}

function renderReconTab(data: ActiveReconResponse): string {
  if (reconTab === 'crawl-map') return renderCrawlMap(data);
  if (reconTab === 'dir-scan') return renderDirScan(data);
  if (reconTab === 'param-analysis') return renderParamAnalysis(data);
  if (reconTab === 'xss-findings') return renderXssFindings(data);
  if (reconTab === 'browser-capture') return renderBrowserCapture(data);
  if (reconTab === 'flags') return renderFlags(data);
  return renderReconOverview(data);
}

function renderReconOverview(data: ActiveReconResponse): string {
  const metrics = [
    { label: 'Pages Crawled', value: data.crawl?.total_pages ?? '—', accent: '' },
    { label: 'Paths Found', value: data.dirbust?.total_found ?? '—', accent: '' },
    { label: 'Params Reflected', value: data.param_fuzz?.total_reflected ?? '—', accent: data.param_fuzz?.total_reflected ? 'dashboard-metric-warning' : '' },
    { label: 'XSS Findings', value: data.xss?.findings?.length ?? '—', accent: (data.xss?.findings?.length ?? 0) > 0 ? 'dashboard-metric-warning' : '' },
    { label: 'Flags Found', value: data.flags?.matches?.length ?? '—', accent: (data.flags?.matches?.length ?? 0) > 0 ? 'dashboard-metric-accent' : '' },
    { label: 'Total Time', value: `${(data.elapsed_ms / 1000).toFixed(1)}s`, accent: '' },
  ];

  return `<div class="recon-metrics-grid mb-8">${metrics.map(m => `<div class="dashboard-metric ${m.accent}"><div class="dashboard-metric-icon">${m.label.charAt(0)}</div><div><div class="dashboard-metric-label">${m.label}</div><div class="dashboard-metric-value">${m.value}</div></div></div>`).join('')}</div>

    <div class="network-evidence-grid mb-8">
      <div class="panel"><div class="panel-header">Scan modules</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">Crawl</div><div class="kv-value">${data.crawl ? `${data.crawl.total_pages} pages, depth ${data.crawl.max_depth_reached}, ${data.crawl.total_forms} forms` : 'Disabled'}</div>
        <div class="kv-key">Dir Bust</div><div class="kv-value">${data.dirbust ? `${data.dirbust.total_found} found / ${data.dirbust.total_tested} tested (${data.dirbust.wordlist_used})` : 'Disabled'}</div>
        <div class="kv-key">Param Fuzz</div><div class="kv-value">${data.param_fuzz ? `${data.param_fuzz.total_reflected} reflected / ${data.param_fuzz.total_tested} tested` : 'Disabled'}</div>
        <div class="kv-key">Browser</div><div class="kv-value">${data.browser ? `${data.browser.console_log.length} console, ${data.browser.network_log.length} network, ${data.browser.storage.length} storage` : 'Disabled'}</div>
        <div class="kv-key">XSS</div><div class="kv-value">${data.xss ? `${data.xss.findings.length} findings (${data.xss.total_reflected} reflected, ${data.xss.total_dom} DOM)` : 'Disabled'}</div>
        <div class="kv-key">Flags</div><div class="kv-value">${data.flags ? `${data.flags.matches.length} matches across ${data.flags.patterns_used.length} patterns` : '—'}</div>
      </div></div></div>
      <div class="panel"><div class="panel-header">Timing</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">Crawl</div><div class="kv-value">${data.crawl ? `${(data.crawl.elapsed_ms / 1000).toFixed(1)}s` : '—'}</div>
        <div class="kv-key">Dir Bust</div><div class="kv-value">${data.dirbust ? `${(data.dirbust.elapsed_ms / 1000).toFixed(1)}s` : '—'}</div>
        <div class="kv-key">Param Fuzz</div><div class="kv-value">${data.param_fuzz ? `${(data.param_fuzz.elapsed_ms / 1000).toFixed(1)}s` : '—'}</div>
        <div class="kv-key">Browser</div><div class="kv-value">${data.browser ? `${(data.browser.elapsed_ms / 1000).toFixed(1)}s` : '—'}</div>
        <div class="kv-key">XSS</div><div class="kv-value">${data.xss ? `${(data.xss.elapsed_ms / 1000).toFixed(1)}s` : '—'}</div>
        <div class="kv-key">Total</div><div class="kv-value">${(data.elapsed_ms / 1000).toFixed(1)}s</div>
      </div></div></div>
    </div>`;
}

function renderCrawlMap(data: ActiveReconResponse): string {
  const crawl = data.crawl;
  if (!crawl || !crawl.pages.length) return renderEmptyState('No crawl data', 'Enable the crawl module to discover pages.');

  return `<div class="section"><div class="section-header"><div class="section-title">Crawled pages</div><span class="text-xs text-muted">${crawl.total_pages} pages, max depth ${crawl.max_depth_reached}, ${crawl.total_forms} forms, ${crawl.total_links} links</span></div>
    <table class="data-table"><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Depth</th><th>Params</th><th>Forms</th><th>Links</th><th>Time</th></tr></thead><tbody>
    ${crawl.pages.map(p => `<tr>
      <td class="mono" style="max-width:400px;word-break:break-all">${escapeHtml(p.url)}</td>
      <td><span class="badge ${p.status_code < 400 ? 'badge-success' : p.status_code < 500 ? 'badge-warning' : 'badge-error'}">${p.status_code}</span></td>
      <td class="text-muted" style="max-width:200px">${escapeHtml(p.title || '—')}</td>
      <td>${p.depth}</td>
      <td class="mono text-muted">${p.parameters.length ? escapeHtml(p.parameters.join(', ')) : '—'}</td>
      <td>${p.forms.length || '—'}</td>
      <td>${p.links.length}</td>
      <td class="text-muted">${p.elapsed_ms}ms</td>
    </tr>`).join('')}
    </tbody></table></div>

    ${crawl.pages.some(p => p.forms.length > 0) ? `<div class="section"><div class="section-title mb-4">Discovered forms</div><table class="data-table"><thead><tr><th>Page</th><th>Action</th><th>Method</th><th>Inputs</th></tr></thead><tbody>
    ${crawl.pages.flatMap(p => p.forms.map(f => `<tr>
      <td class="mono" style="max-width:250px;word-break:break-all">${escapeHtml(p.url)}</td>
      <td class="mono">${escapeHtml(f.action || p.url)}</td>
      <td><span class="badge badge-outline">${escapeHtml(f.method)}</span></td>
      <td class="mono text-muted">${f.inputs.map(i => `${escapeHtml(i.name)} (${escapeHtml(i.input_type)})`).join(', ') || '—'}</td>
    </tr>`)).join('')}
    </tbody></table></div>` : ''}`;
}

function renderDirScan(data: ActiveReconResponse): string {
  const dir = data.dirbust;
  if (!dir) return renderEmptyState('No directory scan data', 'Enable the dir buster module to discover hidden paths.');

  return `<div class="section"><div class="section-header"><div class="section-title">Directory & file discovery</div><span class="text-xs text-muted">${dir.total_found} found / ${dir.total_tested} tested · ${dir.wordlist_used} wordlist · extensions: ${dir.extensions_used.join(', ')} · ${(dir.elapsed_ms / 1000).toFixed(1)}s</span></div>
    <table class="data-table"><thead><tr><th>Path</th><th>Status</th><th>Type</th><th>Size</th><th>Redirect</th><th>Time</th></tr></thead><tbody>
    ${dir.entries.length ? dir.entries.map(e => `<tr>
      <td class="mono">${escapeHtml(e.path)}</td>
      <td><span class="badge ${e.status_code < 300 ? 'badge-success' : e.status_code < 400 ? 'badge-info' : e.status_code < 500 ? 'badge-warning' : 'badge-error'}">${e.status_code}</span></td>
      <td class="text-muted">${escapeHtml(e.content_type || '—')}</td>
      <td>${formatBytes(e.size)}</td>
      <td class="mono text-muted" style="max-width:200px;word-break:break-all">${escapeHtml(e.redirect_url || '—')}</td>
      <td class="text-muted">${e.elapsed_ms}ms</td>
    </tr>`).join('') : emptyRow(6, 'No paths matched the status filter.')}
    </tbody></table></div>`;
}

function renderParamAnalysis(data: ActiveReconResponse): string {
  const fuzz = data.param_fuzz;
  if (!fuzz) return renderEmptyState('No parameter analysis data', 'Enable the parameter fuzzer to test discovered parameters.');

  return `<div class="section"><div class="section-header"><div class="section-title">Parameter reflection analysis</div><span class="text-xs text-muted">${fuzz.total_reflected} reflected / ${fuzz.total_tested} tested · ${(fuzz.elapsed_ms / 1000).toFixed(1)}s</span></div>
    <table class="data-table"><thead><tr><th>Parameter</th><th>Reflected</th><th>Context</th><th>Status</th><th>Size</th><th>Similarity</th></tr></thead><tbody>
    ${fuzz.entries.length ? fuzz.entries.map(e => `<tr class="${e.reflected ? 'recon-reflected-row' : ''}">
      <td class="mono">${escapeHtml(e.parameter)}</td>
      <td>${e.reflected ? '<span class="badge badge-warning">Yes</span>' : '<span class="badge badge-outline">No</span>'}</td>
      <td class="text-muted">${escapeHtml(e.reflection_context || '—')}</td>
      <td>${e.response_status}</td>
      <td>${formatBytes(e.response_size)}</td>
      <td class="text-muted">${Math.round(e.baseline_similarity * 100)}%</td>
    </tr>`).join('') : emptyRow(6, 'No parameters were discovered to test.')}
    </tbody></table></div>`;
}

function renderXssFindings(data: ActiveReconResponse): string {
  const xss = data.xss;
  if (!xss) return renderEmptyState('No XSS scan data', 'Enable the XSS scanner to test for cross-site scripting vulnerabilities.');

  return `<div class="section"><div class="section-header"><div class="section-title">XSS findings</div><span class="text-xs text-muted">${xss.findings.length} findings · ${xss.total_reflected} reflected · ${xss.total_dom} DOM · ${xss.parameters_tested} params tested · ${(xss.elapsed_ms / 1000).toFixed(1)}s</span></div>
    ${xss.findings.length ? xss.findings.map(f => `<div class="panel mb-4 recon-xss-panel recon-xss-${f.severity}">
      <div class="panel-header"><span>${severityBadge(f.severity)} <span class="badge badge-outline">${escapeHtml(f.finding_type)}</span></span><span class="mono text-sm">${escapeHtml(f.parameter)}</span></div>
      <div class="panel-body">
        <div class="kv-list mb-4">
          <div class="kv-key">URL</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(f.url)}</div>
          <div class="kv-key">Context</div><div class="kv-value">${escapeHtml(f.injection_context || '—')}</div>
          ${f.dom_sink ? `<div class="kv-key">DOM Sink</div><div class="kv-value mono">${escapeHtml(f.dom_sink)}</div>` : ''}
          <div class="kv-key">Canary</div><div class="kv-value mono">${escapeHtml(f.canary)}</div>
        </div>
        <div class="text-xs text-muted mb-4">Evidence</div>
        <pre class="mono text-xs recon-evidence">${escapeHtml(f.evidence)}</pre>
        <div class="text-xs mt-4" style="color:var(--accent)">💡 ${escapeHtml(f.suggestion)}</div>
      </div>
    </div>`).join('') : '<div class="text-sm text-muted">No XSS vulnerabilities were detected. This does not mean the target is safe — only that canary injection did not trigger in the tested parameters.</div>'}
  </div>`;
}

function renderBrowserCapture(data: ActiveReconResponse): string {
  const browser = data.browser;
  if (!browser) return renderEmptyState('No browser capture data', 'Enable the browser engine module for full JavaScript execution and DOM analysis.');

  return `<div class="section">
    <div class="section-header"><div class="section-title">Browser render capture</div><span class="text-xs text-muted">${browser.elapsed_ms}ms · ${escapeHtml(browser.title || 'Untitled')}</span></div>

    <div class="network-evidence-grid mb-8">
      <div class="panel"><div class="panel-header">Page info</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">Request URL</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(browser.url)}</div>
        <div class="kv-key">Final URL</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(browser.final_url)}</div>
        <div class="kv-key">Title</div><div class="kv-value">${escapeHtml(browser.title || '—')}</div>
        <div class="kv-key">DOM size</div><div class="kv-value">${browser.dom_snapshot ? formatBytes(browser.dom_snapshot.length) : '—'}</div>
      </div></div></div>
      ${browser.errors.length ? `<div class="panel"><div class="panel-header" style="color:var(--error)">Errors</div><div class="panel-body text-xs">${browser.errors.map(e => `<div>· ${escapeHtml(e)}</div>`).join('')}</div></div>` : ''}
    </div>

    ${browser.screenshot_base64 ? `<div class="panel mb-4"><div class="panel-header">Screenshot</div><div class="panel-body" style="padding:0;overflow:hidden;border-radius:0 0 8px 8px"><img src="data:image/png;base64,${browser.screenshot_base64}" alt="Page screenshot" style="width:100%;display:block"></div></div>` : ''}

    <div class="section-title mb-4">Console output (${browser.console_log.length})</div>
    <table class="data-table mb-8"><thead><tr><th>Level</th><th>Message</th></tr></thead><tbody>
    ${browser.console_log.length ? browser.console_log.slice(0, 100).map(c => `<tr><td><span class="badge ${c.level === 'error' ? 'badge-error' : c.level === 'warn' ? 'badge-warning' : 'badge-outline'}">${escapeHtml(c.level)}</span></td><td class="mono text-xs" style="word-break:break-all">${escapeHtml(c.text)}</td></tr>`).join('') : emptyRow(2, 'No console output captured.')}
    </tbody></table>

    <div class="section-title mb-4">Network requests (${browser.network_log.length})</div>
    <table class="data-table mb-8"><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Time</th></tr></thead><tbody>
    ${browser.network_log.length ? browser.network_log.slice(0, 100).map(n => `<tr><td><span class="badge badge-outline">${escapeHtml(n.method)}</span></td><td class="mono text-xs" style="max-width:500px;word-break:break-all">${escapeHtml(n.url)}</td><td>${n.status_code ?? '—'}</td><td class="text-muted">${n.elapsed_ms}ms</td></tr>`).join('') : emptyRow(4, 'No network requests captured.')}
    </tbody></table>

    <div class="section-title mb-4">Cookies & storage (${browser.storage.length})</div>
    <table class="data-table"><thead><tr><th>Type</th><th>Key</th><th>Value</th></tr></thead><tbody>
    ${browser.storage.length ? browser.storage.map(s => `<tr><td><span class="badge badge-info">${escapeHtml(s.storage_type)}</span></td><td class="mono">${escapeHtml(s.key)}</td><td class="mono text-muted" style="max-width:300px;word-break:break-all">${escapeHtml(s.value)}</td></tr>`).join('') : emptyRow(3, 'No cookies or storage entries captured.')}
    </tbody></table>
  </div>`;
}

function renderFlags(data: ActiveReconResponse): string {
  const flags = data.flags;
  if (!flags || !flags.matches.length) {
    return `<div class="section">
      <div class="section-title mb-4">Flag detection</div>
      <div class="text-sm text-muted">No flag patterns were matched across the collected evidence. Patterns tested: ${flags?.patterns_used.map(p => `<code>${escapeHtml(p)}</code>`).join(', ') || '—'}</div>
    </div>`;
  }

  return `<div class="section"><div class="section-header"><div class="section-title">🏴 Flags detected</div><span class="text-xs text-muted">${flags.matches.length} matches</span></div>
    ${flags.matches.map(f => `<div class="panel mb-4 recon-flag-panel">
      <div class="panel-header"><span class="recon-flag-value">${escapeHtml(f.value)}</span></div>
      <div class="panel-body">
        <div class="kv-list">
          <div class="kv-key">Source</div><div class="kv-value">${escapeHtml(f.source)}</div>
          <div class="kv-key">URL</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(f.url || '—')}</div>
          <div class="kv-key">Pattern</div><div class="kv-value mono">${escapeHtml(f.pattern)}</div>
        </div>
        ${f.context ? `<div class="text-xs text-muted mt-4">Context</div><pre class="mono text-xs recon-evidence">${escapeHtml(f.context)}</pre>` : ''}
      </div>
    </div>`).join('')}
  </div>`;
}

// =========================================================================
// Event handling
// =========================================================================

function bindEvents(): void {
  document.getElementById('web-run')?.addEventListener('click', () => {
    if (webMode === 'passive') void runPassiveAnalysis();
    else void runActiveRecon();
  });
  document.getElementById('web-export')?.addEventListener('click', exportResult);

  // Mode toggle
  document.querySelectorAll<HTMLElement>('.web-mode-btn').forEach(btn => btn.addEventListener('click', () => {
    const mode = btn.dataset.mode as WebMode;
    if (mode && mode !== webMode) {
      webMode = mode;
      analyzing = false;
      statusMessage = mode === 'passive' ? 'Enter an authorized CTF, lab, or owned target.' : 'Configure target and scan modules, then start recon.';
      statusIsError = false;
      renderShell();
    }
  }));

  // Passive tabs
  document.querySelectorAll<HTMLElement>('#web-tabs .tab-item').forEach(tab => tab.addEventListener('click', () => {
    activeTab = (tab.dataset.tab as WebTab | undefined) || 'overview';
    renderShell();
  }));

  // Recon tabs
  document.querySelectorAll<HTMLElement>('#recon-tabs .tab-item').forEach(tab => tab.addEventListener('click', () => {
    reconTab = (tab.dataset.rtab as ReconTab | undefined) || 'recon-overview';
    renderShell();
  }));
}

function parseCookies(value: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  value.split(';').map(item => item.trim()).filter(Boolean).forEach(item => {
    const separator = item.indexOf('=');
    if (separator > 0) cookies[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  });
  return cookies;
}

async function runPassiveAnalysis(): Promise<void> {
  if (analyzing) return;
  const url = (document.getElementById('web-url') as HTMLInputElement | null)?.value.trim() || '';
  const authorized = (document.getElementById('web-authorized') as HTMLInputElement | null)?.checked || false;
  if (!url || !authorized) {
    statusIsError = true;
    statusMessage = !url ? 'Enter an HTTP or HTTPS URL.' : 'Confirm that the target is explicitly authorized.';
    renderShell();
    return;
  }
  const controller = new AbortController();
  activeRequest?.abort();
  activeRequest = controller;
  const auth = (document.getElementById('web-auth') as HTMLInputElement | null)?.value.trim() || '';
  const cookies = parseCookies((document.getElementById('web-cookies') as HTMLInputElement | null)?.value || '');
  const scope = ((document.getElementById('web-scope') as HTMLSelectElement | null)?.value || 'ctf') as TargetScope;
  const method = ((document.getElementById('web-method') as HTMLSelectElement | null)?.value || 'GET') as 'GET' | 'HEAD';
  const fetchJs = (document.getElementById('web-js') as HTMLInputElement | null)?.checked ?? true;
  const compare = (document.getElementById('web-compare') as HTMLInputElement | null)?.checked ?? false;
  analyzing = true;
  statusIsError = false;
  statusMessage = 'Fetching bounded target evidence…';
  renderShell();
  try {
    result = await analyzeWebTarget({ url, target_scope: scope, authorization_confirmed: true, method, headers: auth ? { Authorization: auth } : {}, cookies, fetch_robots: true, fetch_sitemap: true, fetch_javascript: fetchJs, compare_without_auth: compare }, controller.signal);
    activeTab = 'overview';
    statusMessage = `Analysis ${result.analysis_id}`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusIsError = true;
    statusMessage = error instanceof ApiError && error.code === 'NETWORK_ERROR' ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.' : error instanceof Error ? error.message : 'Web analysis failed.';
  } finally {
    if (activeRequest === controller) {
      activeRequest = null;
      analyzing = false;
      if (document.getElementById('web-page')) renderShell();
    }
  }
}

async function runActiveRecon(): Promise<void> {
  if (analyzing) return;
  const url = (document.getElementById('recon-url') as HTMLInputElement | null)?.value.trim() || '';
  const authorized = (document.getElementById('recon-authorized') as HTMLInputElement | null)?.checked || false;
  const activeConfirm = (document.getElementById('recon-active-confirm') as HTMLInputElement | null)?.checked || false;

  if (!url) { statusIsError = true; statusMessage = 'Enter an HTTP or HTTPS URL.'; renderShell(); return; }
  if (!authorized) { statusIsError = true; statusMessage = 'Confirm that the target is explicitly authorized.'; renderShell(); return; }
  if (!activeConfirm) { statusIsError = true; statusMessage = 'Confirm active testing — this sends crafted requests to the target.'; renderShell(); return; }

  const controller = new AbortController();
  activeRequest?.abort();
  activeRequest = controller;

  const scope = ((document.getElementById('recon-scope') as HTMLSelectElement | null)?.value || 'ctf') as TargetScope;
  const auth = (document.getElementById('recon-auth') as HTMLInputElement | null)?.value.trim() || '';
  const cookies = parseCookies((document.getElementById('recon-cookies') as HTMLInputElement | null)?.value || '');

  const enableCrawl = (document.getElementById('recon-crawl') as HTMLInputElement | null)?.checked ?? true;
  const crawlDepth = parseInt((document.getElementById('recon-crawl-depth') as HTMLInputElement | null)?.value || '3', 10);
  const crawlPages = parseInt((document.getElementById('recon-crawl-pages') as HTMLInputElement | null)?.value || '50', 10);
  const enableDirbust = (document.getElementById('recon-dirbust') as HTMLInputElement | null)?.checked ?? true;
  const wordlist = ((document.getElementById('recon-wordlist') as HTMLSelectElement | null)?.value || 'small') as 'common' | 'medium' | 'small';
  const concurrency = parseInt((document.getElementById('recon-concurrency') as HTMLInputElement | null)?.value || '10', 10);
  const rate = parseFloat((document.getElementById('recon-rate') as HTMLInputElement | null)?.value || '10');
  const enableFuzz = (document.getElementById('recon-fuzz') as HTMLInputElement | null)?.checked ?? true;
  const enableBrowser = (document.getElementById('recon-browser') as HTMLInputElement | null)?.checked ?? true;
  const enableXss = (document.getElementById('recon-xss') as HTMLInputElement | null)?.checked ?? true;

  const flagText = (document.getElementById('recon-flags') as HTMLTextAreaElement | null)?.value || '';
  const flagPatterns = flagText.split('\n').map(l => l.trim()).filter(Boolean);
  const extText = (document.getElementById('recon-extensions') as HTMLInputElement | null)?.value || '';
  const extensions = extText.split(',').map(e => e.trim()).filter(Boolean);

  const input: ActiveReconInput = {
    url,
    target_scope: scope,
    authorization_confirmed: true,
    active_testing_confirmed: true,
    enable_crawl: enableCrawl,
    crawl_depth: crawlDepth,
    crawl_max_pages: crawlPages,
    enable_dirbust: enableDirbust,
    dirbust_wordlist: wordlist,
    dirbust_extensions: extensions,
    dirbust_concurrency: concurrency,
    dirbust_status_filter: [200, 201, 204, 301, 302, 307, 401, 403],
    enable_param_fuzz: enableFuzz,
    enable_browser: enableBrowser,
    browser_timeout_ms: 15000,
    enable_xss: enableXss,
    flag_patterns: flagPatterns,
    headers: auth ? { Authorization: auth } : {},
    cookies,
    timeout_ms: 8000,
    rate_limit_rps: rate,
  };

  analyzing = true;
  statusIsError = false;
  statusMessage = 'Running active recon — crawling, busting, fuzzing, scanning…';
  renderShell();

  try {
    reconResult = await startActiveRecon(input, controller.signal);
    reconTab = 'recon-overview';
    statusMessage = `Scan ${reconResult.scan_id.slice(0, 8)} completed in ${(reconResult.elapsed_ms / 1000).toFixed(1)}s`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusIsError = true;
    statusMessage = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Active recon failed.';
  } finally {
    if (activeRequest === controller) {
      activeRequest = null;
      analyzing = false;
      if (document.getElementById('web-page')) renderShell();
    }
  }
}

function exportResult(): void {
  const data = webMode === 'active' ? reconResult : result;
  if (!data) return;
  const id = 'scan_id' in data ? data.scan_id : (data as WebAnalysisResponse).analysis_id;
  const prefix = webMode === 'active' ? 'active-recon' : 'web-analysis';
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${prefix}-${id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
