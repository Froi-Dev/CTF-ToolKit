import { renderSidebar } from './sidebar.js';
import { renderTopbar } from './topbar.js';
import { renderDashboard } from './modules/dashboard.js';
import { renderCases } from './modules/cases.js';
import { renderAutoTriage } from './modules/autotriage.js';
import { renderWeb } from './modules/web.js';
import { renderCrypto } from './modules/crypto.js';
import { renderForensics } from './modules/forensics.js';
import { renderNetwork } from './modules/network.js';
import { renderOsint } from './modules/osint.js';
import { renderStego } from './modules/stego.js';
import { renderReverse } from './modules/reverse.js';
import { renderBinary } from './modules/binary.js';
import { renderMalware } from './modules/malware.js';
import { renderHashes } from './modules/hashes.js';
import { renderWordlists } from './modules/wordlists.js';
import { renderReports } from './modules/reports.js';
import { renderSettings } from './modules/settings.js';

const routes = {
  dashboard: renderDashboard,
  cases: renderCases,
  autotriage: renderAutoTriage,
  web: renderWeb,
  crypto: renderCrypto,
  forensics: renderForensics,
  network: renderNetwork,
  osint: renderOsint,
  stego: renderStego,
  reverse: renderReverse,
  binary: renderBinary,
  malware: renderMalware,
  hashes: renderHashes,
  wordlists: renderWordlists,
  reports: renderReports,
  settings: renderSettings,
};

function getModule() {
  const hash = window.location.hash.replace('#', '') || 'dashboard';
  return hash;
}

function render() {
  const mod = getModule();
  renderSidebar(mod);
  renderTopbar(mod);
  const renderFn = routes[mod] || renderDashboard;
  renderFn();
  // Scroll main to top
  document.getElementById('main').scrollTop = 0;
}

// Route on hash change
window.addEventListener('hashchange', render);

// Initial render
render();
