import { renderSidebar } from './sidebar.ts';
import { renderTopbar } from './topbar.ts';
import { renderDashboard } from './modules/dashboard.ts';
import { renderAutoTriage } from './modules/autotriage.ts';
import { renderWeb } from './modules/web.ts';
import { renderCrypto } from './modules/crypto.ts';
import { renderForensics } from './modules/forensics.ts';
import { renderNetwork } from './modules/network.ts';
import { renderOsint } from './modules/osint.ts';
import { renderStego } from './modules/stego.ts';
import { renderReverse } from './modules/reverse.ts';
import { renderBinary } from './modules/binary.ts';
import { renderMalware } from './modules/malware.ts';
import { renderHashes } from './modules/hashes.ts';
import { renderWordlists } from './modules/wordlists.ts';
import { renderReports } from './modules/reports.ts';
import { renderSettings } from './modules/settings.ts';
import { resolveNavigation } from './navigation.ts';

type RouteRenderer = (view?: string) => void;

const routes: Record<string, RouteRenderer> = {
  dashboard: renderDashboard,
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

function render(): void {
  const route = resolveNavigation(window.location.hash);
  renderSidebar(route.path);
  renderTopbar(route);
  const renderFn = routes[route.child.renderer] || renderDashboard;
  renderFn(route.child.view);

  const main = document.getElementById('main');
  if (main) main.scrollTop = 0;
}

window.addEventListener('hashchange', render);
render();
