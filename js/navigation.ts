export interface NavigationChild {
  label: string;
  route: string;
  renderer: string;
  view: string;
}

export interface NavigationItem {
  id: string;
  label: string;
  icon: string;
  children: NavigationChild[];
}

export interface NavigationSection {
  label: string;
  items: NavigationItem[];
}

export interface ResolvedNavigation {
  path: string;
  parent: NavigationItem;
  child: NavigationChild;
}

const child = (parent: string, route: string, label: string, renderer = parent, view = route): NavigationChild => ({
  label,
  route: `${parent}/${route}`,
  renderer,
  view,
});

export const navigationSections: NavigationSection[] = [
  {
    label: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', children: [
        child('dashboard', 'findings', 'Findings'),
        child('dashboard', 'artifacts', 'Evidence Files'),
        child('dashboard', 'evidence', 'Evidence Graph'),
      ] },
      { id: 'autotriage', label: 'Auto Triage', icon: 'triage', children: [
        child('autotriage', 'new', 'New Analysis'),
        child('autotriage', 'queue', 'Queue & Progress'),
        child('autotriage', 'actions', 'Triage Actions'),
      ] },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { id: 'web', label: 'Web', icon: 'web', children: [
        child('web', 'scanner', 'Web Recon Scanner'),
      ] },
      { id: 'network', label: 'Network / PCAP', icon: 'network', children: [
        child('network', 'analyzer', 'Network Analyzer'),
      ] },
      { id: 'crypto', label: 'Cryptography', icon: 'crypto', children: [
        child('crypto', 'decoder', 'Decoder'),
        child('crypto', 'decryptor', 'Decryptor'),
      ] },
      { id: 'forensics', label: 'Forensics', icon: 'forensics', children: [
        child('forensics', 'files', 'File / Archive Analysis'),
        child('forensics', 'image-steganography', 'Image / Steganography', 'stego', 'overview'),
        child('forensics', 'audio', 'Audio Analyzer', 'audio', 'audio'),
        child('forensics', 'disk-partition', 'Disk / Partition', 'disk', 'overview'),
      ] },
      { id: 'osint', label: 'OSINT', icon: 'osint', children: [
        child('osint', 'website', 'Website OSINT'),
        child('osint', 'google-dorks', 'Google Dorks'),
        child('osint', 'username', 'User OSINT'),
      ] },
      { id: 'reverse', label: 'Reverse Engineering', icon: 'reverse', children: [
        child('reverse', 'overview', 'Overview'),
        child('reverse', 'sections', 'Sections / Imports'),
        child('reverse', 'strings', 'Strings'),
        child('reverse', 'disasm', 'Disassembly'),
      ] },
    ],
  },
  {
    label: 'Tools',
    items: [
      { id: 'hashes', label: 'Hashes / Passwords', icon: 'hashes', children: [
        child('hashes', 'identify', 'Identify Hash'),
        child('hashes', 'database', 'Hash Database'),
        child('hashes', 'cracking', 'Cracking Configuration'),
      ] },
      { id: 'wordlists', label: 'Wordlists', icon: 'wordlists', children: [
        child('wordlists', 'library', 'Available Lists'),
        child('wordlists', 'generator', 'Custom Generator'),
      ] },
    ],
  },
];

const items = navigationSections.flatMap(section => section.items);
const routes = new Map(items.flatMap(item => item.children.map(itemChild => [itemChild.route, { parent: item, child: itemChild }] as const)));

const legacyRoutes: Record<string, string> = {
  dashboard: 'dashboard/findings', autotriage: 'autotriage/new',
  web: 'web/scanner', 'web/passive': 'web/scanner', 'web/active': 'web/scanner',
  crypto: 'crypto/decoder', forensics: 'forensics/files',
  stego: 'forensics/image-steganography', network: 'network/analyzer',
  'network/overview': 'network/analyzer', 'network/protocols': 'network/analyzer',
  'network/streams': 'network/analyzer', osint: 'osint/website',
  'osint/investigation': 'osint/website', 'osint/infrastructure': 'osint/website',
  'osint/identities': 'osint/username', 'osint/search': 'osint/google-dorks',
  reverse: 'reverse/overview', hashes: 'hashes/identify', wordlists: 'wordlists/library',
};

export function resolveNavigation(rawPath: string): ResolvedNavigation {
  const requested = decodeURIComponent(rawPath.replace(/^#/, '').replace(/^\/+|\/+$/g, ''));
  const path = legacyRoutes[requested] || requested || legacyRoutes.dashboard;
  const match = routes.get(path) || routes.get(legacyRoutes.dashboard);
  if (!match) throw new Error('Dashboard navigation is not configured.');
  return { path, parent: match.parent, child: match.child };
}
