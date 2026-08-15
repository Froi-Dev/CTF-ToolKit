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
      { id: 'cases', label: 'Cases', icon: 'cases', children: [
        child('cases', 'all', 'All Cases'),
        child('cases', 'workspace', 'Case Workspace'),
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
        child('web', 'passive', 'Passive Analysis'),
        child('web', 'active', 'Active Recon'),
      ] },
      { id: 'crypto', label: 'Cryptography', icon: 'crypto', children: [
        child('crypto', 'decoder', 'Decode Workbench'),
        child('crypto', 'pipeline', 'Transform Pipeline'),
        child('crypto', 'flags', 'Flag Candidates'),
      ] },
      { id: 'forensics', label: 'Forensics', icon: 'forensics', children: [
        child('forensics', 'files', 'File / Archive Analysis'),
        child('forensics', 'image-steganography', 'Image / Steganography', 'stego', 'overview'),
        child('forensics', 'disk-partition', 'Disk / Partition'),
        child('forensics', 'other', 'Other Forensics'),
      ] },
      { id: 'network', label: 'Network / PCAP', icon: 'network', children: [
        child('network', 'overview', 'Capture Overview'),
        child('network', 'protocols', 'Packets / Protocols'),
        child('network', 'streams', 'Streams / Evidence'),
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
      { id: 'binary', label: 'Binary / Pwn', icon: 'binary', children: [
        child('binary', 'protections', 'Protections'),
        child('binary', 'vulnerabilities', 'Vulnerabilities'),
        child('binary', 'gadgets', 'ROP Gadgets'),
        child('binary', 'exploit', 'Exploit Template'),
      ] },
      { id: 'malware', label: 'Malware Analysis', icon: 'malware', children: [
        child('malware', 'overview', 'Sample Overview'),
        child('malware', 'indicators', 'Indicators'),
        child('malware', 'behavior', 'Behavior'),
        child('malware', 'static', 'Static Analysis'),
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
      { id: 'reports', label: 'Reports', icon: 'reports', children: [
        child('reports', 'generated', 'Generated Reports'),
        child('reports', 'create', 'Create Report'),
      ] },
      { id: 'settings', label: 'Settings', icon: 'settings', children: [
        child('settings', 'general', 'General'),
        child('settings', 'analyzers', 'Analyzers'),
        child('settings', 'integrations', 'Integrations'),
        child('settings', 'backend', 'Backend'),
        child('settings', 'appearance', 'Appearance'),
      ] },
    ],
  },
];

const items = navigationSections.flatMap(section => section.items);
const routes = new Map(items.flatMap(item => item.children.map(itemChild => [itemChild.route, { parent: item, child: itemChild }] as const)));

const legacyRoutes: Record<string, string> = {
  dashboard: 'dashboard/findings', cases: 'cases/all', autotriage: 'autotriage/new',
  web: 'web/passive', crypto: 'crypto/decoder', forensics: 'forensics/files',
  stego: 'forensics/image-steganography', network: 'network/overview', osint: 'osint/website',
  'osint/investigation': 'osint/website', 'osint/infrastructure': 'osint/website',
  'osint/identities': 'osint/username', 'osint/search': 'osint/google-dorks',
  reverse: 'reverse/overview', binary: 'binary/protections', malware: 'malware/overview',
  hashes: 'hashes/identify', wordlists: 'wordlists/library', reports: 'reports/generated',
  settings: 'settings/general',
};

export function resolveNavigation(rawPath: string): ResolvedNavigation {
  const requested = decodeURIComponent(rawPath.replace(/^#/, '').replace(/^\/+|\/+$/g, ''));
  const path = legacyRoutes[requested] || requested || legacyRoutes.dashboard;
  const match = routes.get(path) || routes.get(legacyRoutes.dashboard);
  if (!match) throw new Error('Dashboard navigation is not configured.');
  return { path, parent: match.parent, child: match.child };
}
