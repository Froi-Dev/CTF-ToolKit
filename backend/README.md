# CTFKit backend

The backend currently provides eight bounded analysis slices:

- type-aware auto triage at `POST /api/v1/auto-triage/analyze`, combining the
  baseline file analyzer with applicable image or PCAP specialists;
- recursive cryptography decoding at `POST /api/v1/crypto/decode`, deterministic
  recipes with per-step artifact inspection at `POST /api/v1/crypto/recipes/run`,
  and RSA material analysis/direct decryption at
  `POST /api/v1/crypto/decrypt/analyze` and `POST /api/v1/crypto/decrypt/rsa`.
  OpenSSL `enc` payload recognition and bounded native CBC decryption are available
  at `POST /api/v1/crypto/decrypt/openssl/analyze` and
  `POST /api/v1/crypto/decrypt/openssl`, including legacy `EVP_BytesToKey`
  (MD5/SHA-256), explicit PBKDF2, DES/3DES, and AES candidates;
- static file/forensics triage at `POST /api/v1/forensics/triage` using a
  multipart `file` field.
- offline PCAP/PCAPNG analysis at `POST /api/v1/network/analyze` using a
  multipart `file` field and an installed TShark executable.
- PNG/JPEG steganography analysis at `POST /api/v1/stego/analyze` using a
  multipart `file` field.
- authorized passive Web analysis at `POST /api/v1/web/analyze` using a JSON
  target and request configuration.
- passive public-data OSINT at `POST /api/v1/osint/investigate` for domains,
  public IP addresses, usernames, and public HTTP(S) URLs.
- static reverse-engineering analysis at `POST /api/v1/reversing/analyze` for
  executables, bytecode, scripts, and unknown challenge artifacts.

Reverse-engineering analysis never executes uploads. It identifies common
native and managed formats, parses ELF and PE headers, sections, protections,
symbols and imports, prioritizes ASCII/Unicode strings, records candidate-only
flag matches, and derives validation and debugger leads from observed evidence.
Bounded native disassembly is enabled when GNU `objdump` is on `PATH` or
`CTFKIT_OBJDUMP_PATH` points to it; all other static results remain available
when that optional tool is missing.

Forensics triage derives magic-byte type and MIME, MD5/SHA-1/SHA-256, format
metadata, printable strings, Shannon entropy, signature offsets, extension
mismatches, embedded-file candidates, archive members, flag candidates, and
extracted child-artifact provenance from the uploaded bytes. ZIP, TAR, and
Gzip extraction uses temporary analysis storage and rejects traversal, links,
collisions, encryption, excessive member counts, excessive expanded sizes,
and suspicious compression ratios. Temporary extracts are hashed and
described in the response, then removed; they are not evidence persistence.

Auto triage always runs the static file checks above. It selects PNG/JPEG
structure, bit-plane, and LSB inspection or PCAP/PCAPNG protocol analysis from
detected magic bytes rather than the filename extension. Its response records
completed, skipped, unavailable, and failed analyzer states, so a missing
TShark installation does not discard the baseline result.

```powershell
cd backend
py -3.12 -m pip install -e ".[test]"
py -3.12 -m uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000/api/v1`, with interactive
documentation at `http://127.0.0.1:8000/docs`.

This initial service has no authentication or tenancy boundary and should stay
bound to localhost until those platform foundations are implemented.

Network analysis delegates decoding and reassembly to TShark rather than
reimplementing Wireshark. It returns bounded packet metadata, protocol
hierarchies, bidirectional conversations, DNS/HTTP/FTP activity, TCP stream
discovery and reconstruction, exported HTTP/FTP objects, plaintext credential
candidates, interesting ports, flag candidates, and an evidence-time timeline.
Install Wireshark/TShark. On Windows, the backend discovers TShark from `PATH`
or the standard `Program Files\Wireshark\tshark.exe` installation. A custom
location can be supplied with `CTFKIT_TSHARK_PATH`; on other platforms, place
`tshark` on `PATH` or use that override. If it cannot be resolved, the network
endpoint returns a structured `TOOL_NOT_AVAILABLE` response. Captures are
processed offline with name resolution disabled, and temporary captures and
exported objects are removed after the response is built.

Steganography analysis uses Pillow for safe image decoding and local parsers for
PNG chunks and JPEG segments. It reports image metadata, PNG CRC validation,
JPEG structure, trailing bytes, embedded signatures, channel statistics,
bit-plane balance, one-bit LSB streams, entropy, signature carving provenance,
and flag candidates. Uploaded images are limited by file size and decoded pixel
count; carved artifacts are temporary analysis copies and are removed after the
response is built.

Web analysis requires `authorization_confirmed: true` and a `target_scope` of
`ctf`, `lab`, or `owned`. It performs bounded GET/HEAD requests, follows a small
validated redirect chain, and can fetch same-origin robots.txt, sitemap.xml,
JavaScript, and declared source maps. Results include request/response headers,
cookies, HTML comments, endpoints, parameters, technology evidence,
authentication observations, passive Base64/JWT cookie decoding, cookie-name
and security-attribute leads, and an optional comparison with submitted
authentication state removed. Operators can reuse a raw Cookie header, bearer
token, or custom authentication header on same-origin requests. Supplying an
`authenticated_url` validates that session before crawling and stops with
`AUTH_SESSION_INVALID` on a 401/403 or redirect to a login route. Link-local and cloud
metadata destinations are blocked; private and loopback targets remain available
for local labs. No login form, other form, credential guessing, or exploit traffic
is submitted.

OSINT investigations use modular, failure-isolated providers for Cloudflare
DNS-over-HTTPS, referral-based WHOIS, RDAP.org bootstrap lookups, crt.sh
Certificate Transparency observations, RIPEstat routing metadata, reverse DNS,
and exact public-profile checks on GitHub, GitLab, Reddit, and Hacker News. URL
targets can return bounded HTML title, meta, Open Graph, canonical, JSON-LD, and
link metadata after public-address validation. Results include provider status,
source provenance, generated entity relationships, and safe Google dork links.
No provider failure is replaced with fabricated evidence.

Live Google results are optional and use the official Programmable Search JSON
API. Existing API customers can set `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID`,
then send `include_search_results: true`. Without both values the endpoint still
returns generated queries and marks the live provider unavailable. The Google
API is closed to new customers and scheduled for discontinuation in 2027, so
the integration stays replaceable.

RAR and 7-Zip content is identified but not expanded because this slice does
not yet include an allowlisted external extractor. Recursive nested-archive
analysis and durable case/artifact storage are also intentionally deferred.

Run the tests with:

```powershell
py -3.12 -m pytest
```
