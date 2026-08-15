# CTFKit Google Dork Reference

CTFKit generates focused Google searches for public information in authorized CTF and lab investigations. The executable template source is `js/modules/osint-dorks.ts`; this document explains the supported shapes and troubleshooting rules.

Search-engine indexing is incomplete, especially for social-network profiles, friends, posts, and comments. A result is a lead, not proof that an account belongs to a subject. Corroborate identity matches with independent evidence.

## Placeholders

- `{target}`: normalized domain, such as `example.com`
- `{username}`: normalized username or handle without a leading `@`
- `{subject}`: full name when supplied, otherwise the username
- `{email}`: optional exact email address
- `{after_date}` and `{before_date}`: explicit `YYYY-MM-DD` bounds

## Corrected operator rules

1. Keep `site:` operands domain-only. Use `site:reddit.com inurl:"/r/"`, not `site:reddit.com/r/`.
2. Use `after:YYYY-MM-DD before:YYYY-MM-DD`, not `YYYY..YYYY`.
3. Do not use unsupported `author:` syntax. Search for authorship words as normal terms.
4. Keep platform searches separate instead of building a large multi-site `OR` expression.
5. Never insert whitespace after an operator colon.
6. Encode the complete query as the single `q` URL parameter.

## General website examples

```text
site:{target}
site:{target} filetype:pdf
site:{target} intitle:"index of" "parent directory"
site:{target} intitle:"index of" inurl:backup
site:{target} intitle:"index of" inurl:logs
site:{target} filetype:log
site:{target} filetype:env
site:{target} filetype:ini
site:{target} filetype:config
site:{target} filetype:sql
site:{target} filetype:json
site:{target} filetype:xml
site:{target} (filetype:bak OR filetype:bkp OR filetype:backup)
site:{target} filetype:old
site:{target} filetype:zip
site:{target} (inurl:login OR inurl:signin)
site:{target} inurl:admin
site:{target} inurl:dashboard
site:{target} inurl:"php?id="
site:{target} inurl:config.php
site:{target} "confidential"
site:{target} "password" filetype:txt
site:{target} ("api_key" OR "apikey" OR "secret_key")
site:{target} -site:www.{target}
intitle:"{target}"
inurl:"{target}"
```

## Corrected user OSINT examples

### Profile paths

```text
site:instagram.com inurl:"{username}"
site:tiktok.com inurl:"/@{username}"
site:linkedin.com inurl:"/in/" "{subject}"
site:x.com inurl:"/{username}"
site:twitter.com inurl:"/{username}"
site:reddit.com inurl:"/user/{username}"
site:medium.com inurl:"/@{username}"
site:quora.com inurl:"/profile/{username}"
```

### Posts, comments, and dates

```text
site:facebook.com inurl:permalink "{subject}"
site:reddit.com inurl:"/r/" "{username}"
site:youtube.com intext:comment "{username}"
"{username}" (inurl:forum OR inurl:thread) (comment OR reply)
"{username}" after:{after_date} before:{before_date}
```

### Correlation and documents

```text
"{email}"
"{subject}" "{username}"
"{username}" "real name"
"{subject}" (aka OR "also known as" OR alias)
"{username}" (location OR "based in" OR "lives in" OR "from")
"{subject}" filetype:pdf
"{subject}" (resume OR "curriculum vitae" OR CV) filetype:pdf
"{subject}" (author OR "written by" OR "prepared by") filetype:pdf
```

The last query uses ordinary authorship terms; it does not use an `author:` operator.

## Automation behavior

- The UI creates encoded Google links and copyable queries without scraping result pages.
- Optional live results use the configured Google Programmable Search JSON API via `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID`.
- CTFKit does not rotate browser User-Agents, bypass CAPTCHAs, or use residential proxies because it does not scrape Google Web Search.
- Provider errors and missing API credentials are returned honestly; no search results are fabricated.

## Current scope

- General website dorks: 27 templates
- User OSINT pivots: 77 templates, including eight direct-profile links
- Email-specific pivots only appear when an email is supplied
- Date bounds are editable in the User OSINT form
