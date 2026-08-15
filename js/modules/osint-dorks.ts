export interface SearchDestination {
  display: string;
  url: string;
  action: string;
}

export interface SearchReference {
  label: string;
  description: string;
  query: (target: string) => string;
}

export type IdentityCategory = 'profiles' | 'connections' | 'posts' | 'comments' | 'correlation' | 'documents';

export interface IdentityContext {
  username: string;
  name: string;
  subject: string;
  email: string;
  afterDate: string;
  beforeDate: string;
}

export interface IdentityPivot {
  id: string;
  category: IdentityCategory;
  label: string;
  description: string;
  requires?: 'email';
  destination: (context: IdentityContext) => SearchDestination;
}

export const commonDorks: SearchReference[] = [
  { label: 'Pages in a domain', description: 'Limit results to one website.', query: target => `site:${target}` },
  { label: 'PDF documents', description: 'Find public PDF files indexed for the domain.', query: target => `site:${target} filetype:pdf` },
  { label: 'Office documents', description: 'Find indexed Word documents.', query: target => `site:${target} (filetype:doc OR filetype:docx)` },
  { label: 'Directory listings', description: 'Find pages that expose a directory index.', query: target => `site:${target} intitle:"index of" "parent directory"` },
  { label: 'Backup directories', description: 'Find indexed directory listings that mention backups.', query: target => `site:${target} intitle:"index of" inurl:backup` },
  { label: 'Log directories', description: 'Find indexed directory listings that mention logs.', query: target => `site:${target} intitle:"index of" inurl:logs` },
  { label: 'Log files', description: 'Find public log files.', query: target => `site:${target} filetype:log` },
  { label: 'Environment files', description: 'Find indexed environment files.', query: target => `site:${target} filetype:env` },
  { label: 'INI files', description: 'Find indexed INI configuration files.', query: target => `site:${target} filetype:ini` },
  { label: 'Configuration files', description: 'Find indexed configuration files.', query: target => `site:${target} filetype:config` },
  { label: 'SQL files', description: 'Find indexed SQL dumps or scripts.', query: target => `site:${target} filetype:sql` },
  { label: 'JSON files', description: 'Find indexed JSON documents.', query: target => `site:${target} filetype:json` },
  { label: 'XML files', description: 'Find indexed XML documents.', query: target => `site:${target} filetype:xml` },
  { label: 'Backup files', description: 'Find common indexed backup extensions.', query: target => `site:${target} (filetype:bak OR filetype:bkp OR filetype:backup)` },
  { label: 'Old files', description: 'Find files retained with an old extension.', query: target => `site:${target} filetype:old` },
  { label: 'ZIP archives', description: 'Find indexed ZIP archives.', query: target => `site:${target} filetype:zip` },
  { label: 'Login pages', description: 'Locate public login and sign-in routes.', query: target => `site:${target} (inurl:login OR inurl:signin)` },
  { label: 'Administration pages', description: 'Locate indexed administration routes.', query: target => `site:${target} inurl:admin` },
  { label: 'Dashboards', description: 'Locate indexed dashboard routes.', query: target => `site:${target} inurl:dashboard` },
  { label: 'ID parameters', description: 'Locate indexed PHP pages with ID parameters.', query: target => `site:${target} inurl:"php?id="` },
  { label: 'PHP configuration paths', description: 'Locate indexed config.php paths.', query: target => `site:${target} inurl:config.php` },
  { label: 'Confidential references', description: 'Find pages containing confidentiality language.', query: target => `site:${target} "confidential"` },
  { label: 'Password text files', description: 'Find indexed text files mentioning passwords.', query: target => `site:${target} "password" filetype:txt` },
  { label: 'API key references', description: 'Find common public API-key and secret-key labels.', query: target => `site:${target} ("api_key" OR "apikey" OR "secret_key")` },
  { label: 'Subdomains', description: 'Surface indexed subdomains while excluding the conventional www host.', query: target => `site:${target} -site:www.${target}` },
  { label: 'Page titles', description: 'Find pages with the target in their title.', query: target => `intitle:"${target}"` },
  { label: 'URL references', description: 'Find pages whose URL contains the target term.', query: target => `inurl:"${target}"` },
];

export const identityCategories: Array<{ id: IdentityCategory; label: string; description: string }> = [
  { id: 'profiles', label: 'User Profiles', description: 'Direct public profiles and focused, platform-specific index searches' },
  { id: 'connections', label: 'Friends / Connections', description: 'Public references to friends, followers, family, and shared mentions' },
  { id: 'posts', label: 'Posts / Media / Pastes', description: 'Indexed posts, blogs, paste sites, images, videos, and archived writing' },
  { id: 'comments', label: 'Comments', description: 'Indexed replies and comments on forums, blogs, and social sites' },
  { id: 'correlation', label: 'Correlation', description: 'Pivot between usernames, names, locations, emails, phones, and aliases' },
  { id: 'documents', label: 'Documents / Resume', description: 'Indexed documents, resumes, CVs, and authorship phrases' },
];

const directProfile = (url: string): SearchDestination => ({
  display: decodeURIComponent(url),
  url,
  action: 'Open profile',
});

const googleDestination = (query: string): SearchDestination => ({
  display: query,
  url: googleSearchUrl(query),
  action: 'Search Google',
});

export const identityPivots: IdentityPivot[] = [
  { id: 'facebook-direct', category: 'profiles', label: 'Facebook direct profile', description: 'Open the conventional public profile URL for the exact username.', destination: ctx => directProfile(`https://www.facebook.com/${encodeURIComponent(ctx.username)}`) },
  { id: 'tiktok-direct', category: 'profiles', label: 'TikTok direct profile', description: 'Open the public TikTok profile for the exact handle.', destination: ctx => directProfile(`https://www.tiktok.com/@${encodeURIComponent(ctx.username)}`) },
  { id: 'instagram-direct', category: 'profiles', label: 'Instagram direct profile', description: 'Open the public Instagram profile for the exact handle.', destination: ctx => directProfile(`https://www.instagram.com/${encodeURIComponent(ctx.username)}/`) },
  { id: 'linkedin-direct', category: 'profiles', label: 'LinkedIn direct profile', description: 'Open a public LinkedIn profile using its custom URL slug.', destination: ctx => directProfile(`https://www.linkedin.com/in/${encodeURIComponent(ctx.username)}/`) },
  { id: 'x-direct', category: 'profiles', label: 'X direct profile', description: 'Open the public X profile for the exact username.', destination: ctx => directProfile(`https://x.com/${encodeURIComponent(ctx.username)}`) },
  { id: 'github-direct', category: 'profiles', label: 'GitHub direct profile', description: 'Open the public GitHub profile for the exact username.', destination: ctx => directProfile(`https://github.com/${encodeURIComponent(ctx.username)}`) },
  { id: 'reddit-direct', category: 'profiles', label: 'Reddit direct profile', description: 'Open the public Reddit profile for the exact username.', destination: ctx => directProfile(`https://www.reddit.com/user/${encodeURIComponent(ctx.username)}/`) },
  { id: 'medium-direct', category: 'profiles', label: 'Medium direct profile', description: 'Open the conventional Medium profile path for the username.', destination: ctx => directProfile(`https://medium.com/@${encodeURIComponent(ctx.username)}`) },
  { id: 'exact-username', category: 'profiles', label: 'Exact username', description: 'Find exact public references to the handle.', destination: ctx => googleDestination(`"${ctx.username}"`) },
  { id: 'excluded-socials', category: 'profiles', label: 'Username outside major networks', description: 'Find references while excluding common social networks.', destination: ctx => googleDestination(`"${ctx.username}" -site:facebook.com -site:instagram.com -site:linkedin.com`) },
  { id: 'profile-paths', category: 'profiles', label: 'Common profile paths', description: 'Find indexed user, member, account, or profile URLs.', destination: ctx => googleDestination(`"${ctx.username}" (inurl:user OR inurl:member OR inurl:account OR inurl:profile)`) },
  { id: 'facebook-index', category: 'profiles', label: 'Facebook indexed profiles', description: 'Search Facebook while excluding login and sign-up pages.', destination: ctx => googleDestination(`site:facebook.com "${ctx.username}" -intitle:"log in" -intitle:"sign up"`) },
  { id: 'instagram-index', category: 'profiles', label: 'Instagram indexed profiles', description: 'Search Instagram URLs for the username.', destination: ctx => googleDestination(`site:instagram.com inurl:"${ctx.username}"`) },
  { id: 'tiktok-index', category: 'profiles', label: 'TikTok indexed profiles', description: 'Search TikTok handle paths without putting a path in site:.', destination: ctx => googleDestination(`site:tiktok.com inurl:"/@${ctx.username}"`) },
  { id: 'linkedin-username', category: 'profiles', label: 'LinkedIn by username', description: 'Search public LinkedIn profile paths for the username.', destination: ctx => googleDestination(`site:linkedin.com inurl:"/in/" "${ctx.username}"`) },
  { id: 'linkedin-subject', category: 'profiles', label: 'LinkedIn by name', description: 'Search public LinkedIn profile paths for the supplied name.', destination: ctx => googleDestination(`site:linkedin.com inurl:"/in/" "${ctx.subject}"`) },
  { id: 'x-index', category: 'profiles', label: 'X indexed profiles', description: 'Search public X pages for the username.', destination: ctx => googleDestination(`site:x.com inurl:"/${ctx.username}"`) },
  { id: 'twitter-index', category: 'profiles', label: 'Twitter indexed profiles', description: 'Search legacy Twitter pages for the username.', destination: ctx => googleDestination(`site:twitter.com inurl:"/${ctx.username}"`) },
  { id: 'reddit-index', category: 'profiles', label: 'Reddit indexed profiles', description: 'Search Reddit user paths for the username.', destination: ctx => googleDestination(`site:reddit.com inurl:"/user/${ctx.username}"`) },
  { id: 'github-index', category: 'profiles', label: 'GitHub references', description: 'Search GitHub for the exact username.', destination: ctx => googleDestination(`site:github.com "${ctx.username}"`) },
  { id: 'gitlab-index', category: 'profiles', label: 'GitLab references', description: 'Search GitLab for the exact username.', destination: ctx => googleDestination(`site:gitlab.com "${ctx.username}"`) },
  { id: 'medium-index', category: 'profiles', label: 'Medium profiles', description: 'Search Medium handle paths for the username.', destination: ctx => googleDestination(`site:medium.com inurl:"/@${ctx.username}"`) },
  { id: 'steam-index', category: 'profiles', label: 'Steam Community', description: 'Search public Steam Community pages.', destination: ctx => googleDestination(`site:steamcommunity.com "${ctx.username}"`) },
  { id: 'twitch-index', category: 'profiles', label: 'Twitch', description: 'Search public Twitch pages.', destination: ctx => googleDestination(`site:twitch.tv "${ctx.username}"`) },
  { id: 'keybase-index', category: 'profiles', label: 'Keybase', description: 'Search public Keybase profiles.', destination: ctx => googleDestination(`site:keybase.io "${ctx.username}"`) },
  { id: 'about-index', category: 'profiles', label: 'About.me', description: 'Search public About.me pages.', destination: ctx => googleDestination(`site:about.me "${ctx.username}"`) },
  { id: 'linktree-index', category: 'profiles', label: 'Linktree', description: 'Search public Linktree pages.', destination: ctx => googleDestination(`site:linktr.ee "${ctx.username}"`) },
  { id: 'gravatar-index', category: 'profiles', label: 'Gravatar', description: 'Search public Gravatar pages.', destination: ctx => googleDestination(`site:gravatar.com "${ctx.username}"`) },
  { id: 'pinterest-index', category: 'profiles', label: 'Pinterest', description: 'Search public Pinterest pages.', destination: ctx => googleDestination(`site:pinterest.com "${ctx.username}"`) },
  { id: 'quora-index', category: 'profiles', label: 'Quora', description: 'Search Quora profile paths for the username.', destination: ctx => googleDestination(`site:quora.com inurl:"/profile/${ctx.username}"`) },

  { id: 'friends-with', category: 'connections', label: 'Friends and connections', description: 'Find public pages that describe social connections.', destination: ctx => googleDestination(`"${ctx.subject}" ("friends with" OR "connected to" OR tagged OR mentioned)`) },
  { id: 'mutual-friends', category: 'connections', label: 'Mutual friends', description: 'Find indexed pages containing mutual-friend language.', destination: ctx => googleDestination(`"${ctx.subject}" intext:"mutual friends"`) },
  { id: 'linkedin-connections', category: 'connections', label: 'LinkedIn connections', description: 'Search LinkedIn profile paths for connection references.', destination: ctx => googleDestination(`site:linkedin.com inurl:"/in/" "${ctx.subject}" connections`) },
  { id: 'followers', category: 'connections', label: 'Followers and follows', description: 'Find public follower or following references.', destination: ctx => googleDestination(`"${ctx.username}" (followers OR follows OR "followed by")`) },
  { id: 'family', category: 'connections', label: 'Family relationships', description: 'Find public references to family or relationship terms.', destination: ctx => googleDestination(`"${ctx.subject}" (family OR spouse OR "married to" OR sibling OR brother OR sister)`) },

  { id: 'x-posts', category: 'posts', label: 'X posts', description: 'Search indexed X posts and mentions.', destination: ctx => googleDestination(`site:x.com "${ctx.username}"`) },
  { id: 'twitter-posts', category: 'posts', label: 'Twitter posts', description: 'Search indexed legacy Twitter posts and mentions.', destination: ctx => googleDestination(`site:twitter.com "${ctx.username}"`) },
  { id: 'reddit-posts', category: 'posts', label: 'Reddit posts', description: 'Search indexed Reddit submissions and mentions.', destination: ctx => googleDestination(`site:reddit.com "${ctx.username}"`) },
  { id: 'facebook-posts', category: 'posts', label: 'Facebook permalinks', description: 'Search indexed Facebook permalink URLs by subject.', destination: ctx => googleDestination(`site:facebook.com inurl:permalink "${ctx.subject}"`) },
  { id: 'medium-posts', category: 'posts', label: 'Medium articles', description: 'Search public Medium articles mentioning the username.', destination: ctx => googleDestination(`site:medium.com "${ctx.username}"`) },
  { id: 'blogspot-posts', category: 'posts', label: 'Blogspot posts', description: 'Search Blogspot writing by full name or username.', destination: ctx => googleDestination(`site:blogspot.com "${ctx.subject}"`) },
  { id: 'wordpress-posts', category: 'posts', label: 'WordPress posts', description: 'Search WordPress writing by full name or username.', destination: ctx => googleDestination(`site:wordpress.com "${ctx.subject}"`) },
  { id: 'authored-posts', category: 'posts', label: 'Authored posts', description: 'Find common post-author attribution phrases.', destination: ctx => googleDestination(`"${ctx.username}" ("posted by" OR "submitted by" OR "written by")`) },
  { id: 'dated-posts', category: 'posts', label: 'Date-bounded references', description: 'Use supported after: and before: operators.', destination: ctx => googleDestination(`"${ctx.username}" after:${ctx.afterDate} before:${ctx.beforeDate}`) },
  { id: 'pastebin-username', category: 'posts', label: 'Pastebin username', description: 'Search public Pastebin pages for the username.', destination: ctx => googleDestination(`site:pastebin.com "${ctx.username}"`) },
  { id: 'pastebin-email', category: 'posts', label: 'Pastebin email', description: 'Search public Pastebin pages for the supplied email.', requires: 'email', destination: ctx => googleDestination(`site:pastebin.com "${ctx.email}"`) },
  { id: 'throwbin', category: 'posts', label: 'ThrowBin', description: 'Search indexed ThrowBin pages.', destination: ctx => googleDestination(`site:throwbin.io "${ctx.username}"`) },
  { id: 'ghostbin', category: 'posts', label: 'Ghostbin', description: 'Search indexed Ghostbin pages.', destination: ctx => googleDestination(`site:ghostbin.com "${ctx.username}"`) },
  { id: 'justpaste', category: 'posts', label: 'JustPaste.it', description: 'Search indexed JustPaste.it pages.', destination: ctx => googleDestination(`site:justpaste.it "${ctx.username}"`) },
  { id: 'forum-pages', category: 'posts', label: 'Forum pages', description: 'Find forum URLs mentioning the username.', destination: ctx => googleDestination(`"${ctx.username}" inurl:forum`) },
  { id: 'thread-pages', category: 'posts', label: 'Thread pages', description: 'Find discussion-thread URLs mentioning the username.', destination: ctx => googleDestination(`"${ctx.username}" inurl:thread`) },
  { id: 'image-files', category: 'posts', label: 'Indexed images', description: 'Find common indexed image formats associated with the username.', destination: ctx => googleDestination(`"${ctx.username}" (filetype:jpg OR filetype:png OR filetype:jpeg)`) },
  { id: 'flickr', category: 'posts', label: 'Flickr', description: 'Search public Flickr pages.', destination: ctx => googleDestination(`site:flickr.com "${ctx.username}"`) },
  { id: 'imgur', category: 'posts', label: 'Imgur', description: 'Search public Imgur pages.', destination: ctx => googleDestination(`site:imgur.com "${ctx.username}"`) },
  { id: 'youtube-handle', category: 'posts', label: 'YouTube handle', description: 'Search YouTube for the exact handle.', destination: ctx => googleDestination(`site:youtube.com "@${ctx.username}"`) },
  { id: 'youtube-subject', category: 'posts', label: 'YouTube by name', description: 'Search YouTube for the supplied name.', destination: ctx => googleDestination(`site:youtube.com "${ctx.subject}"`) },

  { id: 'comment-terms', category: 'comments', label: 'Comment and reply terms', description: 'Find pages describing comments, replies, or quotations.', destination: ctx => googleDestination(`"${ctx.username}" (commented OR replied OR said)`) },
  { id: 'reddit-comments', category: 'comments', label: 'Reddit comments', description: 'Search Reddit discussion paths without putting a path in site:.', destination: ctx => googleDestination(`site:reddit.com inurl:"/r/" "${ctx.username}"`) },
  { id: 'disqus-comments', category: 'comments', label: 'Disqus comments', description: 'Search indexed Disqus discussions.', destination: ctx => googleDestination(`site:disqus.com "${ctx.username}"`) },
  { id: 'youtube-comments', category: 'comments', label: 'YouTube comment references', description: 'Search indexed YouTube pages containing comment text.', destination: ctx => googleDestination(`site:youtube.com intext:comment "${ctx.username}"`) },
  { id: 'comment-pages', category: 'comments', label: 'Comment pages', description: 'Search common comment-page URL patterns.', destination: ctx => googleDestination(`"${ctx.username}" inurl:comment-page`) },
  { id: 'hacker-news', category: 'comments', label: 'Hacker News', description: 'Search indexed Hacker News discussions.', destination: ctx => googleDestination(`site:news.ycombinator.com "${ctx.username}"`) },
  { id: 'forum-comments', category: 'comments', label: 'Forum comments', description: 'Search indexed forum and thread pages for replies.', destination: ctx => googleDestination(`"${ctx.username}" (inurl:forum OR inurl:thread) (comment OR reply)`) },

  { id: 'email-providers', category: 'correlation', label: 'Email-provider references', description: 'Find pages connecting the username to common email domains.', destination: ctx => googleDestination(`"${ctx.username}" ("@gmail.com" OR "@yahoo.com" OR "@outlook.com" OR "@protonmail.com")`) },
  { id: 'exact-email', category: 'correlation', label: 'Exact email', description: 'Find exact public references to the supplied email address.', requires: 'email', destination: ctx => googleDestination(`"${ctx.email}"`) },
  { id: 'name-username', category: 'correlation', label: 'Name and username', description: 'Find pages where the full name and username appear together.', destination: ctx => googleDestination(`"${ctx.subject}" "${ctx.username}"`) },
  { id: 'real-name', category: 'correlation', label: 'Real-name references', description: 'Find pages associating the username with real-name language.', destination: ctx => googleDestination(`"${ctx.username}" "real name"`) },
  { id: 'aliases', category: 'correlation', label: 'Aliases', description: 'Search for alternate-name and alias language.', destination: ctx => googleDestination(`"${ctx.subject}" (aka OR "also known as" OR alias)`) },
  { id: 'location', category: 'correlation', label: 'Location references', description: 'Find pages associating the identity with location language.', destination: ctx => googleDestination(`"${ctx.username}" (location OR "based in" OR "lives in" OR "from")`) },
  { id: 'phone', category: 'correlation', label: 'Phone references', description: 'Find public phone or messaging references.', destination: ctx => googleDestination(`"${ctx.username}" (phone OR "phone number" OR mobile OR whatsapp)`) },
  { id: 'government', category: 'correlation', label: 'Government records', description: 'Search indexed government pages by subject.', destination: ctx => googleDestination(`site:.gov "${ctx.subject}"`) },
  { id: 'education', category: 'correlation', label: 'Education records', description: 'Search indexed education pages by subject.', destination: ctx => googleDestination(`site:.edu "${ctx.subject}"`) },

  { id: 'pdf', category: 'documents', label: 'PDF documents', description: 'Search indexed PDFs mentioning the username or name.', destination: ctx => googleDestination(`"${ctx.subject}" filetype:pdf`) },
  { id: 'resume-pdf', category: 'documents', label: 'PDF resumes', description: 'Search indexed PDF resumes and CVs.', destination: ctx => googleDestination(`"${ctx.subject}" (resume OR "curriculum vitae" OR CV) filetype:pdf`) },
  { id: 'resume-doc', category: 'documents', label: 'Word resumes', description: 'Search indexed Word resumes and CVs.', destination: ctx => googleDestination(`"${ctx.subject}" (resume OR "curriculum vitae" OR CV) (filetype:doc OR filetype:docx)`) },
  { id: 'document-posts', category: 'documents', label: 'Archived writing', description: 'Find username references inside indexed PDF and Word files.', destination: ctx => googleDestination(`"${ctx.username}" (filetype:pdf OR filetype:doc OR filetype:docx)`) },
  { id: 'authorship-phrases', category: 'documents', label: 'Document authorship phrases', description: 'Find PDFs that explicitly mention common authorship language.', destination: ctx => googleDestination(`"${ctx.subject}" (author OR "written by" OR "prepared by") filetype:pdf`) },
];

export function googleSearchUrl(query: string): string {
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

export function cleanUsername(value: string): string {
  return value.trim().replace(/^@+/, '').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64);
}

export function availableIdentityPivots(context: IdentityContext): IdentityPivot[] {
  return identityPivots.filter(pivot => pivot.requires !== 'email' || Boolean(context.email));
}

export function normalizeDorkDomain(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    const hostname = url.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
    if (!hostname.includes('.') || hostname.length > 253) return '';
    if (!hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) return '';
    return hostname;
  } catch {
    return '';
  }
}
