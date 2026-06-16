const https = require('https');
const http = require('http');

function fetchRaw(urlStr, timeout = 12000) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(urlStr);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.get(urlStr, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': '*/*',
        },
        timeout,
        rejectUnauthorized: false,
      }, (res) => {
        // follow redirects
        if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
          try {
            const loc = new URL(res.headers.location, urlStr).href;
            return fetchRaw(loc, timeout).then(resolve).catch(reject);
          } catch(e) {}
        }
        let data = '';
        res.on('data', c => { if (data.length < 2000000) data += c; }); // 2MB max
        res.on('end', () => resolve({ body: data, status: res.statusCode, finalUrl: urlStr }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    } catch(e) { reject(e); }
  });
}

async function headCheck(urlStr, timeout = 6000) {
  return new Promise((resolve) => {
    try {
      const u = new URL(urlStr);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request(urlStr, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': '*/*' },
        timeout,
        rejectUnauthorized: false,
      }, (res) => resolve({ url: urlStr, status: res.statusCode }));
      req.on('error', () => resolve({ url: urlStr, status: 0 }));
      req.on('timeout', () => { req.destroy(); resolve({ url: urlStr, status: -1 }); });
      req.end();
    } catch(e) { resolve({ url: urlStr, status: 0 }); }
  });
}

// ── SECRET PATTERNS ────────────────────────────────────────────────────────
const SECRET_PATTERNS = [
  { type:'AWS Access Key',         sev:'critical', re:/AKIA[0-9A-Z]{16}/g },
  { type:'AWS Secret Key',         sev:'critical', re:/(?:aws.{0,20}secret|secret.{0,10}key).{0,10}["'\s:=]+([A-Za-z0-9\/+=]{40})/gi },
  { type:'Google API Key',         sev:'high',     re:/AIza[0-9A-Za-z\-_]{35}/g },
  { type:'Firebase URL',           sev:'medium',   re:/https:\/\/[a-z0-9-]+\.firebaseio\.com/g },
  { type:'Stripe Secret Key',      sev:'critical', re:/sk_live_[0-9a-zA-Z]{24,}/g },
  { type:'Stripe Test Key',        sev:'info',     re:/sk_test_[0-9a-zA-Z]{24,}/g },
  { type:'GitHub Token',           sev:'critical', re:/ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/g },
  { type:'GitLab Token',           sev:'critical', re:/glpat-[A-Za-z0-9\-_]{20}/g },
  { type:'Slack Bot Token',        sev:'critical', re:/xoxb-[0-9]{6,}-[0-9]{6,}-[A-Za-z0-9]{24}/g },
  { type:'Slack Webhook',          sev:'high',     re:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g },
  { type:'SendGrid Key',           sev:'critical', re:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { type:'Twilio SID',             sev:'high',     re:/AC[a-zA-Z0-9]{32}/g },
  { type:'JWT Token',              sev:'high',     re:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { type:'Bearer Token',           sev:'high',     re:/(?:bearer|authorization)["'\s:]+([A-Za-z0-9\-._~+\/]{20,}=*)/gi },
  { type:'Basic Auth URL',         sev:'critical', re:/https?:\/\/[^:@\s]{2,}:[^@\s]{2,}@[^\s"'<>]+/g },
  { type:'Private Key',            sev:'critical', re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type:'Hardcoded Password',     sev:'high',     re:/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi },
  { type:'API Key Generic',        sev:'high',     re:/(?:api_key|apikey|api-key)\s*[:=]\s*["']([A-Za-z0-9\-_]{10,})["']/gi },
  { type:'Secret Generic',         sev:'high',     re:/(?:client_secret|app_secret)\s*[:=]\s*["']([A-Za-z0-9\-_!@#$%]{8,})["']/gi },
  { type:'Access Token',           sev:'high',     re:/(?:access_token|accesstoken)\s*[:=]\s*["']([A-Za-z0-9\-_.]{16,})["']/gi },
  { type:'Database URL',           sev:'critical', re:/(?:mongodb|mysql|postgresql|redis|mssql):\/\/[^\s"'<>]{10,}/gi },
  { type:'S3 Bucket',              sev:'medium',   re:/[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/g },
  { type:'Mapbox Token',           sev:'medium',   re:/pk\.eyJ1[A-Za-z0-9._-]+/g },
  { type:'Mailgun Key',            sev:'high',     re:/key-[0-9a-zA-Z]{32}/g },
  { type:'NPM Token',              sev:'high',     re:/npm_[A-Za-z0-9]{36}/g },
  { type:'Shopify Token',          sev:'critical', re:/shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}/g },
  { type:'Internal Endpoint',      sev:'medium',   re:/https?:\/\/(?:api|internal|dev|staging|admin|backend)\.[a-z0-9.-]+\/[^\s"'<>]{3,}/gi },
  { type:'Private IP',             sev:'low',      re:/(?<![.\d])(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}(?![.\d])/g },
  { type:'Google OAuth Client',    sev:'medium',   re:/[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com/g },
  { type:'Discord Token',          sev:'high',     re:/[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}/g },
  { type:'Telegram Bot Token',     sev:'high',     re:/[0-9]{8,10}:[A-Za-z0-9_-]{35}/g },
  { type:'Azure Storage Key',      sev:'critical', re:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{80,}/g },
  { type:'GCP Service Account',    sev:'critical', re:/"type"\s*:\s*"service_account"/g },
  { type:'Mailchimp Key',          sev:'high',     re:/[0-9a-f]{32}-us[0-9]{1,2}/g },
  { type:'Heroku API Key',         sev:'high',     re:/(?i:heroku).{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g },
];

function scanForSecrets(content, sourceUrl) {
  const findings = [];
  const seen = new Set();
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(content)) !== null) {
      const val = (typeof m[1] === 'string' ? m[1] : m[0]).trim();
      if (val.length < 6 || ['true','false','null','undefined','function'].includes(val)) continue;
      const key = p.type + '|' + val.slice(0,40);
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({ type: p.type, severity: p.sev, match: val.slice(0,200), source: sourceUrl });
      }
    }
  }
  return findings;
}

// ── URL UTILS ──────────────────────────────────────────────────────────────
async function getWaybackUrls(domain) {
  const urls = new Set();

  // Wayback CDX — multiple queries for better coverage
  const cdxQueries = [
    `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=text&fl=original&collapse=urlkey&limit=5000&filter=statuscode:200`,
    `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=text&fl=original&collapse=urlkey&limit=3000&filter=mimetype:application/javascript`,
    `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=text&fl=original&collapse=urlkey&limit=3000&filter=mimetype:application/json`,
    `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=3000`,
  ];

  for (const q of cdxQueries) {
    try {
      const r = await fetchRaw(q, 14000);
      r.body.split('\n').forEach(u => { const t = u.trim(); if (t.startsWith('http')) urls.add(t); });
    } catch(e) {}
  }

  // Common Crawl
  try {
    const r = await fetchRaw(
      `https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=${domain}/*&output=text&fl=url&limit=2000`,
      12000
    );
    r.body.split('\n').forEach(u => { const t = u.trim(); if (t.startsWith('http')) urls.add(t); });
  } catch(e) {}

  return [...urls];
}

function classifyUrl(url) {
  const tags = new Set();
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    const params = [...u.searchParams.keys()];

    if (/\.js(\?|$)/.test(path))   tags.add('js');
    if (/\.json(\?|$)/.test(path)) tags.add('json');
    if (/\.xml(\?|$)/.test(path))  tags.add('xml');
    if (/\.(zip|tar|gz|rar|7z)(\?|$)/.test(path)) tags.add('archive');
    if (/\.env/.test(path))         tags.add('env');
    if (/\.git/.test(path))         tags.add('git');
    if (/\.(sql|db|sqlite)(\?|$)/.test(path)) tags.add('database');
    if (/\.log(\?|$)/.test(path))   tags.add('log');
    if (/\.(bak|backup|old|orig)(\?|$)/.test(path)) tags.add('backup');
    if (/\.(config|conf|cfg|ini|ya?ml)(\?|$)/.test(path)) tags.add('config');
    if (/\.(php|asp|aspx|jsp)/.test(path)) tags.add('backend');
    if (path.includes('/api/') || /\/api$/.test(path)) tags.add('api');
    if (/\/admin|\/wp-admin|\/administrator/.test(path)) tags.add('admin');
    if (/\/login|\/signin|\/auth|\/oauth|\/sso|\/reset|\/forgot/.test(path)) tags.add('auth');
    if (/\/upload|\/uploads/.test(path)) tags.add('upload');
    if (/\/graphql|\/gql/.test(path)) tags.add('graphql');
    if (/\/swagger|\/openapi|\/api-docs/.test(path)) tags.add('swagger');
    if (/\/debug|\/test|\/dev/.test(path)) tags.add('debug');
    if (/\/(v1|v2|v3|v4)\//.test(path)) tags.add('api');
    if (/\/internal|\/private/.test(path)) tags.add('sensitive');
    if (/\/webhook|\/callback/.test(path)) tags.add('webhook');
    if (params.length > 0) tags.add('params');
    const juicy = ['id','user','uid','token','key','secret','pass','password','redirect','url','next','file','path','cmd','exec','debug','q','query','callback','jsonp'];
    if (params.some(p => juicy.includes(p.toLowerCase()))) tags.add('interesting-params');
  } catch(e) {}
  return [...tags];
}

// ── MAIN HANDLER ───────────────────────────────────────────────────────────
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { domain, limit = 2000, scan_secrets = true } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const cleanDomain = domain.replace(/^https?:\/\//,'').replace(/\/.*/,'').replace(/^www\./,'').trim();

  // 1. Get URLs
  let urls = await getWaybackUrls(cleanDomain);
  urls = [...new Set(urls)].slice(0, parseInt(limit) || 2000);

  // 2. Classify
  const classified = urls.map(url => ({ url, tags: classifyUrl(url), status: null }));

  // 3. Status check — first 200
  const toCheck = classified.slice(0, 200);
  const statusRes = await Promise.allSettled(toCheck.map(r => headCheck(r.url, 5000)));
  statusRes.forEach((r, i) => { if (r.status === 'fulfilled') toCheck[i].status = r.value.status; });

  // 4. Secret scanning — fetch JS + JSON + HTML pages (up to 40 files)
  const allSecrets = [];
  if (scan_secrets) {
    const toScan = classified.filter(r =>
      r.tags.includes('js') || r.tags.includes('json') || r.tags.includes('env') ||
      r.tags.includes('config') || r.tags.includes('backend')
    ).slice(0, 40);

    // also scan main page
    try {
      const main = await fetchRaw(`https://${cleanDomain}`, 8000);
      const secrets = scanForSecrets(main.body, `https://${cleanDomain}`);
      allSecrets.push(...secrets);
    } catch(e) {}

    await Promise.allSettled(
      toScan.map(async (r) => {
        try {
          const res2 = await fetchRaw(r.url, 8000);
          const secrets = scanForSecrets(res2.body, r.url);
          if (secrets.length) allSecrets.push(...secrets);
          // update status
          r.status = res2.status;
        } catch(e) {}
      })
    );
  }

  // 5. Buckets
  const buckets = {
    alive:        classified.filter(r => r.status === 200),
    redirect:     classified.filter(r => [301,302,303,307,308].includes(r.status)),
    forbidden:    classified.filter(r => r.status === 403),
    server_error: classified.filter(r => [500,502,503,504].includes(r.status)),
    not_found:    classified.filter(r => r.status === 404),
    unchecked:    classified.filter(r => !r.status || r.status <= 0),
  };

  // 6. Special
  const special = {
    js:                 classified.filter(r => r.tags.includes('js')),
    json:               classified.filter(r => r.tags.includes('json')),
    api_endpoints:      classified.filter(r => r.tags.includes('api')),
    with_params:        classified.filter(r => r.tags.includes('params')),
    interesting_params: classified.filter(r => r.tags.includes('interesting-params')),
    admin_panels:       classified.filter(r => r.tags.includes('admin')),
    auth_endpoints:     classified.filter(r => r.tags.includes('auth')),
    file_uploads:       classified.filter(r => r.tags.includes('upload')),
    graphql:            classified.filter(r => r.tags.includes('graphql')),
    swagger_docs:       classified.filter(r => r.tags.includes('swagger')),
    sensitive_files:    classified.filter(r => r.tags.some(t => ['env','git','database','log','backup','config','archive'].includes(t))),
    debug_endpoints:    classified.filter(r => r.tags.includes('debug')),
    webhooks:           classified.filter(r => r.tags.includes('webhook')),
    backend_files:      classified.filter(r => r.tags.includes('backend')),
  };

  // dedup secrets
  const seenSec = new Set();
  const uniqueSecrets = allSecrets.filter(s => {
    const k = s.type + '|' + s.match.slice(0,40);
    if (seenSec.has(k)) return false;
    seenSec.add(k); return true;
  });

  return res.status(200).json({
    domain: cleanDomain,
    total_found: urls.length,
    total_checked: toCheck.length,
    secrets_found: uniqueSecrets.length,
    buckets,
    special,
    secrets: uniqueSecrets,
  });
}
