const https = require('https');
const http = require('http');

function fetchRaw(urlStr, timeout = 12000) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(urlStr);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.get(urlStr, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; recon/1.0)' },
        timeout,
        rejectUnauthorized: false,
      }, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve({ body: data, status: res.statusCode }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    } catch(e) { reject(e); }
  });
}

async function getWaybackUrls(domain) {
  const urls = new Set();
  try {
    const r = await fetchRaw(
      `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=text&fl=original&collapse=urlkey&limit=5000`,
      15000
    );
    r.body.split('\n').forEach(u => { const t = u.trim(); if(t.startsWith('http')) urls.add(t); });
  } catch(e) {}

  try {
    const r2 = await fetchRaw(
      `https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=${domain}/*&output=text&fl=url&limit=2000`,
      12000
    );
    r2.body.split('\n').forEach(u => { const t = u.trim(); if(t.startsWith('http')) urls.add(t); });
  } catch(e) {}

  return [...urls];
}

async function checkStatus(url, timeout = 5000) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request(url, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': '*/*' },
        timeout,
        rejectUnauthorized: false,
      }, (res) => resolve({ url, status: res.statusCode }));
      req.on('error', () => resolve({ url, status: 0 }));
      req.on('timeout', () => { req.destroy(); resolve({ url, status: -1 }); });
      req.end();
    } catch(e) { resolve({ url, status: 0 }); }
  });
}

function classifyUrl(url) {
  const tags = new Set();
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    const params = [...u.searchParams.keys()];

    // File types
    if (/\.js(\?|$)/.test(path))   tags.add('js');
    if (/\.json(\?|$)/.test(path)) tags.add('json');
    if (/\.xml(\?|$)/.test(path))  tags.add('xml');
    if (/\.pdf(\?|$)/.test(path))  tags.add('pdf');
    if (/\.(zip|tar|gz|rar|7z)(\?|$)/.test(path)) tags.add('archive');
    if (/\.env/.test(path))         tags.add('env');
    if (/\.git/.test(path))         tags.add('git');
    if (/\.(sql|db|sqlite)(\?|$)/.test(path)) tags.add('database');
    if (/\.log(\?|$)/.test(path))   tags.add('log');
    if (/\.(bak|backup|old|orig|copy)(\?|$)/.test(path)) tags.add('backup');
    if (/\.(config|conf|cfg|ini|yaml|yml)(\?|$)/.test(path)) tags.add('config');
    if (/\.(php|asp|aspx|jsp)(\?|$)/.test(path)) tags.add('backend');

    // Interesting paths
    if (path.includes('/api/') || path.includes('/api?')) tags.add('api');
    if (/\/admin|\/administrator|\/wp-admin/.test(path)) tags.add('admin');
    if (/\/login|\/signin|\/auth|\/oauth|\/sso/.test(path)) tags.add('auth');
    if (/\/upload|\/file|\/files/.test(path)) tags.add('upload');
    if (/\/graphql|\/gql/.test(path)) tags.add('graphql');
    if (/\/swagger|\/openapi|\/api-docs/.test(path)) tags.add('swagger');
    if (/\/debug|\/test|\/dev/.test(path)) tags.add('debug');
    if (/\/(v1|v2|v3|v4)\//.test(path)) tags.add('api');
    if (/\/internal|\/private|\/hidden/.test(path)) tags.add('sensitive');
    if (/\/reset|\/forgot|\/password/.test(path)) tags.add('auth');
    if (/\/webhook|\/callback/.test(path)) tags.add('webhook');
    if (/\/search/.test(path)) tags.add('search');

    // Params
    if (params.length > 0) tags.add('params');
    const sensitiveParams = ['id','user','uid','username','token','key','secret','pass','password',
      'redirect','url','next','file','path','cmd','exec','debug','q','query','search','page','limit',
      'offset','sort','order','filter','type','action','method','lang','locale','callback','jsonp'];
    if (params.some(p => sensitiveParams.includes(p.toLowerCase()))) tags.add('interesting-params');

  } catch(e) {}
  return [...tags];
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { domain, limit = 1000 } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const cleanDomain = domain.replace(/^https?:\/\//,'').replace(/\/.*/,'').trim();

  // 1. Fetch from archives
  let urls = await getWaybackUrls(cleanDomain);
  urls = [...new Set(urls)].slice(0, parseInt(limit) || 1000);

  // 2. Classify all
  const classified = urls.map(url => ({ url, tags: classifyUrl(url), status: null }));

  // 3. Status check (first 150 only — vercel 25s limit)
  const toCheck = classified.slice(0, 150);
  const results = await Promise.allSettled(toCheck.map(r => checkStatus(r.url, 4500)));
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') toCheck[i].status = r.value.status;
  });

  // 4. Buckets by status
  const buckets = {
    alive:     classified.filter(r => r.status === 200),
    redirect:  classified.filter(r => [301,302,303,307,308].includes(r.status)),
    forbidden: classified.filter(r => r.status === 403),
    server_error: classified.filter(r => [500,502,503,504].includes(r.status)),
    not_found: classified.filter(r => r.status === 404),
    unchecked: classified.filter(r => r.status === null || r.status === 0 || r.status === -1),
  };

  // 5. Special categories
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
    search_endpoints:   classified.filter(r => r.tags.includes('search')),
    backend_files:      classified.filter(r => r.tags.includes('backend')),
  };

  return res.status(200).json({
    domain: cleanDomain,
    total_found: urls.length,
    total_checked: toCheck.length,
    buckets,
    special,
  });
}
