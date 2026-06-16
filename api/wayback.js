const https = require('https');
const http = require('http');

function fetchRaw(urlStr, timeout) {
  timeout = timeout || 12000;
  return new Promise(function(resolve, reject) {
    try {
      var u = new URL(urlStr);
      var lib = u.protocol === 'https:' ? https : http;
      var req = lib.get(urlStr, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        timeout: timeout,
        rejectUnauthorized: false,
      }, function(res) {
        if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
          try {
            var loc = new URL(res.headers.location, urlStr).href;
            return fetchRaw(loc, timeout).then(resolve).catch(reject);
          } catch(e) {}
        }
        var data = '';
        res.on('data', function(c) { if (data.length < 1500000) data += c; });
        res.on('end', function() { resolve({ body: data, status: res.statusCode }); });
      });
      req.on('error', reject);
      req.on('timeout', function() { req.destroy(); reject(new Error('Timeout')); });
    } catch(e) { reject(e); }
  });
}

function headCheck(urlStr, timeout) {
  timeout = timeout || 6000;
  return new Promise(function(resolve) {
    try {
      var u = new URL(urlStr);
      var lib = u.protocol === 'https:' ? https : http;
      var req = lib.request(urlStr, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': '*/*' },
        timeout: timeout,
        rejectUnauthorized: false,
      }, function(res) { resolve({ url: urlStr, status: res.statusCode }); });
      req.on('error', function() { resolve({ url: urlStr, status: 0 }); });
      req.on('timeout', function() { req.destroy(); resolve({ url: urlStr, status: -1 }); });
      req.end();
    } catch(e) { resolve({ url: urlStr, status: 0 }); }
  });
}

var SECRET_PATTERNS = [
  { type:'AWS Access Key',       sev:'critical', re:/AKIA[0-9A-Z]{16}/g },
  { type:'Google API Key',       sev:'high',     re:/AIza[0-9A-Za-z\-_]{35}/g },
  { type:'Stripe Secret Key',    sev:'critical', re:/sk_live_[0-9a-zA-Z]{24,}/g },
  { type:'Stripe Test Key',      sev:'info',     re:/sk_test_[0-9a-zA-Z]{24,}/g },
  { type:'GitHub Token',         sev:'critical', re:/ghp_[A-Za-z0-9]{36}/g },
  { type:'GitHub PAT',           sev:'critical', re:/github_pat_[A-Za-z0-9_]{82}/g },
  { type:'GitLab Token',         sev:'critical', re:/glpat-[A-Za-z0-9\-_]{20}/g },
  { type:'Slack Bot Token',      sev:'critical', re:/xoxb-[0-9]{6,}-[0-9]{6,}-[A-Za-z0-9]{24}/g },
  { type:'Slack Webhook',        sev:'high',     re:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g },
  { type:'SendGrid Key',         sev:'critical', re:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { type:'JWT Token',            sev:'high',     re:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { type:'Private Key',          sev:'critical', re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type:'Hardcoded Password',   sev:'high',     re:/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi },
  { type:'API Key Generic',      sev:'high',     re:/(?:api_key|apikey|api-key)\s*[:=]\s*["']([A-Za-z0-9\-_]{10,})["']/gi },
  { type:'Secret Generic',       sev:'high',     re:/(?:client_secret|app_secret)\s*[:=]\s*["']([A-Za-z0-9\-_]{8,})["']/gi },
  { type:'Access Token',         sev:'high',     re:/(?:access_token|accesstoken)\s*[:=]\s*["']([A-Za-z0-9\-_.]{16,})["']/gi },
  { type:'Database URL',         sev:'critical', re:/(?:mongodb|mysql|postgresql|redis|mssql):\/\/[^\s"'<>]{10,}/gi },
  { type:'S3 Bucket',            sev:'medium',   re:/[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/g },
  { type:'Firebase URL',         sev:'medium',   re:/https:\/\/[a-z0-9-]+\.firebaseio\.com/g },
  { type:'Mapbox Token',         sev:'medium',   re:/pk\.eyJ1[A-Za-z0-9._-]+/g },
  { type:'Mailgun Key',          sev:'high',     re:/key-[0-9a-zA-Z]{32}/g },
  { type:'NPM Token',            sev:'high',     re:/npm_[A-Za-z0-9]{36}/g },
  { type:'Shopify Token',        sev:'critical', re:/shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}/g },
  { type:'Internal Endpoint',    sev:'medium',   re:/https?:\/\/(?:api|internal|dev|staging|admin|backend)\.[a-z0-9.-]+\/[^\s"'<>]{3,}/gi },
  { type:'Private IP',           sev:'low',      re:/(?<![.\d])(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}(?![.\d])/g },
  { type:'Azure Storage Key',    sev:'critical', re:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{80,}/g },
  { type:'Discord Token',        sev:'high',     re:/[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}/g },
  { type:'Telegram Bot Token',   sev:'high',     re:/[0-9]{8,10}:[A-Za-z0-9_-]{35}/g },
  { type:'Basic Auth URL',       sev:'critical', re:/https?:\/\/[^:@\s]{2,}:[^@\s]{2,}@[^\s"'<>]+/g },
  { type:'Bearer Token',         sev:'high',     re:/(?:bearer|authorization)["'\s:]+([A-Za-z0-9\-._~+\/]{20,}=*)/gi },
];

function scanForSecrets(content, sourceUrl) {
  var findings = [];
  var seen = {};
  SECRET_PATTERNS.forEach(function(p) {
    p.re.lastIndex = 0;
    var m;
    while ((m = p.re.exec(content)) !== null) {
      var val = (typeof m[1] === 'string' ? m[1] : m[0]).trim();
      if (val.length < 6) continue;
      if (['true','false','null','undefined'].includes(val)) continue;
      var key = p.type + '|' + val.slice(0,40);
      if (!seen[key]) {
        seen[key] = true;
        findings.push({ type: p.type, severity: p.sev, match: val.slice(0,200), source: sourceUrl });
      }
    }
  });
  return findings;
}

async function getWaybackUrls(domain) {
  var urls = {};
  var queries = [
    'https://web.archive.org/cdx/search/cdx?url=' + domain + '/*&output=text&fl=original&collapse=urlkey&limit=5000',
    'https://web.archive.org/cdx/search/cdx?url=' + domain + '/*&output=text&fl=original&collapse=urlkey&limit=3000&filter=mimetype:application/javascript',
    'https://web.archive.org/cdx/search/cdx?url=*.' + domain + '/*&output=text&fl=original&collapse=urlkey&limit=2000',
  ];
  for (var i = 0; i < queries.length; i++) {
    try {
      var r = await fetchRaw(queries[i], 14000);
      r.body.split('\n').forEach(function(u) {
        var t = u.trim();
        if (t.startsWith('http')) urls[t] = true;
      });
    } catch(e) {}
  }
  try {
    var r2 = await fetchRaw('https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=' + domain + '/*&output=text&fl=url&limit=2000', 12000);
    r2.body.split('\n').forEach(function(u) {
      var t = u.trim();
      if (t.startsWith('http')) urls[t] = true;
    });
  } catch(e) {}
  return Object.keys(urls);
}

function classifyUrl(url) {
  var tags = {};
  try {
    var u = new URL(url);
    var path = u.pathname.toLowerCase();
    var params = Array.from(u.searchParams.keys());
    if (/\.js(\?|$)/.test(path))   tags.js = true;
    if (/\.json(\?|$)/.test(path)) tags.json = true;
    if (/\.xml(\?|$)/.test(path))  tags.xml = true;
    if (/\.(zip|tar|gz|rar)(\?|$)/.test(path)) tags.archive = true;
    if (/\.env/.test(path))         tags.env = true;
    if (/\.git/.test(path))         tags.git = true;
    if (/\.(sql|db|sqlite)(\?|$)/.test(path)) tags.database = true;
    if (/\.log(\?|$)/.test(path))   tags.log = true;
    if (/\.(bak|backup|old)(\?|$)/.test(path)) tags.backup = true;
    if (/\.(config|conf|cfg|ini|ya?ml)(\?|$)/.test(path)) tags.config = true;
    if (/\.(php|asp|aspx|jsp)/.test(path)) tags.backend = true;
    if (/\/api\/|\/api$/.test(path)) tags.api = true;
    if (/\/admin|\/wp-admin/.test(path)) tags.admin = true;
    if (/\/login|\/signin|\/auth|\/oauth|\/sso|\/reset/.test(path)) tags.auth = true;
    if (/\/upload/.test(path)) tags.upload = true;
    if (/\/graphql|\/gql/.test(path)) tags.graphql = true;
    if (/\/swagger|\/openapi|\/api-docs/.test(path)) tags.swagger = true;
    if (/\/debug|\/test|\/dev/.test(path)) tags.debug = true;
    if (/\/(v1|v2|v3|v4)\//.test(path)) tags.api = true;
    if (/\/internal|\/private/.test(path)) tags.sensitive = true;
    if (/\/webhook|\/callback/.test(path)) tags.webhook = true;
    if (params.length > 0) tags.params = true;
    var juicy = ['id','user','uid','token','key','secret','pass','password','redirect','url','next','file','path','cmd','exec','debug','q','query','callback','jsonp'];
    if (params.some(function(p) { return juicy.includes(p.toLowerCase()); })) tags['interesting-params'] = true;
  } catch(e) {}
  return Object.keys(tags);
}

module.exports = async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(200).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

  var body = req.body || {};
  var domain = body.domain;
  var limit = parseInt(body.limit) || 2000;
  var scanSecrets = body.scan_secrets !== false;

  if (!domain) { res.status(400).json({ error: 'domain required' }); return; }

  var cleanDomain = domain.replace(/^https?:\/\//,'').replace(/\/.*/,'').replace(/^www\./,'').trim();

  // 1. Get URLs
  var urls = await getWaybackUrls(cleanDomain);
  var seen = {};
  urls = urls.filter(function(u) { if (seen[u]) return false; seen[u]=true; return true; }).slice(0, limit);

  // 2. Classify
  var classified = urls.map(function(url) { return { url: url, tags: classifyUrl(url), status: null }; });

  // 3. Status check first 200
  var toCheck = classified.slice(0, 200);
  var statusRes = await Promise.allSettled(toCheck.map(function(r) { return headCheck(r.url, 5000); }));
  statusRes.forEach(function(r, i) { if (r.status === 'fulfilled') toCheck[i].status = r.value.status; });

  // 4. Secret scanning
  var allSecrets = [];
  if (scanSecrets) {
    var toScan = classified.filter(function(r) {
      return r.tags.includes('js') || r.tags.includes('json') || r.tags.includes('env') || r.tags.includes('config');
    }).slice(0, 35);

    try {
      var main = await fetchRaw('https://' + cleanDomain, 8000);
      allSecrets = allSecrets.concat(scanForSecrets(main.body, 'https://' + cleanDomain));
    } catch(e) {}

    await Promise.allSettled(toScan.map(async function(r) {
      try {
        var res2 = await fetchRaw(r.url, 7000);
        var secrets = scanForSecrets(res2.body, r.url);
        if (secrets.length) allSecrets = allSecrets.concat(secrets);
        r.status = res2.status;
      } catch(e) {}
    }));
  }

  // 5. Buckets
  var buckets = {
    alive:        classified.filter(function(r) { return r.status === 200; }),
    redirect:     classified.filter(function(r) { return [301,302,303,307,308].includes(r.status); }),
    forbidden:    classified.filter(function(r) { return r.status === 403; }),
    server_error: classified.filter(function(r) { return r.status >= 500 && r.status < 600; }),
    not_found:    classified.filter(function(r) { return r.status === 404; }),
    unchecked:    classified.filter(function(r) { return !r.status || r.status <= 0; }),
  };

  // 6. Special
  var special = {
    js:                 classified.filter(function(r) { return r.tags.includes('js'); }),
    json:               classified.filter(function(r) { return r.tags.includes('json'); }),
    api_endpoints:      classified.filter(function(r) { return r.tags.includes('api'); }),
    with_params:        classified.filter(function(r) { return r.tags.includes('params'); }),
    interesting_params: classified.filter(function(r) { return r.tags.includes('interesting-params'); }),
    admin_panels:       classified.filter(function(r) { return r.tags.includes('admin'); }),
    auth_endpoints:     classified.filter(function(r) { return r.tags.includes('auth'); }),
    file_uploads:       classified.filter(function(r) { return r.tags.includes('upload'); }),
    graphql:            classified.filter(function(r) { return r.tags.includes('graphql'); }),
    swagger_docs:       classified.filter(function(r) { return r.tags.includes('swagger'); }),
    sensitive_files:    classified.filter(function(r) { return r.tags.some(function(t) { return ['env','git','database','log','backup','config','archive'].includes(t); }); }),
    debug_endpoints:    classified.filter(function(r) { return r.tags.includes('debug'); }),
    webhooks:           classified.filter(function(r) { return r.tags.includes('webhook'); }),
    backend_files:      classified.filter(function(r) { return r.tags.includes('backend'); }),
  };

  // dedup secrets
  var seenSec = {};
  var uniqueSecrets = allSecrets.filter(function(s) {
    var k = s.type + '|' + s.match.slice(0,40);
    if (seenSec[k]) return false;
    seenSec[k] = true; return true;
  });

  res.status(200).json({
    domain: cleanDomain,
    total_found: urls.length,
    total_checked: toCheck.length,
    secrets_found: uniqueSecrets.length,
    buckets: buckets,
    special: special,
    secrets: uniqueSecrets,
  });
};
