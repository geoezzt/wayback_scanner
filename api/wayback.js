const https = require('https');
const http = require('http');

function fetchRaw(urlStr, timeout) {
  timeout = timeout || 6000;
  return new Promise(function(resolve) {
    try {
      var u = new URL(urlStr);
      var lib = u.protocol === 'https:' ? https : http;
      var req = lib.get(urlStr, {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        timeout: timeout,
        rejectUnauthorized: false,
      }, function(res) {
        var data = '';
        res.on('data', function(c) { if (data.length < 800000) data += c; });
        res.on('end', function() { resolve({ body: data, status: res.statusCode }); });
      });
      req.on('error', function() { resolve({ body: '', status: 0 }); });
      req.on('timeout', function() { req.destroy(); resolve({ body: '', status: -1 }); });
    } catch(e) { resolve({ body: '', status: 0 }); }
  });
}

function headCheck(urlStr) {
  return new Promise(function(resolve) {
    try {
      var u = new URL(urlStr);
      var lib = u.protocol === 'https:' ? https : http;
      var req = lib.request(urlStr, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0' },
        timeout: 3500,
        rejectUnauthorized: false,
      }, function(res) { resolve({ url: urlStr, status: res.statusCode }); });
      req.on('error', function() { resolve({ url: urlStr, status: 0 }); });
      req.on('timeout', function() { req.destroy(); resolve({ url: urlStr, status: -1 }); });
      req.end();
    } catch(e) { resolve({ url: urlStr, status: 0 }); }
  });
}

var SECRET_PATTERNS = [
  { type:'AWS Access Key',     sev:'critical', re:/AKIA[0-9A-Z]{16}/g },
  { type:'Google API Key',     sev:'high',     re:/AIza[0-9A-Za-z\-_]{35}/g },
  { type:'Stripe Secret Key',  sev:'critical', re:/sk_live_[0-9a-zA-Z]{24,}/g },
  { type:'Stripe Test Key',    sev:'info',     re:/sk_test_[0-9a-zA-Z]{24,}/g },
  { type:'GitHub Token',       sev:'critical', re:/ghp_[A-Za-z0-9]{36}/g },
  { type:'Slack Bot Token',    sev:'critical', re:/xoxb-[0-9]{6,}-[0-9]{6,}-[A-Za-z0-9]{24}/g },
  { type:'SendGrid Key',       sev:'critical', re:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { type:'JWT Token',          sev:'high',     re:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { type:'Private Key',        sev:'critical', re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type:'Hardcoded Password', sev:'high',     re:/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi },
  { type:'API Key Generic',    sev:'high',     re:/(?:api_key|apikey|api-key)\s*[:=]\s*["']([A-Za-z0-9\-_]{10,})["']/gi },
  { type:'Secret Generic',     sev:'high',     re:/(?:client_secret|app_secret)\s*[:=]\s*["']([A-Za-z0-9\-_]{8,})["']/gi },
  { type:'Access Token',       sev:'high',     re:/(?:access_token|accesstoken)\s*[:=]\s*["']([A-Za-z0-9\-_.]{16,})["']/gi },
  { type:'Database URL',       sev:'critical', re:/(?:mongodb|mysql|postgresql|redis|mssql):\/\/[^\s"'<>]{10,}/gi },
  { type:'S3 Bucket',          sev:'medium',   re:/[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/g },
  { type:'Firebase URL',       sev:'medium',   re:/https:\/\/[a-z0-9-]+\.firebaseio\.com/g },
  { type:'Bearer Token',       sev:'high',     re:/(?:bearer|authorization)["'\s:]+([A-Za-z0-9\-._~+\/]{20,}=*)/gi },
  { type:'Basic Auth URL',     sev:'critical', re:/https?:\/\/[^:@\s]{2,}:[^@\s]{2,}@[^\s"'<>]+/g },
  { type:'Internal Endpoint',  sev:'medium',   re:/https?:\/\/(?:api|internal|dev|staging|admin|backend)\.[a-z0-9.-]+\/[^\s"'<>]{3,}/gi },
  { type:'Private IP',         sev:'low',      re:/(?<![.\d])(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}(?![.\d])/g },
];

function scanForSecrets(content, sourceUrl) {
  var findings = [], seen = {};
  SECRET_PATTERNS.forEach(function(p) {
    p.re.lastIndex = 0;
    var m;
    while ((m = p.re.exec(content)) !== null) {
      var val = (typeof m[1] === 'string' ? m[1] : m[0]).trim();
      if (val.length < 6 || ['true','false','null','undefined'].includes(val)) continue;
      var key = p.type + '|' + val.slice(0,40);
      if (!seen[key]) { seen[key] = true; findings.push({ type: p.type, severity: p.sev, match: val.slice(0,200), source: sourceUrl }); }
    }
  });
  return findings;
}

function classifyUrl(url) {
  var tags = {};
  try {
    var u = new URL(url);
    var path = u.pathname.toLowerCase();
    var params = Array.from(u.searchParams.keys());
    if (/\.js(\?|$)/.test(path))    tags.js = true;
    if (/\.json(\?|$)/.test(path))  tags.json = true;
    if (/\.env/.test(path))          tags.env = true;
    if (/\.git/.test(path))          tags.git = true;
    if (/\.(sql|db|sqlite)(\?|$)/.test(path)) tags.database = true;
    if (/\.log(\?|$)/.test(path))   tags.log = true;
    if (/\.(bak|backup|old)(\?|$)/.test(path)) tags.backup = true;
    if (/\.(config|conf|cfg|ini|ya?ml)(\?|$)/.test(path)) tags.config = true;
    if (/\.(php|asp|aspx|jsp)/.test(path)) tags.backend = true;
    if (/\.(zip|tar|gz)(\?|$)/.test(path)) tags.archive = true;
    if (/\/api\/|\/api$/.test(path)) tags.api = true;
    if (/\/admin|\/wp-admin/.test(path)) tags.admin = true;
    if (/\/login|\/signin|\/auth|\/oauth|\/sso/.test(path)) tags.auth = true;
    if (/\/upload/.test(path))       tags.upload = true;
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

// ── ROUTE ──────────────────────────────────────────────────────────────────
module.exports = async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(200).end(); return; }
  if (req.method !== 'POST')   { res.status(405).json({ error: 'POST only' }); return; }

  var body = req.body || {};
  var action = body.action || 'fetch';  // 'fetch' | 'check' | 'scan'
  var domain = (body.domain || '').replace(/^https?:\/\//,'').replace(/\/.*/,'').replace(/^www\./,'').trim();

  if (!domain) { res.status(400).json({ error: 'domain required' }); return; }

  // ── ACTION: fetch URLs from Wayback ─────────────────────────────────────
  if (action === 'fetch') {
    var limit = Math.min(parseInt(body.limit) || 1000, 3000);
    var urls = {};
    try {
      var r = await fetchRaw(
        'https://web.archive.org/cdx/search/cdx?url=' + domain + '/*&output=text&fl=original&collapse=urlkey&limit=' + limit,
        22000
      );
      r.body.split('\n').forEach(function(u) { var t=u.trim(); if(t.startsWith('http')) urls[t]=true; });
    } catch(e) {}
    var urlList = Object.keys(urls);
    var classified = urlList.map(function(url) { return { url:url, tags:classifyUrl(url), status:null }; });
    return res.status(200).json({ domain:domain, urls:classified, total:classified.length });
  }

  // ── ACTION: check status for a batch of URLs ─────────────────────────────
  if (action === 'check') {
    var batch = (body.urls || []).slice(0, 50);
    var results = await Promise.allSettled(batch.map(function(u) { return headCheck(u); }));
    var out = results.map(function(r) {
      return r.status === 'fulfilled' ? r.value : { url:'', status:0 };
    });
    return res.status(200).json({ results: out });
  }

  // ── ACTION: scan JS/JSON for secrets ─────────────────────────────────────
  if (action === 'scan') {
    var jsUrls = (body.urls || []).slice(0, 15);
    var allSecrets = [];

    // scan main page
    try {
      var main = await fetchRaw('https://' + domain, 5000);
      allSecrets = allSecrets.concat(scanForSecrets(main.body, 'https://' + domain));
    } catch(e) {}

    await Promise.allSettled(jsUrls.map(async function(url) {
      try {
        var r = await fetchRaw(url, 5000);
        var s = scanForSecrets(r.body, url);
        if (s.length) allSecrets = allSecrets.concat(s);
      } catch(e) {}
    }));

    var seen = {};
    var unique = allSecrets.filter(function(s) {
      var k = s.type+'|'+s.match.slice(0,40);
      if (seen[k]) return false; seen[k]=true; return true;
    });
    return res.status(200).json({ secrets: unique });
  }

  res.status(400).json({ error: 'unknown action' });
};
