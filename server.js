'use strict';
// Small reference licensing API for YOUR MJ VIP/PRO module only.
// Node.js 18+; uses only built-in modules. For larger deployments use a managed DB,
// TLS reverse proxy, rate limiting, backups, and a proper secret manager.
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8787);
const ADMIN_TOKEN = process.env.MJ_ADMIN_TOKEN || '';
const PRODUCT = 'MJ VIP/PRO';
const DB_PATH = process.env.MJ_DB_PATH || path.join(__dirname, 'licenses.json');
if (ADMIN_TOKEN.length < 32) {
  console.error('Set MJ_ADMIN_TOKEN to a random secret of at least 32 characters.');
  process.exit(1);
}

function loadDb() {
  try { const x = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); return { licenses: Array.isArray(x.licenses) ? x.licenses : [] }; }
  catch (e) { if (e.code === 'ENOENT') return { licenses: [] }; throw e; }
}
let db = loadDb();
function saveDb() {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_PATH);
}
function hashKey(key) { return crypto.createHash('sha256').update(key, 'utf8').digest('hex'); }
function newKey() {
  const parts = [crypto.randomBytes(4).toString('hex'), crypto.randomBytes(4).toString('hex'), crypto.randomBytes(4).toString('hex')];
  return 'MJPRO-' + parts.join('-').toUpperCase();
}
function send(res, code, body) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(body));
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = ''; let size = 0;
    req.on('data', chunk => { size += chunk.length; if (size > 16384) { reject(new Error('Request too large')); req.destroy(); return; } body += chunk; });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
function validText(s, max=200) { return typeof s === 'string' && s.length > 0 && s.length <= max && !/[\u0000-\u001f]/.test(s); }
function admin(req) { return typeof req.headers.authorization === 'string' && safeEqual(req.headers.authorization, 'Bearer ' + ADMIN_TOKEN); }
function safeEqual(a,b) { const aa=Buffer.from(a); const bb=Buffer.from(b); return aa.length===bb.length && crypto.timingSafeEqual(aa,bb); }
const hits = new Map();
function rateOk(req) {
  const ip = (req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  const now = Date.now(); const prior = hits.get(ip) || { start: now, count: 0 };
  if (now - prior.start > 60_000) { prior.start = now; prior.count = 0; }
  prior.count++; hits.set(ip, prior); return prior.count <= 60;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (!rateOk(req)) return send(res, 429, { valid:false, pro:false, message:'Rate limit exceeded; try again later.' });
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok:true, product:PRODUCT });

    if (req.method === 'POST' && url.pathname === '/api/activate') {
      const b = await readJson(req);
      if (b.product !== PRODUCT || !validText(b.licenseKey, 128) || !validText(b.deviceId, 128))
        return send(res, 400, { valid:false, pro:false, message:'Missing or invalid product, license key, or device ID.' });
      const record = db.licenses.find(x => x.keyHash === hashKey(b.licenseKey.trim()));
      if (!record) return send(res, 200, { valid:false, pro:false, message:'License not found.' });
      if (record.revokedAt) return send(res, 200, { valid:false, pro:false, message:'License has been revoked.' });
      if (record.product !== PRODUCT) return send(res, 200, { valid:false, pro:false, message:'License is for a different product.' });
      if (record.expiresAt && Date.now() >= Date.parse(record.expiresAt)) return send(res, 200, { valid:false, pro:false, message:'License expired.' });
      if (!record.deviceId) { record.deviceId = b.deviceId; record.activatedAt = new Date().toISOString(); saveDb(); }
      if (record.deviceId !== b.deviceId) return send(res, 200, { valid:false, pro:false, message:'License is already bound to another device.' });
      record.lastVerifiedAt = new Date().toISOString(); saveDb();
      return send(res, 200, { valid:true, pro:true, product:PRODUCT, expiresAt:record.expiresAt || null, message:'License verified.' });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/licenses') {
      if (!admin(req)) return send(res, 401, { error:'Unauthorized' });
      const b = await readJson(req);
      const count = Number.isInteger(b.count) ? Math.max(1, Math.min(25, b.count)) : 1;
      const note = typeof b.note === 'string' ? b.note.slice(0,120) : '';
      const issued = [];
      for (let i=0; i<count; i++) {
        let key; let kh;
        do { key = newKey(); kh = hashKey(key); } while (db.licenses.some(x => x.keyHash === kh));
        db.licenses.push({ keyHash:kh, product:PRODUCT, plan:'lifetime', expiresAt:null, deviceId:null, createdAt:new Date().toISOString(), activatedAt:null, lastVerifiedAt:null, revokedAt:null, note });
        issued.push(key);
      }
      saveDb();
      return send(res, 201, { product:PRODUCT, plan:'lifetime', licenses:issued, warning:'Save these keys now. The server stores only their hashes and cannot display them again.' });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/revoke') {
      if (!admin(req)) return send(res, 401, { error:'Unauthorized' });
      const b = await readJson(req);
      if (!validText(b.licenseKey,128)) return send(res, 400, { error:'licenseKey required' });
      const record = db.licenses.find(x => x.keyHash === hashKey(b.licenseKey.trim()));
      if (!record) return send(res, 404, { error:'License not found' });
      record.revokedAt = new Date().toISOString(); saveDb();
      return send(res, 200, { ok:true, revokedAt:record.revokedAt });
    }
    return send(res, 404, { error:'Not found' });
  } catch (e) {
    console.error(e.message);
    if (!res.headersSent) send(res, 400, { valid:false, pro:false, message:'Invalid request.' });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log(`MJ VIP/PRO licensing API listening on :${PORT}`));
