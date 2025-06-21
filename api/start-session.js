import fetch from 'node-fetch';
import LRU from 'lru-cache';
import crypto from 'crypto';

const HYPERBEAM_API_KEY = process.env.HYPERBEAM_API_KEY;
const HYPERBEAM_API_URL = 'https://engine.hyperbeam.com/v0/sessions';
const RATE_LIMIT_MAX = 5;           // max requests
const RATE_LIMIT_WINDOW = 60_000;   // 1 minute
const SESSION_TTL = 5 * 60_000;     // 5 minutes

// In-memory caches for rate-limiting and sessions
const rateLimitCache = new LRU({ max: 1000, ttl: RATE_LIMIT_WINDOW }); 
const sessionCache = new LRU({ max: 1000, ttl: SESSION_TTL }); 

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // ---- CSRF Protection ----
  const cookieHeader = req.headers.cookie || '';
  const csrfToken = cookieHeader.split('; ').find(c => c.startsWith('csrf_token='))?.split('=')[1];
  const headerToken = req.headers['x-csrf-token'];
  if (!csrfToken || !headerToken || csrfToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' }); 
  }

  // ---- Rate Limiting ----
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const count = rateLimitCache.get(clientIp) || 0;
  if (count >= RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests, try again later.' }); 
  }
  rateLimitCache.set(clientIp, count + 1);

  // ---- Session Creation ----
  const resp = await fetch(HYPERBEAM_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${HYPERBEAM_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ /* any required session options here */ })
  });
  if (!resp.ok) {
    const error = await resp.text();
    return res.status(500).json({ error: `Hyperbeam error: ${error}` }); 
  }
  const data = await resp.json();

  // Save session with TTL
  sessionCache.set(data.session_id, { startedAt: Date.now() });
  
  res.json({ embedUrl: data.embed_url }); 
}
