// monitor-demo.js — real-time auth monitoring with detection rules + active response
// Run: node monitor-demo.js  |  Test: http://localhost:4001/login?email=u@test.com&password=wrong
const http = require('http');
const fs = require('fs');

const WINDOW_MS = 60000;   // R1 detection window (production: 10 min)
const THRESHOLD = 5;       // R1 failed-login threshold
const BLOCK_MS  = 120000;  // active-response block duration

const attempts = new Map(); const blocked = new Map(); const fails = new Map();
const stamp = () => new Date().toISOString();
const write = (f, s) => fs.appendFileSync(f, s + '\n');

http.createServer((req, res) => {
  const ip = req.socket.remoteAddress;
  const u  = new URL(req.url, 'http://x');
  if (u.pathname !== '/login') { res.statusCode = 404; return res.end(); }

  // Active response: reject traffic from blocked sources
  if ((blocked.get(ip) || 0) > Date.now()) {
    const line = `[${stamp()}] BLOCKED   src=${ip} request rejected (auto-response active)`;
    console.log(line); write('auth.log', line);
    res.statusCode = 403;
    return res.end(JSON.stringify({ error: 'Forbidden - source IP blocked by monitoring auto-response' }));
  }

  const ok = u.searchParams.get('password') === 'Test123!';
  const line = `[${stamp()}] LOGIN ${ok ? 'SUCCESS' : 'FAILED '} src=${ip} user=${u.searchParams.get('email') || '-'}`;
  console.log(line); write('auth.log', line);

  if (!ok) {
    const now = Date.now();
    const arr = (attempts.get(ip) || []).filter(t => now - t < WINDOW_MS);
    arr.push(now); attempts.set(ip, arr); fails.set(ip, (fails.get(ip) || 0) + 1);
    // R1: brute force
    if (arr.length >= THRESHOLD) {
      blocked.set(ip, now + BLOCK_MS); attempts.set(ip, []);
      const a = `[${stamp()}] [ALERT][R1-BRUTE-FORCE] ${arr.length} failed logins in ${WINDOW_MS/1000}s from ${ip} -> ACTIVE RESPONSE: IP blocked ${BLOCK_MS/1000}s`;
      console.log(a); write('auth.log', a); write('alerts.log', a);
    }
  } else {
    // R2: success after failures = possible compromise
    if ((fails.get(ip) || 0) >= 3) {
      const a = `[${stamp()}] [ALERT][R2-ACCOUNT-COMPROMISE] successful login from ${ip} after ${fails.get(ip)} failures - verify user`;
      console.log(a); write('alerts.log', a);
    }
    fails.set(ip, 0);
    res.statusCode = 200;
    return res.end(JSON.stringify({ status: 'authenticated' }));
  }
  res.statusCode = 401;
  res.end(JSON.stringify({ status: 'invalid credentials' }));
}).listen(4001, () =>
  console.log(`Monitoring agent live on http://localhost:4001 | R1: >=${THRESHOLD} fails/60s/IP -> alert+block | R2: success-after-failures -> alert`));

