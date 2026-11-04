const http = require('http');
const crypto = require('crypto');

function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function wafBlocked(v){if(!v)return false;return [/'\s*or\s/i,/union\s+select/i,/<script/i,/<iframe/i,/javascript:/i].some(p=>p.test(v));}

const vault = new Map();
function mask(p){return p.slice(0,4)+' **** **** '+p.slice(-4);}

http.createServer((req,res)=>{
  const u = new URL(req.url,'http://localhost');
  const q = u.searchParams.get('q')||'';

  if(u.pathname==='/vulnerable'){                 // BEFORE: raw reflection, no controls
    res.setHeader('Content-Type','text/html');
    res.end('<h1>Results for: '+q+'</h1>');
  } else if(u.pathname==='/encoded'){             // AFTER step 1: output encoding only
    res.setHeader('Content-Type','text/html');
    res.end('<h1>Results for: '+escapeHtml(q)+'</h1>');
  } else if(u.pathname==='/secure'){              // AFTER step 2: WAF + encoding + hardened headers
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'");
    res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('X-Frame-Options','DENY');
    if(wafBlocked(q)){ res.statusCode=403; res.setHeader('Content-Type','text/plain');
      return res.end('403 Forbidden: request blocked by WAF rule (injection/XSS pattern detected)');}
    res.setHeader('Content-Type','text/html');
    res.end('<h1>Results for: '+escapeHtml(q)+'</h1>');
  } else if(u.pathname==='/tokenize'){            // Tokenization + allowlist validation
    const pan=(u.searchParams.get('pan')||'').replace(/\s+/g,'');
    if(!/^\d{13,19}$/.test(pan)){ res.statusCode=400; res.setHeader('Content-Type','application/json');
      return res.end(JSON.stringify({error:'Invalid card number (allowlist validation failed)'}));}
    const token='tok_'+crypto.createHash('sha256').update(pan+Date.now()).digest('hex').slice(0,24);
    vault.set(token,pan);                          // production: PCI-scoped provider vault
    res.setHeader('Content-Type','application/json');
    res.end(JSON.stringify({stored_in_our_db:{token:token},raw_pan_stored:false,display:mask(pan)},null,2));
  } else {
    res.setHeader('Content-Type','text/html');
    res.end('<h2>Hardened E-Commerce Demo</h2><p>Paste these URLs:</p><pre>/vulnerable?q=...   /encoded?q=...   /secure?q=...   /tokenize?pan=...</pre>');
  }
}).listen(4000,()=>console.log('Hardened demo on http://localhost:4000'));