// auth-demo.js — MFA (TOTP, RFC 6238) + RBAC demonstration. Run: node auth-demo.js
const http = require('http');
const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s){let bits=0,val=0;const out=[];for(const c of s.toUpperCase()){const i=B32.indexOf(c);if(i<0)continue;val=(val<<5)|i;bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8;}}return Buffer.from(out);}
function totp(secret, off=0){const counter=Math.floor(Date.now()/30000)+off;const c=Buffer.alloc(8);c.writeUInt32BE(Math.floor(counter/2**32),0);c.writeUInt32BE(counter>>>0,4);const h=crypto.createHmac('sha1',secret).update(c).digest();const o=h[h.length-1]&0xf;const n=((h[o]&0x7f)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%1000000;return n.toString().padStart(6,'0');}
function verifyTotp(s,code){return [-1,0,1].some(o=>totp(s,o)===code);}
function randomSecret(){let s='';const b=crypto.randomBytes(20);for(const x of b)s+=B32[x%32];return s;}

const users={alice:{role:'customer',password:'Test123!'},bob:{role:'support',password:'Test123!'},carol:{role:'admin',password:'Test123!'}};
const mfa={};
const PERMS={view_own_orders:['customer','support','manager','admin'],view_any_order:['support','manager','admin'],issue_refunds:['support','manager','admin'],manage_products:['manager','admin'],manage_users:['admin']};

http.createServer((req,res)=>{
  const u=new URL(req.url,'http://x'); const q=u.searchParams; const user=q.get('user');
  res.setHeader('Content-Type','application/json');
  if(u.pathname==='/enroll'){
    if(!users[user]){res.statusCode=404;return res.end(JSON.stringify({error:'unknown user'}));}
    const secret=randomSecret(); mfa[user]=secret;
    return res.end(JSON.stringify({user,mfa_secret_base32:secret,
      otpauth_uri:`otpauth://totp/ECommerce:${user}?secret=${secret}&issuer=ECommerce&digits=6&period=30`,
      note:'Production: shown ONCE as QR code, stored encrypted',
      current_valid_code_demo:totp(b32decode(secret))},null,2));
  }
  if(u.pathname==='/login'){
    const rec=users[user];
    if(!rec){res.statusCode=404;return res.end(JSON.stringify({error:'unknown user'}));}
    if(q.get('password')!==rec.password){res.statusCode=401;return res.end(JSON.stringify({error:'invalid credentials'}));}
    const code=q.get('code')||'';
    if(!/^\d{6}$/.test(code)||!mfa[user]||!verifyTotp(b32decode(mfa[user]),code)){
      res.statusCode=401;return res.end(JSON.stringify({error:'MFA verification failed - invalid or expired code'}));}
    return res.end(JSON.stringify({status:'authenticated',user,role:rec.role,mfa:'verified (TOTP)'}));
  }
  if(u.pathname==='/action'){
    const rec=users[user]; const perm=q.get('perm');
    if(!rec){res.statusCode=404;return res.end(JSON.stringify({error:'unknown user'}));}
    if(!(PERMS[perm]||[]).includes(rec.role)){res.statusCode=403;
      return res.end(JSON.stringify({error:'Forbidden',detail:`role '${rec.role}' is not authorized for '${perm}' (RBAC deny-by-default)`}));}
    if(perm==='issue_refunds'){const amt=Number(q.get('amount')||0);
      if(rec.role==='support'&&amt>100){res.statusCode=403;
        return res.end(JSON.stringify({error:'Forbidden',detail:'support role refund limit is 100'}));}}
    return res.end(JSON.stringify({status:'allowed',user,role:rec.role,perm}));
  }
  res.end(JSON.stringify({demo:'MFA + RBAC',endpoints:['/enroll?user=','/login?user=&password=&code=','/action?user=&perm=&amount='],roles:'alice:customer, bob:support, carol:admin (password Test123!)'}));
}).listen(4002,()=>console.log('MFA+RBAC demo on http://localhost:4002 | TOTP 30s window (+-1 skew)'));