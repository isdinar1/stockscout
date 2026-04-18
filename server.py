#!/usr/bin/env python3
"""
StockScout — News-driven stock scanner.
Reads today's financial news, figures out what's happening in the world,
then finds small/mid-cap stocks in affected sectors that haven't moved yet.
No API key. No packages. Pure Python stdlib.
Run: python3 server.py
"""
import json, re, os, time, io, urllib.request, urllib.parse, html as htmllib
import zipfile, xml.etree.ElementTree as ET, sqlite3, hashlib, secrets, hmac, base64
import http.cookies, smtplib, random, threading
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed
import socketserver
import warnings
warnings.filterwarnings('ignore')
import yfinance as yf
import pdfplumber

# ── Live progress log (streamed to frontend during scan) ─────────────────────
_progress = []   # list of message strings for the current scan
_scan_done = False

def _log(msg):
    print(msg)
    _progress.append(msg)

# ── Auth / Database ───────────────────────────────────────────────────────────
# Sessions use HMAC-signed cookies — no DB lookup needed, survives server restarts.
# Users (email+pw) are stored in SQLite only for login verification.
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
DATABASE_URL = os.environ.get('DATABASE_URL', '')  # set automatically by Railway Postgres

# ── DB connection (Postgres on Railway, SQLite locally) ───────────────────────
def _pg():
    """Return a psycopg2 connection. Only called when DATABASE_URL is set."""
    import psycopg2
    return psycopg2.connect(DATABASE_URL)

def _get_conn():
    if DATABASE_URL:
        return _pg(), True   # (conn, is_postgres)
    return sqlite3.connect(DB), False

def _ph(is_pg):
    """Placeholder: %s for postgres, ? for sqlite."""
    return '%s' if is_pg else '?'

# Secret for signing session tokens.
def _load_secret():
    if os.environ.get('SESSION_SECRET'):
        return os.environ['SESSION_SECRET']
    _sf = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.session_secret')
    if os.path.exists(_sf):
        return open(_sf).read().strip()
    s = secrets.token_hex(32)
    try: open(_sf, 'w').write(s)
    except Exception: pass
    return s

SESSION_SECRET = _load_secret()

def init_db():
    conn, pg = _get_conn()
    ph = _ph(pg)
    try:
        if pg:
            conn.cursor().execute('''CREATE TABLE IF NOT EXISTS users (
                id    SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name  TEXT NOT NULL,
                pw    TEXT NOT NULL
            )''')
        else:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name  TEXT NOT NULL,
                pw    TEXT NOT NULL
            )''')
        conn.commit()
    finally:
        conn.close()

def _hash(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100_000)
    return f'{salt}:{h.hex()}'

def _verify(pw, stored):
    try:
        salt, h = stored.split(':')
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100_000).hex() == h
    except:
        return False

def create_user(contact, name, pw, pw_hash=None):
    """Insert user. Returns (id, name) or None if contact already exists."""
    hashed = pw_hash if pw_hash else _hash(pw)
    conn, pg = _get_conn()
    ph = _ph(pg)
    try:
        if pg:
            cur = conn.cursor()
            cur.execute(f'INSERT INTO users (email,name,pw) VALUES ({ph},{ph},{ph}) RETURNING id',
                        (contact, name, hashed))
            uid = cur.fetchone()[0]
        else:
            cur = conn.execute(f'INSERT INTO users (email,name,pw) VALUES ({ph},{ph},{ph})',
                               (contact, name, hashed))
            uid = cur.lastrowid
        conn.commit()
        return (uid, name)
    except Exception:
        return None
    finally:
        conn.close()

def check_user(contact, pw):
    """Returns (id, name) if credentials valid, else None."""
    conn, pg = _get_conn()
    ph = _ph(pg)
    try:
        if pg:
            cur = conn.cursor()
            cur.execute(f'SELECT id,name,pw FROM users WHERE email={ph}', (contact,))
            row = cur.fetchone()
        else:
            row = conn.execute(f'SELECT id,name,pw FROM users WHERE email={ph}', (contact,)).fetchone()
        if row and _verify(pw, row[2]):
            return (row[0], row[1])
        return None
    finally:
        conn.close()

# ── HMAC session tokens (self-contained, no DB needed) ───────────────────────
# Token format: base64( uid|name|expiry ) + '.' + hmac_sig

def new_session(uid, name):
    """Create a signed session cookie value encoding uid + name + expiry."""
    expiry  = int(time.time()) + 2_592_000          # 30 days
    payload = base64.urlsafe_b64encode(
        f'{uid}\x00{name}\x00{expiry}'.encode()
    ).decode().rstrip('=')
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    return f'{payload}.{sig}'

def session_info(token):
    """Verify token. Returns (uid, name) or None."""
    if not token or '.' not in token:
        return None
    try:
        payload, sig = token.rsplit('.', 1)
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(sig, expected):
            return None
        pad     = payload + '=' * (-len(payload) % 4)
        uid_str, name, expiry_str = base64.urlsafe_b64decode(pad).decode().split('\x00')
        if int(time.time()) > int(expiry_str):
            return None
        return (int(uid_str), name)
    except:
        return None

def get_cookie(headers):
    raw = headers.get('Cookie', '')
    if not raw: return None
    jar = http.cookies.SimpleCookie(raw)
    return jar['session'].value if 'session' in jar else None

# ── Verification codes (stored in memory, expire in 10 min) ──────────────────
_pending = {}  # token -> {name, contact, contact_type, pw, code, expires}

def is_phone(s):
    return bool(re.fullmatch(r'\d{3}-\d{3}-\d{4}', s.strip()))

def is_email(s):
    return '@' in s and '.' in s.split('@')[-1]

def create_pending(name, contact, pw):
    """Store pending signup with a 6-digit code. Returns (token, code)."""
    # Clean up expired entries
    now = time.time()
    for k in list(_pending.keys()):
        if _pending[k]['expires'] < now:
            del _pending[k]
    code  = str(random.randint(100000, 999999))
    token = secrets.token_hex(16)
    _pending[token] = {
        'name':    name,
        'contact': contact,
        'type':    'phone' if is_phone(contact) else 'email',
        'pw':      _hash(pw),
        'code':    code,
        'expires': now + 600,  # 10 minutes
    }
    return token, code

def get_all_subscribers():
    """Return list of (email, name) for all users with email addresses."""
    conn, pg = _get_conn()
    ph = _ph(pg)
    try:
        if pg:
            cur = conn.cursor()
            cur.execute('SELECT email, name FROM users')
            rows = cur.fetchall()
        else:
            rows = conn.execute('SELECT email, name FROM users').fetchall()
        # Only email addresses (not phone numbers)
        return [(r[0], r[1]) for r in rows if '@' in r[0]]
    except Exception as e:
        print(f'  [subscribers] {e}')
        return []
    finally:
        conn.close()


def send_alert_email(to_email, name, short_picks, long_picks):
    """Send a scan-results alert email via Brevo HTTP API (avoids SMTP port blocks)."""
    import json as _json
    import urllib.request as _req
    brevo_key = os.environ.get('BREVO_API_KEY', '')
    from_email = os.environ.get('SMTP_EMAIL', 'stock_scout@yahoo.com')
    site_url   = os.environ.get('SITE_URL', 'https://stockscout.up.railway.app')
    if not brevo_key:
        return False

    def pick_rows(picks, label, color):
        if not picks:
            return ''
        rows = ''
        for p in picks[:4]:
            congress = '<br><span style="color:#6366f1;font-size:.72rem;font-weight:600">🏛️ Congress confirmed</span>' if p.get('congressConfirmed') else ''
            rows += (
                f'<tr style="border-bottom:1px solid #e5e7eb">'
                f'<td style="padding:12px 10px;font-weight:800;font-size:1rem;color:{color};white-space:nowrap">${p["symbol"]}</td>'
                f'<td style="padding:12px 10px;color:#111827;font-weight:600;word-break:break-word">{p["name"]}{congress}</td>'
                f'<td style="padding:12px 10px;color:#374151;font-size:.85rem">{p["signal"]}</td>'
                f'<td style="padding:12px 10px;font-weight:700;white-space:nowrap;text-align:right">{p["score"]}/100</td>'
                f'</tr>'
            )
        return (
            f'<h3 style="margin:28px 0 10px;color:#111827;font-size:1rem">{label}</h3>'
            f'<table style="width:100%;border-collapse:collapse;background:#f9fafb;border-radius:8px;overflow:hidden;font-size:.88rem">'
            f'<tr style="background:#f3f4f6;font-size:.72rem;color:#6b7280;text-transform:uppercase;letter-spacing:.05em">'
            f'<th style="padding:8px 10px;text-align:left">Ticker</th>'
            f'<th style="padding:8px 10px;text-align:left">Company</th>'
            f'<th style="padding:8px 10px;text-align:left">Signal</th>'
            f'<th style="padding:8px 10px;text-align:right">Score</th></tr>'
            f'{rows}</table>'
        )

    html_body = f'''
<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:24px">
  <h1 style="color:#dc2626;margin-bottom:4px">📡 StockScout</h1>
  <p style="color:#6b7280;margin-top:0">Market Alert</p>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">
  <p style="color:#111827">Hi <b>{name}</b>,</p>
  <p style="color:#374151">Here are today's top stock picks based on world news and Congressional trading disclosures:</p>
  {pick_rows(short_picks, '⚡ Short Hold — Days to Weeks', '#d97706')}
  {pick_rows(long_picks,  '🏦 Long Hold — Weeks to Months', '#4f46e5')}
  <div style="text-align:center;margin:32px 0">
    <a href="{site_url}" style="background:#dc2626;color:#fff;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:1rem">
      View Full Analysis →
    </a>
  </div>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">
  <p style="color:#9ca3af;font-size:.75rem;text-align:center">
    ⚠️ Not financial advice. Always do your own research.<br>
    <a href="{site_url}/unsubscribe?email={urllib.parse.quote(to_email)}" style="color:#9ca3af">Unsubscribe</a>
  </p>
</div>'''

    payload = _json.dumps({
        'sender':  {'name': 'StockScout', 'email': from_email},
        'to':      [{'email': to_email, 'name': name}],
        'subject': f'📡 StockScout: {len(short_picks)+len(long_picks)} new picks',
        'htmlContent': html_body,
    }).encode()

    try:
        request = _req.Request(
            'https://api.brevo.com/v3/smtp/email',
            data=payload,
            headers={
                'api-key':      brevo_key,
                'Content-Type': 'application/json',
                'Accept':       'application/json',
            },
            method='POST'
        )
        with _req.urlopen(request, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        print(f'  [alert] Email to {to_email} failed: {e}')
        return False


def send_alerts_to_all(short_picks, long_picks):
    """Send scan-result emails to all subscribers in background threads."""
    subscribers = get_all_subscribers()
    if not subscribers:
        print('  [alert] No subscribers to notify')
        return
    sent, failed = 0, 0
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(send_alert_email, email, name, short_picks, long_picks): email
                   for email, name in subscribers}
        for f in as_completed(futures):
            if f.result():
                sent += 1
            else:
                failed += 1
    print(f'  [alert] Sent {sent} emails, {failed} failed')


def send_email_code(to_email, code, name):
    """Send verification code via Brevo HTTP API."""
    import json as _json, urllib.request as _req
    brevo_key  = os.environ.get('BREVO_API_KEY', '')
    from_email = os.environ.get('SMTP_EMAIL', 'issadinar@icloud.com')
    if not brevo_key:
        return False
    html_body = f'''
<div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px">
  <h1 style="color:#dc2626;margin-bottom:4px">📡 StockScout</h1>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">
  <p style="color:#111827">Hi <b>{name}</b>,</p>
  <p style="color:#374151;margin:16px 0">Your verification code is:</p>
  <div style="background:#f3f4f6;border-radius:12px;padding:24px;text-align:center;margin:20px 0">
    <span style="font-size:2.5rem;font-weight:900;letter-spacing:.4em;color:#111827">{code}</span>
  </div>
  <p style="color:#6b7280;font-size:.85rem">This code expires in 10 minutes. If you didn't sign up for StockScout, ignore this email.</p>
</div>'''
    payload = _json.dumps({
        'sender':      {'name': 'StockScout', 'email': from_email},
        'to':          [{'email': to_email, 'name': name}],
        'subject':     f'Your StockScout code: {code}',
        'htmlContent': html_body,
    }).encode()
    try:
        req = _req.Request(
            'https://api.brevo.com/v3/smtp/email',
            data=payload,
            headers={'api-key': brevo_key, 'Content-Type': 'application/json', 'Accept': 'application/json'},
            method='POST'
        )
        with _req.urlopen(req, timeout=15) as r:
            return r.status in (200, 201)
    except Exception as e:
        print(f'  [verify] Email code send failed: {e}')
        return False

# ── Shared page CSS ───────────────────────────────────────────────────────────
_PAGE_CSS = '''
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#07090f;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#0f1623;border:1px solid #1c2a40;border-radius:18px;padding:40px 44px;width:100%;max-width:420px}
.logo{text-align:center;margin-bottom:28px}
.logo h1{font-size:1.5rem;font-weight:800;color:#fff}
.logo p{color:#4b5e78;font-size:.85rem;margin-top:4px}
h2{font-size:1.1rem;font-weight:700;margin-bottom:8px;color:#fff}
.sub{color:#4b5e78;font-size:.82rem;margin-bottom:22px}
.field{margin-bottom:16px}
.field label{display:block;font-size:.78rem;color:#64748b;margin-bottom:6px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.field input{width:100%;background:#07090f;border:1px solid #1c2a40;border-radius:9px;color:#e2e8f0;font-size:.9rem;padding:11px 14px;outline:none;transition:border-color .2s}
.field input:focus{border-color:#3b82f6}
.btn{width:100%;background:linear-gradient(135deg,#1d4ed8,#1e40af);border:none;border-radius:10px;color:#fff;cursor:pointer;font-size:.95rem;font-weight:700;padding:13px;margin-top:6px;transition:opacity .2s}
.btn:hover{opacity:.88}
.switch{text-align:center;margin-top:20px;font-size:.82rem;color:#4b5e78}
.switch a{color:#60a5fa;text-decoration:none;font-weight:600}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:8px;color:#fca5a5;font-size:.82rem;padding:10px 14px;margin-bottom:16px}
.ok{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);border-radius:8px;color:#34d399;font-size:.82rem;padding:10px 14px;margin-bottom:16px}
.code-input{font-size:1.6rem;letter-spacing:.3em;text-align:center;font-weight:800}
'''

# ── Auth page HTML ────────────────────────────────────────────────────────────
def auth_page(mode='login', error=''):
    is_login = mode == 'login'
    title  = 'Sign In' if is_login else 'Create Account'
    action = '/login'  if is_login else '/signup'
    switch_text = "Don't have an account?" if is_login else 'Already have an account?'
    switch_link = '/signup' if is_login else '/login'
    switch_label = 'Sign up' if is_login else 'Sign in'
    name_field = '' if is_login else '''
      <div class="field">
        <label>Your name</label>
        <input type="text" name="name" placeholder="John Smith" required autocomplete="name"/>
      </div>'''
    contact_field = '''
      <div class="field">
        <label>Email</label>
        <input type="email" name="email" placeholder="you@example.com" required autocomplete="email"/>
      </div>'''
    err_html = f'<div class="err">{htmllib.escape(error)}</div>' if error else ''
    extra_css = ''
    extra_js = ''
    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>StockScout — {title}</title>
<style>{_PAGE_CSS}{extra_css}</style></head><body>
<div class="box">
  <div class="logo"><h1>📡 StockScout</h1><p>News-driven stock research</p></div>
  <h2>{title}</h2>
  {err_html}
  <form method="POST" action="{action}">
    {name_field}
    {contact_field}
    <div class="field">
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required minlength="6" autocomplete="{'current-password' if is_login else 'new-password'}"/>
    </div>
    <button class="btn" type="submit">{title}</button>
  </form>
  <div class="switch">{switch_text} <a href="{switch_link}">{switch_label}</a></div>
</div>
{extra_js}
</body></html>'''

# ── Verify page HTML ──────────────────────────────────────────────────────────
def verify_page(token, contact, error='', show_code=None):
    masked   = contact[:3] + '***' + contact[contact.index('@'):]
    err_html = f'<div class="err">{htmllib.escape(error)}</div>' if error else ''
    sent_msg = f'<p class="sub">We emailed a 6-digit code to <strong style="color:#e2e8f0">{htmllib.escape(masked)}</strong></p>'
    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>StockScout — Verify</title>
<style>{_PAGE_CSS}</style></head><body>
<div class="box">
  <div class="logo"><h1>📡 StockScout</h1><p>News-driven stock research</p></div>
  <h2>Check your email</h2>
  {sent_msg}
  {err_html}
  <form method="POST" action="/verify">
    <input type="hidden" name="token" value="{htmllib.escape(token)}"/>
    <div class="field">
      <label>Verification code</label>
      <input class="code-input" type="text" name="code" placeholder="000000"
             maxlength="6" pattern="[0-9]{{6}}" inputmode="numeric" required autofocus/>
    </div>
    <button class="btn" type="submit">Verify &amp; Create Account</button>
  </form>
  <div class="switch"><a href="/signup">← Use a different email</a></div>
</div>
</body></html>'''

# ── Sector candidate pools (small/mid cap focus) ──────────────────────────────
# These are stocks we screen when a relevant news theme fires.
# Deliberately excludes mega-caps (AAPL, MSFT, etc.) — they're already priced in.
SECTORS = {
    'oil':        ['OXY','DVN','SM','CIVI','MGY','VTLE','CPE','NOG','MTDR','CTRA','MRO','CLR'],
    'nat_gas':    ['AR','EQT','RRC','SWN','CNX','GPOR','CRK'],
    'defense':    ['KTOS','AVAV','DRS','VSEC','HEI','MOOG','TDY','AXON','LDOS','LMT','NOC','RTX','GD'],
    'semis':      ['WOLF','POWI','COHU','ONTO','ACLS','AMBA','CEVA','FORM','SITM','ALGM','NVDA','AMD','INTC','QCOM'],
    'gold':       ['AU','HL','CDE','EXK','AGI','MAG','GATO','SAND','ASA'],
    'uranium':    ['UEC','DNN','URG','UUUU','EU','LTBR','NXE'],
    'shipping':   ['SBLK','GOGL','NMM','GNK','SALT','EDRY','GRIN','EGLE'],
    'china':      ['BABA','JD','PDD','NIO','XPEV','LI','BILI','VIPS','TIGR'],
    'biotech':    ['SAVA','AGEN','SNDX','CTIC','ICAD','GLYC','PRME','APLT','AVDL','MRNA','BNTX','NVAX'],
    'pharma':     ['PFE','MRK','ABBV','BMY','LLY','JNJ','RHHBY','AZN','GILD','REGN','BIIB'],
    'solar':      ['ARRY','CSIQ','JKS','DAQO','RUN','NOVA','SHLS','FLNC'],
    'retail':     ['FIVE','GCO','PLCE','CATO','DXLG','PRTY','GOOS','BIG','CONN'],
    'reit':       ['NXRT','SAFE','GMRE','GOOD','NLCP','BRSP','CLNC','KREF'],
    'ev':         ['TSLA','RIVN','LCID','FSR','NKLA','GOEV','WKHS'],
    'steel':      ['CLF','X','CMC','STLD','ATI','HAYN','KALU'],
    'airlines':   ['SAVE','ALGT','HA','SY','SKYW','MESA','DAL','UAL','AAL','LUV'],
    'gaming':     ['ATVI','EA','TTWO','RBLX','MSFT','NTDOY','SNE','PLTK','GLBE','HOOK'],
    'streaming':  ['NFLX','DIS','PARA','WBD','AMZN','SPOT','FUBO','ROKU'],
    'social':     ['META','SNAP','PINS','TWTR','RDDT','BMBL','MTCH'],
    'crypto':     ['COIN','MSTR','RIOT','MARA','HUT','CLSK','BITF','BTBT'],
    'travel':     ['BKNG','EXPE','ABNB','TRIP','LYFT','UBER','GRAB'],
    'food':       ['BYND','APPH','APPS','SFM','HAIN','TTCF','BRFS','VERY'],
    'cybersec':   ['CRWD','S','PANW','ZS','FTNT','CYBR','TENB','VRNS','RPD'],
    'space':      ['RKLB','ASTS','LUNR','KTOS','VACQ','SPCE','MNTS','ASTR'],
    'cannabis':   ['TLRY','CGC','ACB','CURLF','GTBIF','TCNNF','CRLBF'],
    'weight_loss':['LLY','NVO','HIMS','GUTS','AMGN','VKTX','ZAFG','CGON'],
}

# ── Theme definitions ─────────────────────────────────────────────────────────
# Each theme: what keywords trigger it, what sectors go up/down, and why.
THEMES = [
    {
        'id': 'tariffs_trade_war',
        'icon': '🔒',
        'title': 'Trump Tariffs / Trade War',
        'detect': ['tariff','trade war','reciprocal tariff','import duty','trade deal','trade pause',
                   'trade truce','exemption tariff','tariff relief','trump trade','tariff rate'],
        'up': ['steel', 'defense'],
        'down': ['china', 'semis', 'solar', 'ev'],
        'logic': 'Tariffs hit companies with global supply chains hardest — Chinese ADRs, chipmakers, '
                 'solar, and EV makers face margin pressure. Domestic steel producers gain from import '
                 'protection. Any pause or exemption causes sharp relief rallies in the most-beaten names.',
    },
    {
        'id': 'oil_supply_tight',
        'icon': '🛢️',
        'title': 'Oil Supply Crunch',
        'detect': ['opec','opec+','production cut','oil supply','crude inventory','pipeline attack',
                   'iran sanction','oil embargo','tanker seized','oil output','barrel','wti crude'],
        'up': ['oil', 'nat_gas'],
        'down': [],
        'logic': 'When oil supply tightens (OPEC cuts, sanctions, pipeline disruptions), crude prices rise. '
                 'Small-cap E&P companies get the most leverage — a 10% oil price move can mean 30-50% earnings '
                 'swing for a small producer. Look for ones near their 52-week lows that haven\'t priced this in.',
    },
    {
        'id': 'geopolitical_calm',
        'icon': '🕊️',
        'title': 'Ceasefire / Peace Deal',
        'detect': ['ceasefire','peace deal','peace agreement','truce','hostage deal','hostage release',
                   'diplomatic','pullout','troop withdrawal','end of war','de-escalat'],
        'up': [],
        'down': ['oil', 'defense'],
        'logic': 'When conflicts ease, the geopolitical risk premium priced into oil fades — crude often drops '
                 '3-8% on ceasefire news. Defense contractors lose the urgency bid. These moves overshoot, '
                 'creating short-term pressure on oil and defense names.',
    },
    {
        'id': 'geopolitical_escalation',
        'icon': '⚠️',
        'title': 'Conflict / Escalation',
        'detect': ['military strike','attack on','airstrike','invasion','escalation','war escalat',
                   'troops deployed','conflict zone','missile attack','drone attack'],
        'up': ['oil', 'defense'],
        'down': ['airlines', 'shipping'],
        'logic': 'Rising military tensions spike oil risk premiums and lift defense expectations. '
                 'Airlines and shipping suffer from route disruptions and fuel cost spikes. '
                 'Defense names with government contracts are the most direct beneficiaries.',
    },
    {
        'id': 'fed_rate_cut',
        'icon': '📉',
        'title': 'Fed Rate Cut / Dovish Signal',
        'detect': ['rate cut','fed cut','lower rates','dovish','fed pivot','easing monetary',
                   'rate reduction','powell cut','fed eases','cut interest'],
        'up': ['gold', 'biotech', 'solar', 'reit', 'ev'],
        'down': [],
        'logic': 'Lower rates reduce the discount applied to future earnings — growth and speculative sectors '
                 'benefit most. Gold rises as real yields fall. Small-cap biotech and solar names, beaten '
                 'down during the rate-hike cycle, often see the sharpest reversals.',
    },
    {
        'id': 'fed_rate_hike',
        'icon': '📈',
        'title': 'Fed Rate Hike / Hawkish Signal',
        'detect': ['rate hike','tighten','hawkish','hot inflation','cpi above','inflation surge',
                   'fed hikes','higher for longer','rates stay high','inflation beats'],
        'up': [],
        'down': ['biotech', 'solar', 'reit', 'gold', 'ev'],
        'logic': 'Higher rates crush rate-sensitive sectors. Speculative biotech, clean energy, and REITs '
                 'get hit hardest. These selloffs often overshoot — high-quality names in these sectors '
                 'can become very cheap.',
    },
    {
        'id': 'china_trade_tension',
        'icon': '🇨🇳',
        'title': 'US-China Trade Tensions',
        'detect': ['tariff','trade war','china trade','trade tension','import duty','export ban',
                   'chip ban','trade restriction','china sanction','decoupling','china tariff'],
        'up': [],
        'down': ['china', 'semis'],
        'logic': 'Trade tensions compress Chinese ADR valuations and hit US chipmakers with China revenue. '
                 'These selloffs are often immediate overreactions — oversold China tech names with strong '
                 'fundamentals can snap back sharply on any sign of trade-talk progress.',
    },
    {
        'id': 'china_stimulus',
        'icon': '🇨🇳',
        'title': 'China Stimulus / Trade Thaw',
        'detect': ['china stimulus','trade deal','trade truce','trade talks','china reopening',
                   'tariff relief','china growth','china recovery','china economic'],
        'up': ['china', 'steel'],
        'down': [],
        'logic': 'China stimulus or trade thaw directly lifts Chinese ADRs and commodity demand. '
                 'Chinese tech and EV names often trade at extreme discounts to US peers — any '
                 'positive catalyst can cause sharp multiple re-rating.',
    },
    {
        'id': 'ai_chip_demand',
        'icon': '🤖',
        'title': 'AI Infrastructure Buildout',
        'detect': ['ai chip','data center','gpu demand','artificial intelligence spending','ai investment',
                   'ai capex','generative ai','llm','ai infrastructure','hyperscaler'],
        'up': ['semis'],
        'down': [],
        'logic': 'The AI infrastructure buildout creates sustained demand for semiconductors and power equipment. '
                 'Smaller chip companies that supply picks-and-shovels to AI hardware often trade at a big '
                 'discount to headline names like Nvidia — and have more room to run.',
    },
    {
        'id': 'nuclear_power',
        'icon': '⚛️',
        'title': 'Nuclear Energy Revival',
        'detect': ['nuclear','reactor','uranium','power demand','data center power','electricity grid',
                   'nuclear plant','smr','nuclear energy','clean power','grid capacity'],
        'up': ['uranium'],
        'down': [],
        'logic': 'AI data center electricity demand is driving a nuclear power renaissance. '
                 'Small uranium miners are the highest-leverage play — their stocks move 3-5x '
                 'the underlying uranium price. Many are still far below 2021 highs.',
    },
    {
        'id': 'gold_demand',
        'icon': '🥇',
        'title': 'Gold / Safe-Haven Demand',
        'detect': ['gold price','gold hits','precious metal','safe haven','dollar weakness',
                   'gold rally','gold record','bullion','gold surge','central bank gold'],
        'up': ['gold'],
        'down': [],
        'logic': 'Gold miners provide 2-3x leverage to gold price moves. Junior miners that haven\'t '
                 'yet caught up to the gold price rally offer the most asymmetric setups. '
                 'Look for ones near their 52-week lows while gold itself is near highs.',
    },
    {
        'id': 'shipping_disruption',
        'icon': '🚢',
        'title': 'Shipping Route Disruption',
        'detect': ['freight rate','container ship','shipping route','red sea','suez canal',
                   'panama canal','bulk carrier','shipping disruption','port congestion','tanker route'],
        'up': ['shipping'],
        'down': ['airlines'],
        'logic': 'Shipping route disruptions (Red Sea, Panama Canal) spike freight rates dramatically. '
                 'Dry bulk shipping company earnings have direct leverage to spot rates. '
                 'Stocks typically lag the actual rate move by days to weeks.',
    },
    {
        'id': 'consumer_spending',
        'icon': '🛍️',
        'title': 'Consumer Spending Surge',
        'detect': ['consumer spending','retail sales beat','consumer confidence','strong spending',
                   'consumer sentiment','record retail','holiday sales','consumer strong'],
        'up': ['retail'],
        'down': [],
        'logic': 'Better consumer spending data lifts beaten-down specialty retailers. '
                 'Small-cap retailers with high short interest can see outsized moves '
                 'when macro fears ease. Look for ones already at 52-week lows.',
    },
    {
        'id': 'steel_infrastructure',
        'icon': '🏗️',
        'title': 'Infrastructure / Steel Demand',
        'detect': ['infrastructure bill','infrastructure spending','steel demand','construction boom',
                   'building permits','housing starts','reshoring','manufacturing comeback'],
        'up': ['steel'],
        'down': [],
        'logic': 'Infrastructure spending cycles directly boost domestic steel demand. '
                 'Mid-cap US steel producers benefit from both volume increases and '
                 'anti-dumping protection from imports.',
    },
    {
        'id': 'gaming_release',
        'icon': '🎮',
        'title': 'Major Game Release / Gaming Surge',
        'detect': ['gta 6','grand theft auto','gta vi','call of duty','game release','gaming revenue',
                   'playstation','xbox','nintendo','video game sales','gaming record','esports',
                   'fortnite','minecraft','game launch','gaming stock','take-two','rockstar games',
                   'activision','ea sports','game sales','console launch'],
        'up': ['gaming'],
        'down': [],
        'logic': 'Major game releases drive massive spikes in revenue for publishers and platform holders. '
                 'GTA 6, Call of Duty, or console launches can move gaming stocks 10-30%. '
                 'Cross-reference with Congress members who hold gaming stocks.',
    },
    {
        'id': 'streaming_content',
        'icon': '🎬',
        'title': 'Streaming / Entertainment Surge',
        'detect': ['netflix','streaming','disney plus','hbo max','subscriber growth','content deal',
                   'box office','movie release','hollywood','entertainment spending','streaming wars',
                   'cord cutting','streaming revenue','paramount','warner bros','apple tv'],
        'up': ['streaming'],
        'down': [],
        'logic': 'Blockbuster content, subscriber beats, or major content deals move streaming stocks sharply. '
                 'Subscriber growth surprises are the single biggest catalyst for streaming valuations.',
    },
    {
        'id': 'drug_approval',
        'icon': '💊',
        'title': 'FDA Drug Approval / Medical Breakthrough',
        'detect': ['fda approval','fda approves','drug approved','clinical trial','phase 3','breakthrough therapy',
                   'new medicine','cancer treatment','alzheimer','diabetes drug','weight loss drug',
                   'ozempic','wegovy','glp-1','drug trial','medical breakthrough','fda clears',
                   'new treatment','cure','vaccine approved','drug application'],
        'up': ['pharma', 'biotech', 'weight_loss'],
        'down': [],
        'logic': 'FDA approvals can double or triple biotech stocks overnight. Weight loss drugs (GLP-1) '
                 'are reshaping pharma. Cancer and Alzheimer breakthroughs move entire sectors. '
                 'Congress members often hold pharma stocks ahead of key decisions.',
    },
    {
        'id': 'crypto_surge',
        'icon': '₿',
        'title': 'Crypto / Bitcoin Rally',
        'detect': ['bitcoin','crypto','ethereum','btc','cryptocurrency','coinbase','digital asset',
                   'crypto rally','bitcoin price','crypto adoption','blockchain','defi','nft',
                   'bitcoin etf','crypto regulation','stablecoin','solana','crypto bull'],
        'up': ['crypto'],
        'down': [],
        'logic': 'Bitcoin price moves drag the entire crypto ecosystem. Mining stocks move 2-3x BTC. '
                 'Coinbase revenue is directly tied to trading volume which spikes in bull runs.',
    },
    {
        'id': 'cybersecurity_threat',
        'icon': '🔐',
        'title': 'Cyberattack / Security Threat',
        'detect': ['cyberattack','ransomware','data breach','hack','cybersecurity','cyber threat',
                   'nation state attack','infrastructure hack','cybercrime','security breach',
                   'zero day','malware','phishing attack','cyber warfare'],
        'up': ['cybersec'],
        'down': [],
        'logic': 'High-profile cyberattacks drive immediate government and corporate spending on security. '
                 'Cybersecurity stocks often jump 5-15% following major breach news as companies '
                 'rush to upgrade their defenses.',
    },
    {
        'id': 'space_launch',
        'icon': '🚀',
        'title': 'Space / Satellite News',
        'detect': ['spacex','rocket launch','satellite','nasa','space station','lunar','moon mission',
                   'space contract','rocket lab','asts','starlink','space force','orbit','space exploration',
                   'space economy','space tourism','space defense'],
        'up': ['space', 'defense'],
        'down': [],
        'logic': 'Space contracts and successful launches are major catalysts for small-cap space stocks. '
                 'Companies like Rocket Lab and AST SpaceMobile can move 20-50% on contract news.',
    },
    {
        'id': 'social_media',
        'icon': '📱',
        'title': 'Social Media / Tech Platform News',
        'detect': ['tiktok','instagram','facebook','meta','snapchat','twitter','x.com','reddit',
                   'social media','ad revenue','user growth','platform ban','tiktok ban',
                   'social platform','influencer','viral','algorithm'],
        'up': ['social'],
        'down': [],
        'logic': 'Platform bans, ad revenue beats, or user growth surprises move social media stocks sharply. '
                 'A TikTok ban directly benefits Meta, Snap, and Pinterest as users migrate.',
    },
    {
        'id': 'travel_boom',
        'icon': '✈️',
        'title': 'Travel / Tourism Boom',
        'detect': ['travel demand','airline','hotel','tourism','vacation','summer travel','travel record',
                   'airfare','booking','uber','lyft','travel surge','international travel',
                   'cruise','resort','hospitality'],
        'up': ['travel', 'airlines'],
        'down': [],
        'logic': 'Travel demand surges post-disruption create outsized moves in travel stocks. '
                 'Booking platforms and airlines with high operating leverage see the biggest earnings swings.',
    },
    {
        'id': 'weight_loss_drugs',
        'icon': '⚕️',
        'title': 'Weight Loss / GLP-1 Drug News',
        'detect': ['ozempic','wegovy','glp-1','semaglutide','tirzepatide','mounjaro','weight loss drug',
                   'obesity drug','diabetes treatment','eli lilly','novo nordisk','hims','weight loss pill',
                   'appetite suppressant','bariatric'],
        'up': ['weight_loss', 'pharma'],
        'down': ['food'],
        'logic': 'GLP-1 weight loss drugs are the biggest pharma story. New approvals, trial results, '
                 'or generic competition moves the entire space. Eli Lilly and Novo Nordisk are the '
                 'dominant players but smaller competitors offer higher upside.',
    },
]

# ── HTTP helpers (news only — stock data goes through yfinance) ───────────────

UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'

def fetch_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f'  [fetch_json] {url[:70]}… → {e}')
        return None

def fetch_text(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'text/html,*/*'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f'  [fetch_text] {url[:70]}… → {e}')
        return ''

# ── Congress member photo lookup ──────────────────────────────────────────────

_legislators_cache = None
_legislators_ts    = 0

def get_legislators_map():
    """Fetch current legislators JSON → {normalized_name: bioguide_id}. Cached 24h."""
    global _legislators_cache, _legislators_ts
    if _legislators_cache is not None and time.time() - _legislators_ts < 86400:
        return _legislators_cache
    try:
        req = urllib.request.Request(
            'https://unitedstates.github.io/congress-legislators/legislators-current.json',
            headers={'User-Agent': UA}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        mapping = {}
        for leg in data:
            bio_id = leg.get('id', {}).get('bioguide', '')
            if not bio_id:
                continue
            n = leg.get('name', {})
            first = n.get('first', '')
            last  = n.get('last', '')
            full  = n.get('official_full', f'{first} {last}')
            for key in [full.lower(), f'{first} {last}'.lower(), f'{last}, {first}'.lower()]:
                if key.strip():
                    mapping[key.strip()] = bio_id
        _legislators_cache = mapping
        _legislators_ts    = time.time()
        print(f'  [legislators] loaded {len(mapping)} name entries')
        return mapping
    except Exception as e:
        print(f'  [legislators] fetch failed: {e}')
        _legislators_cache = {}
        return {}

def member_photo_url(name, leg_map):
    """Return theunitedstates.io photo URL for a congress member name, or ''."""
    if not leg_map or not name:
        return ''
    nl = name.lower().strip()
    if nl in leg_map:
        return f'https://raw.githubusercontent.com/unitedstates/images/gh-pages/congress/225x275/{leg_map[nl]}.jpg'
    parts = nl.split()
    if len(parts) >= 2:
        # Try "Last, First" and reversed
        for attempt in [f'{parts[-1]}, {parts[0]}', f'{parts[0]} {parts[-1]}',
                         f'{" ".join(parts[1:])} {parts[0]}']:
            if attempt in leg_map:
                return f'https://raw.githubusercontent.com/unitedstates/images/gh-pages/congress/225x275/{leg_map[attempt]}.jpg'
        # Last-name-only fallback
        last = parts[-1]
        for key, bio_id in leg_map.items():
            if key.split()[-1] == last or key.startswith(last + ','):
                return f'https://raw.githubusercontent.com/unitedstates/images/gh-pages/congress/225x275/{bio_id}.jpg'
    return ''

# ── Congress trading data ─────────────────────────────────────────────────────

_congress_cache = None   # {ticker: [{name, date, type, amount, photo}, ...]}
_congress_ts    = 0

TICKER_IN_PDF = re.compile(r'\(([A-Z]{1,6})\)')  # matches "(NFLX)" style tickers in PDFs

def _parse_ptr_pdf(pdf_bytes, member_name):
    """Extract trades from a House PTR PDF. Returns list of trade dicts."""
    trades = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            full = '\n'.join(page.extract_text() or '' for page in pdf.pages)
        # Remove null bytes (common in these PDFs)
        full = full.replace('\x00', '')
        lines = full.split('\n')
        date_re = re.compile(r'\b(\d{2}/\d{2}/\d{4})\b')
        for line in lines:
            tickers = TICKER_IN_PDF.findall(line)
            if not tickers:
                continue
            trade_type = 'P' if ' P ' in line or line.strip().endswith(' P') else (
                         'S' if ' S ' in line or line.strip().endswith(' S') else None)
            if not trade_type:
                if 'Purchase' in line: trade_type = 'P'
                elif 'Sale' in line or 'Sell' in line: trade_type = 'S'
            if not trade_type:
                continue
            dates = date_re.findall(line)
            trade_date = dates[0] if dates else ''
            for tk in tickers:
                if len(tk) < 1 or len(tk) > 6:
                    continue
                trades.append({
                    'name':   member_name,
                    'ticker': tk,
                    'type':   'Buy' if trade_type == 'P' else 'Sell',
                    'date':   trade_date,
                })
    except Exception as e:
        pass
    return trades

def get_congress_trades(max_ptrs=15):
    """
    Download recent House PTR filings and extract stock trades.
    Returns {ticker: [list of trades]} for all tickers found.
    Cached for 12 hours.
    """
    global _congress_cache, _congress_ts
    if _congress_cache is not None and time.time() - _congress_ts < 43200:
        return _congress_cache

    _log('📂  Downloading House disclosure index (2026FD.zip)...')
    try:
        req = urllib.request.Request(
            'https://disclosures-clerk.house.gov/public_disc/financial-pdfs/2026FD.zip',
            headers={'User-Agent': UA}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            zdata = r.read()
        zf   = zipfile.ZipFile(io.BytesIO(zdata))
        root = ET.fromstring(zf.read('2026FD.xml'))
    except Exception as e:
        _log(f'⚠️  Could not reach House disclosure system: {e}')
        _congress_cache = {}
        return {}

    ptrs = [(m.findtext('Last',''), m.findtext('First',''), m.findtext('DocID',''), m.findtext('FilingDate',''))
            for m in root.findall('.//Member') if m.findtext('FilingType') == 'P']
    ptrs.sort(key=lambda x: x[3], reverse=True)
    ptrs = ptrs[:max_ptrs]
    _log(f'📄  Reading {len(ptrs)} recent trade disclosure PDFs...')

    leg_map = get_legislators_map()

    def fetch_ptr(args):
        idx, (last, first, doc_id, filed) = args
        member = f'{first} {last}'
        photo  = member_photo_url(member, leg_map)
        try:
            req2 = urllib.request.Request(
                f'https://disclosures-clerk.house.gov/public_disc/ptr-pdfs/2026/{doc_id}.pdf',
                headers={'User-Agent': UA}
            )
            with urllib.request.urlopen(req2, timeout=15) as r2:
                pdf_bytes = r2.read()
            trades = _parse_ptr_pdf(pdf_bytes, member)
            for t in trades:
                t['photo'] = photo
            _log(f'📄  [{idx+1}/{len(ptrs)}] {member} — {len(trades)} trade(s) found')
            return trades
        except Exception:
            return []

    ticker_trades = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for trades in ex.map(fetch_ptr, enumerate(ptrs)):
            for trade in trades:
                tk = trade['ticker']
                if tk not in ticker_trades:
                    ticker_trades[tk] = []
                ticker_trades[tk].append(trade)

    buys  = sum(1 for trades in ticker_trades.values() for t in trades if t['type']=='Buy')
    sells = sum(1 for trades in ticker_trades.values() for t in trades if t['type']=='Sell')
    print(f'  [congress] Found {len(ticker_trades)} tickers — {buys} buys, {sells} sells')

    _congress_cache = ticker_trades
    _congress_ts    = time.time()
    return ticker_trades

def congress_signal(ticker, trades):
    """Return a human-readable congress trading signal for a ticker."""
    buys  = [t for t in trades if t['type'] == 'Buy']
    sells = [t for t in trades if t['type'] == 'Sell']
    parts = []
    if buys:
        names = list({t['name'] for t in buys})[:3]
        parts.append(f"🏛️ {', '.join(names)} {'bought' if len(buys)==1 else f'({len(buys)} members bought)'}")
    if sells:
        names = list({t['name'] for t in sells})[:2]
        parts.append(f"sold by {', '.join(names)}")
    return ' | '.join(parts)


# ── News fetching ─────────────────────────────────────────────────────────────

def get_news():
    headlines = []
    seen = set()

    def add(title, summary=''):
        t = htmllib.unescape(title).strip()
        if t and t not in seen and len(t) > 15:
            seen.add(t)
            headlines.append({'title': t, 'summary': htmllib.unescape(summary).strip()})

    def parse_rss(text):
        if not text:
            return
        # Try structured XML first
        try:
            root = ET.fromstring(text)
            for item in root.findall('.//item'):
                add(item.findtext('title',''), item.findtext('description',''))
            return
        except Exception:
            pass
        # Regex fallback for malformed XML
        for m in re.finditer(r'<title>(?:<!\[CDATA\[)?([^\]<]{15,})(?:\]\]>)?</title>', text):
            add(m.group(1))

    # Fetch all RSS feeds in parallel
    google_queries = [
        # Markets & macro
        'oil prices OPEC tariffs stock market',
        'federal reserve interest rates inflation',
        'china tariffs trade war sanctions',
        'gold price rally safe haven',
        'nuclear uranium energy AI data center',
        'shipping freight rates Red Sea',
        # Tech & gaming
        'GTA 6 grand theft auto rockstar games release date',
        'video game sales gaming revenue console launch',
        'nvidia AMD semiconductors chip demand AI',
        'cybersecurity hack ransomware data breach',
        'bitcoin crypto ethereum rally regulation',
        # Entertainment & streaming
        'netflix disney streaming subscriber revenue',
        'box office movie release hollywood entertainment',
        'tiktok instagram meta social media ad revenue',
        # Pharma & medicine
        'FDA approval drug trial breakthrough medicine',
        'ozempic wegovy GLP-1 weight loss drug eli lilly',
        'cancer treatment alzheimer vaccine clinical trial',
        # Space & defense
        'spacex rocket launch satellite NASA contract',
        'defense military contract lockheed northrop',
        # Travel & consumer
        'airline travel demand booking uber lyft',
        'retail consumer spending earnings',
        # Geopolitical
        'ceasefire war conflict escalation military',
        'ukraine russia israel iran middle east',
    ]
    urls = [f'https://news.google.com/rss/search?q={urllib.parse.quote(q)}&hl=en-US&gl=US&ceid=US:en'
            for q in google_queries]
    with ThreadPoolExecutor(max_workers=6) as ex:
        for text in ex.map(fetch_text, urls):
            parse_rss(text)

    print(f'  [news] {len(headlines)} headlines fetched')
    return headlines

# ── Theme detection ───────────────────────────────────────────────────────────

def detect_themes(headlines):
    """Match headlines against themes. Returns list of (theme, matching_headlines)."""
    corpus = ' '.join((h['title'] + ' ' + h.get('summary','')).lower() for h in headlines)

    scored = []
    for theme in THEMES:
        hits = sum(1 for kw in theme['detect'] if kw in corpus)
        if hits > 0:
            relevant = []
            for h in headlines:
                text = (h['title'] + ' ' + h.get('summary','')).lower()
                if any(kw in text for kw in theme['detect']):
                    relevant.append(h)
                    if len(relevant) >= 3:
                        break
            scored.append((theme, hits, relevant))

    scored.sort(key=lambda x: -x[1])
    print(f'  [themes] detected: {[t["id"] for t,_,_ in scored[:5]]}')
    return [(t, r) for t, _, r in scored[:5]]  # top 5 themes

# ── Stock data via yfinance ───────────────────────────────────────────────────

def batch_fetch(symbols):
    """
    Fetch price/technicals for all symbols at once using yfinance.
    yfinance handles cookies/sessions — no rate limit issues.
    Returns {symbol: chart_dict}.
    """
    results = {}
    try:
        tickers = yf.Tickers(' '.join(symbols))
        hist = tickers.history(period='1y', auto_adjust=True, progress=False)
        # hist is a MultiIndex DataFrame: (field, symbol)
        closes_all  = hist.get('Close',  None)
        volumes_all = hist.get('Volume', None)

        for sym in symbols:
            try:
                closes  = closes_all[sym].dropna().tolist()  if closes_all  is not None and sym in closes_all.columns  else []
                volumes = volumes_all[sym].dropna().tolist() if volumes_all is not None and sym in volumes_all.columns else []
                if len(closes) < 30:
                    continue

                curr = closes[-1]
                hi52 = max(closes)
                lo52 = min(closes)
                w52  = (curr - lo52) / (hi52 - lo52) if hi52 != lo52 else 0.5
                chg5 = (curr / closes[-6] - 1) * 100 if len(closes) > 5 else 0

                avg_vol = sum(volumes[-20:]) / 20 if len(volumes) >= 20 else 1
                vol_r   = (volumes[-1] / avg_vol) if avg_vol and volumes else 1.0

                d = [closes[i] - closes[i-1] for i in range(1, len(closes))]
                g = sum(max(x, 0) for x in d[-14:]) / 14
                l = sum(max(-x, 0) for x in d[-14:]) / 14
                rsi_val = 100 - 100 / (1 + g / l) if l > 0 else 100.0

                # Pull name + market cap from fast_info (no extra network call)
                fi   = tickers.tickers[sym].fast_info if hasattr(tickers, 'tickers') else None
                name = sym
                mc   = 0
                try:
                    if fi:
                        mc   = getattr(fi, 'market_cap', 0) or 0
                except Exception:
                    pass

                results[sym] = {
                    'price':  round(curr, 2),
                    'hi52':   round(hi52, 2),
                    'lo52':   round(lo52, 2),
                    'w52':    w52,
                    'chg5':   round(chg5, 1),
                    'vol_r':  round(vol_r, 1),
                    'rsi':    round(rsi_val, 1),
                    'name':   name,
                    'mc':     mc,
                    'closes': [round(c, 2) for c in closes[-90:]],  # 90-day chart
                }
            except Exception as e:
                pass
    except Exception as e:
        print(f'  [batch_fetch] {e}')
    return results

def enrich_top(symbols, chart_cache=None):
    """Return name + market cap. Uses data already in chart_cache when available."""
    out = {}
    if chart_cache:
        for sym in symbols:
            ch = chart_cache.get(sym, {})
            out[sym] = {'name': ch.get('name', sym), 'mc': ch.get('mc', 0)}
        # Fill in any missing ones with a fast yfinance lookup
        missing = [s for s in symbols if not out.get(s, {}).get('name') or out[s]['name'] == s]
    else:
        missing = symbols

    if missing:
        try:
            for sym in missing:
                try:
                    t    = yf.Ticker(sym)
                    info = t.info
                    name = info.get('longName') or info.get('shortName') or sym
                    mc   = info.get('marketCap', 0) or 0
                    out[sym] = {'name': name, 'mc': mc}
                except Exception:
                    out[sym] = {'name': sym, 'mc': 0}
        except Exception as e:
            print(f'  [enrich] {e}')
    return out

# ── Helpers ───────────────────────────────────────────────────────────────────

def cap_label(mc):
    if not mc:      return 'Unknown'
    if mc >= 10e9:  return 'Large Cap'
    if mc >= 2e9:   return 'Mid Cap'
    if mc >= 300e6: return 'Small Cap'
    if mc >= 50e6:  return 'Micro Cap'
    return 'Nano Cap'

def fmt_mc(mc):
    if mc >= 1e9:  return f'${mc/1e9:.1f}B'
    if mc >= 1e6:  return f'${mc/1e6:.0f}M'
    return f'~${mc:.0f}'

# ── Per-stock analysis ────────────────────────────────────────────────────────

def analyze(symbol, theme, direction, ch, mc=0):
    """Score a stock given pre-fetched chart data `ch` and optional market cap `mc`."""
    if not ch:
        return None

    price     = ch['price']
    w52       = ch['w52']
    rsi       = ch['rsi']
    chg5      = ch['chg5']
    vol_r     = ch['vol_r']
    name      = ch.get('name', symbol)
    target    = 0
    short_pct = 0

    score = 50

    # ── Direction-specific scoring ─────────────────────────────────────────
    if direction == 'up':
        # Want: near 52w LOW (hasn't priced in the tailwind yet)
        if   w52 < 0.15: score += 30
        elif w52 < 0.30: score += 20
        elif w52 < 0.45: score += 10
        elif w52 > 0.80: score -= 28  # already pumped on this theme
        elif w52 > 0.65: score -= 12

        # Oversold RSI = more room to bounce
        if   rsi < 28: score += 20
        elif rsi < 38: score += 12
        elif rsi < 48: score += 5
        elif rsi > 70: score -= 10

        # Already ran hard this week = probably too late
        if   chg5 > 20: score -= 20
        elif chg5 > 12: score -= 10
        elif chg5 > 6:  score -= 4
        elif -4 < chg5 < 4: score += 8   # flat/quiet = market hasn't noticed

        # Short squeeze potential
        if   short_pct > 0.25: score += 16
        elif short_pct > 0.15: score += 9
        elif short_pct > 0.10: score += 4

    elif direction == 'down':
        # Want: near 52w HIGH (most to fall)
        if   w52 > 0.85: score += 28
        elif w52 > 0.70: score += 14
        elif w52 < 0.25: score -= 22  # already sold off
        elif w52 < 0.40: score -= 10

        # Overbought RSI
        if   rsi > 72: score += 16
        elif rsi > 62: score += 8
        elif rsi < 40: score -= 12

        if chg5 > 15: score += 8   # still rising, likely to reverse
        if chg5 < -12: score -= 15  # already falling hard

    # ── Universal factors ──────────────────────────────────────────────────
    # Smaller cap = more leverage (and less likely to be priced in by institutions)
    if   mc < 200e6: score += 22
    elif mc < 500e6: score += 15
    elif mc < 2e9:   score += 8
    elif mc < 8e9:   score += 2
    elif mc > 25e9:  score -= 12

    # Volume spike = something's happening
    if   vol_r > 3.0: score += 14
    elif vol_r > 2.0: score += 8
    elif vol_r > 1.5: score += 4

    # Analyst upside (for up plays)
    upside = (target - price) / price * 100 if target and price else 0
    if direction == 'up':
        if   upside > 60: score += 16
        elif upside > 35: score += 10
        elif upside > 15: score += 5
        elif upside < -5: score -= 8

    score = max(0, min(100, int(score)))
    if score < 46:
        return None

    # ── Build explanation ──────────────────────────────────────────────────
    parts = []
    if direction == 'up':
        if w52 < 0.30:
            parts.append(
                f"it's near its 52-week low ({int(w52*100)}% of its annual range) — "
                f"the market hasn't priced in the sector tailwind yet"
            )
        if mc and mc < 2e9:
            parts.append(
                f"as a {cap_label(mc)} ({fmt_mc(mc)}), it gets more leverage than large peers "
                f"when this sector moves"
            )
        if rsi < 40:
            parts.append(f"technically oversold (RSI {rsi}) — due for a bounce")
        if short_pct > 0.15:
            parts.append(
                f"{int(short_pct*100)}% of the float is short — any positive news "
                f"could trigger a short squeeze on top of the sector move"
            )
        if upside > 20 and target:
            parts.append(f"analysts target ${round(target,2)} ({int(upside)}% above current price)")
        if -4 < chg5 < 4:
            parts.append("flat price action this week — the market hasn't noticed yet")

    elif direction == 'down':
        if w52 > 0.70:
            parts.append(
                f"trading near its 52-week high ({int(w52*100)}% of its range) — "
                f"likely to pull back as the sector headwind hits"
            )
        if rsi > 65:
            parts.append(f"technically overbought (RSI {rsi})")
        if mc and mc < 2e9:
            parts.append(f"{cap_label(mc)} — moves faster and harder than large caps")

    why = f'{name} is a {direction.upper()} play tied to the {theme["title"]} story'
    if parts:
        why += ': ' + '; '.join(parts[:3])

    # Signal label
    if   score >= 74: sig, sc = 'Strong Setup',   'strong'
    elif score >= 62: sig, sc = 'Worth Watching',  'moderate'
    elif score >= 46: sig, sc = 'On Radar',        'watch'
    else:             sig, sc = 'Cautious',        'caution'

    stats = {
        '52w pos': f'{int(w52*100)}%',
        'RSI':     str(rsi),
        '5d':      f'{chg5:+.1f}%',
    }
    if mc:              stats['cap'] = fmt_mc(mc)
    if vol_r > 1.2:     stats['vol'] = f'{vol_r:.1f}x avg'

    return {
        'symbol':         symbol,
        'name':           name,
        'price':          price,
        'target':         None,
        'upsidePct':      None,
        'score':          score,
        'signal':         sig,
        'sigClass':       sc,
        'capLabel':       cap_label(mc),
        'why':            why,
        'topNews':        [],
        'stats':          stats,
        'direction':      direction,
        'closes':         ch.get('closes', []),
    }

# ── Per-stock news fetch ──────────────────────────────────────────────────────

def fetch_stock_news(symbol, company_name=''):
    """Fetch recent news headlines for a specific stock symbol."""
    headlines = []
    seen = set()
    queries = [f'${symbol} stock', f'{company_name} stock' if company_name else symbol]
    for q in queries[:2]:
        enc = urllib.parse.quote(q)
        text = fetch_text(f'https://news.google.com/rss/search?q={enc}&hl=en-US&gl=US&ceid=US:en')
        if not text:
            continue
        try:
            root = ET.fromstring(text)
            for item in root.findall('.//item'):
                t = htmllib.unescape(item.findtext('title', '')).strip()
                if t and t not in seen and len(t) > 15:
                    seen.add(t)
                    headlines.append(t)
        except Exception:
            pass
    return headlines[:8]

POS_WORDS = ['beat','surge','rally','growth','record','strong','upgrade','buy','bullish',
             'profit','revenue','gains','rises','jumps','soars','outperform','positive']
NEG_WORDS = ['miss','fall','decline','cut','downgrade','sell','weak','loss','bearish',
             'drops','slides','plunges','warning','risk','concern','lawsuit','investigation']

def news_sentiment(headlines):
    """Returns (score -30..+30, supporting_headlines[])"""
    pos, neg, supporting = 0, 0, []
    for h in headlines:
        hl = h.lower()
        p = sum(1 for w in POS_WORDS if w in hl)
        n = sum(1 for w in NEG_WORDS if w in hl)
        if p > n:
            pos += 1
            supporting.append(h)
        elif n > p:
            neg += 1
    return min(30, (pos - neg) * 8), supporting[:3]

# ── News-first helpers ────────────────────────────────────────────────────────

def fetch_trending_tickers(max_n=25):
    """Pull trending + most-active US tickers from Yahoo Finance (no key needed)."""
    tickers, seen = [], set()

    def _add(sym):
        if sym and '.' not in sym and '^' not in sym and sym not in seen:
            seen.add(sym)
            tickers.append(sym)

    # Trending tickers
    d = fetch_json('https://query1.finance.yahoo.com/v1/finance/trending/US?count=25&lang=en-US')
    for q in (d or {}).get('finance', {}).get('result', [{}])[0].get('quotes', []):
        _add(q.get('symbol', ''))

    # Most-active screener
    d2 = fetch_json(
        'https://query1.finance.yahoo.com/v1/finance/screener/predefined/saved'
        '?scrIds=most_actives&count=25&lang=en-US'
    )
    for q in (d2 or {}).get('finance', {}).get('result', [{}])[0].get('quotes', []):
        _add(q.get('symbol', ''))

    return tickers[:max_n]


def extract_tickers_from_headlines(headlines):
    """Pull explicit $TICKER mentions out of headline text."""
    tickers, seen = [], set()
    for h in headlines:
        text = h.get('title', '') + ' ' + h.get('summary', '')
        for m in re.finditer(r'\$([A-Z]{2,5})\b', text):
            sym = m.group(1)
            if sym not in seen:
                seen.add(sym)
                tickers.append(sym)
    return tickers


# ── Main research pipeline ────────────────────────────────────────────────────

def run_research():
    global _progress, _scan_done, _congress_cache, _congress_ts, _legislators_cache, _legislators_ts
    _progress = []
    _scan_done = False
    # Always clear caches so every scan fetches fresh news, congress trades, and stock prices
    _congress_cache    = None
    _congress_ts       = 0
    _legislators_cache = None
    _legislators_ts    = 0

    # ── Steps 1+2: Fetch news AND congress trades in parallel ────────────────
    _log('🌍  Scanning news and Congressional disclosures simultaneously...')
    with ThreadPoolExecutor(max_workers=2) as ex:
        news_fut     = ex.submit(get_news)
        congress_fut = ex.submit(get_congress_trades, 10)
        headlines    = news_fut.result()
        congress_data = congress_fut.result()
    _log(f'✅  News: {len(headlines)} headlines  |  Congress: {len(congress_data)} stocks tracked')

    # ── Step 3: Detect themes ─────────────────────────────────────────────────
    _log('🔍  Detecting active themes (tariffs, oil, ceasefire, Fed, AI...)...')
    active_themes = detect_themes(headlines)
    if not active_themes:
        _log('⚠️  No strong themes detected — using broad market scan')
    else:
        for t, _ in active_themes:
            _log(f'📡  Theme detected: {t["icon"]} {t["title"]}')

    # ── Step 4: Build candidate stock list from affected sectors ─────────────
    seen_sym, candidates, sym_theme = set(), [], {}
    for theme, rel_headlines in active_themes:
        for direction in ('up', 'down'):
            for sector in theme.get(direction, []):
                for sym in SECTORS.get(sector, []):
                    if sym not in seen_sym:
                        seen_sym.add(sym)
                        candidates.append(sym)
                        sym_theme[sym] = (theme, direction, rel_headlines)
    candidates = candidates[:20]  # cap to keep scoring fast
    _log(f'📋  {len(candidates)} stocks identified: {", ".join(candidates[:10])}{"…" if len(candidates)>10 else ""}')

    # ── Congress buyers map ───────────────────────────────────────────────────
    congress_buyers = {}
    for sym, trades in congress_data.items():
        buyers = [t for t in trades if t['type'] == 'Buy']
        if buyers:
            congress_buyers[sym] = buyers

    # Add any congress-bought stocks not already in our candidate pool
    for sym in congress_buyers:
        if sym not in seen_sym:
            seen_sym.add(sym)
            candidates.append(sym)

    confirmed_overlap = [s for s in candidates if s in congress_buyers]
    _log(f'✅  Congress buying {len(congress_buyers)} stocks — {len(confirmed_overlap)} overlap with news themes: {", ".join(confirmed_overlap[:5])}{"…" if len(confirmed_overlap)>5 else ""}')

    # ── Step 5: Live price data ───────────────────────────────────────────────
    _log(f'📈  Fetching price data for {len(candidates)} stocks...')
    chart_cache = batch_fetch(candidates) if candidates else {}
    _log(f'✅  Got price history for {len(chart_cache)} stocks')

    # ── Step 6: Company names + market caps (reuse chart_cache data) ─────────
    enriched = enrich_top(candidates, chart_cache)

    # ── Step 7: Fetch per-stock news in parallel ─────────────────────────────
    valid = [s for s in candidates if s in chart_cache]
    _log(f'🔬  Fetching news for {len(valid)} stocks in parallel...')

    def fetch_stock_news_for(sym):
        comp_name = enriched.get(sym, {}).get('name', sym)
        headlines = fetch_stock_news(sym, comp_name)
        return sym, headlines

    news_cache = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        for sym, headlines in ex.map(fetch_stock_news_for, valid):
            news_cache[sym] = headlines

    # ── Step 8: Score every candidate ────────────────────────────────────────
    _log(f'🔬  Scoring {len(valid)} stocks...')
    results = []
    for i, sym in enumerate(valid):
        ch        = chart_cache[sym]
        e         = enriched.get(sym, {})
        mc        = e.get('mc', 0)
        comp_name = e.get('name', sym)
        price     = ch.get('price', 0)
        closes    = ch.get('closes', [])
        w52       = ch.get('w52', 0.5)
        rsi       = ch.get('rsi', 50)
        chg5      = ch.get('chg5', 0)
        vol_r     = ch.get('vol_r', 1)

        congress_confirmed = sym in congress_buyers
        theme_info         = sym_theme.get(sym)
        direction          = theme_info[1] if theme_info else 'up'

        # Per-stock news sentiment (already fetched)
        stock_headlines = news_cache.get(sym, [])
        news_score, supporting_headlines = news_sentiment(stock_headlines)

        tag = ('🏛️ Congress + news' if congress_confirmed else '📰 News theme')
        _log(f'🔬  [{i+1}/{len(valid)}] {comp_name} (${sym}) — score pending ({tag})')

        # Base score from world-news theme signal
        score = 35
        if direction == 'up':
            score += 15                           # theme says this sector benefits
        else:
            score -= 10                           # theme says sector hurt (short signal)

        score += min(20, max(-20, news_score))    # per-stock news sentiment

        if congress_confirmed:
            buyers      = congress_buyers[sym]
            buyer_names = list({t['name'] for t in buyers})
            n_buyers    = len(buyer_names)
            score += min(25, n_buyers * 8)        # congress confirmation bonus
        else:
            buyer_names, n_buyers = [], 0

        if w52 < 0.35: score += 8                # near 52w low = more upside
        if rsi < 45:   score += 6                # oversold
        if vol_r > 1.5: score += 5               # unusual volume = attention
        if chg5 < -5:  score += 4                # recent dip = entry point
        score = max(0, min(100, score))

        if score < 28:
            continue

        if   score >= 74: signal = 'Strong Setup'
        elif score >= 58: signal = 'Worth Watching'
        else:             signal = 'On Radar'

        # Hold type: short = momentum/news pop; long = dip/conviction
        is_short  = (rsi >= 52 or chg5 >= 0 or news_score >= 10)
        hold_type = 'short' if is_short else 'long'

        # Why text — world event first, then congress
        if theme_info:
            th = theme_info[0]
            why = f'{th["icon"]} {th["title"]}: {th["logic"][:160]}…'
        elif supporting_headlines:
            why = f'News: "{supporting_headlines[0][:120]}"'
        else:
            why = f'Positive news momentum around ${sym}.'

        if congress_confirmed:
            names_str = ', '.join(buyer_names[:3])
            if len(buyer_names) > 3: names_str += f' +{len(buyer_names)-3} more'
            why += f' 🏛️ Also confirmed by Congress: {names_str} {"have" if n_buyers>1 else "has"} recently bought.'

        all_trades = congress_data.get(sym, [])
        print(f'    {"🏛️" if congress_confirmed else "📰"} {sym:6s} score={score:2d} dir={direction} news={news_score:+d}')

        results.append({
            'symbol':            sym,
            'name':              comp_name,
            'price':             price,
            'target':            None,
            'upsidePct':         None,
            'score':             score,
            'signal':            signal,
            'holdType':          hold_type,
            'congressConfirmed': congress_confirmed,
            'capLabel':          cap_label(mc),
            'why':               why,
            'direction':         'up' if direction == 'up' else 'down',
            'closes':            closes,
            'stats': {
                '52w pos': f'{int(w52*100)}%',
                'RSI':     str(rsi),
                '5d':      f'{chg5:+.1f}%',
                'cap':     fmt_mc(mc) if mc else 'N/A',
                'vol':     f'{vol_r:.1f}x' if vol_r > 1.2 else 'normal',
            },
            'congressTrades':  all_trades,
            'supportingNews':  supporting_headlines,
        })

    results.sort(key=lambda x: -x['score'])
    short_picks = [r for r in results if r['holdType'] == 'short']
    long_picks  = [r for r in results if r['holdType'] == 'long']

    # Force exactly 8 each — reclassify overflow from the larger group if needed
    TARGET = 10
    while len(short_picks) < TARGET and len(long_picks) > TARGET:
        r = long_picks.pop(TARGET)
        r['holdType'] = 'short'
        short_picks.append(r)
    while len(long_picks) < TARGET and len(short_picks) > TARGET:
        r = short_picks.pop(TARGET)
        r['holdType'] = 'long'
        long_picks.append(r)
    short_picks = short_picks[:TARGET]
    long_picks  = long_picks[:TARGET]

    confirmed_count = sum(1 for r in results if r['congressConfirmed'])
    strong          = sum(1 for r in results if r['signal'] == 'Strong Setup')
    _log(f'🎯  {len(results)} picks — {confirmed_count} Congress-confirmed, {strong} strong setups')
    _log(f'✅  Done! Showing results now...')
    _scan_done = True

    themes_out = []
    if short_picks:
        themes_out.append({
            'themeId':    'short_hold',
            'themeIcon':  '⚡',
            'themeTitle': 'Short Hold — Days to Weeks',
            'themeLogic': 'Stocks affected by today\'s world events with upward momentum — tariff news, '
                          'geopolitical moves, Fed signals. Where Congress is also buying, that adds conviction. '
                          'Best for near-term catalyst plays.',
            'headlines':  [],
            'stocks':     short_picks,
        })
    if long_picks:
        themes_out.append({
            'themeId':    'long_hold',
            'themeIcon':  '🏦',
            'themeTitle': 'Long Hold — Weeks to Months',
            'themeLogic': 'Stocks impacted by real-world events that are oversold or pulling back. '
                          'Congressional buying on these names adds conviction for a patient entry. '
                          'Let the trade develop as the macro story plays out.',
            'headlines':  [],
            'stocks':     long_picks,
        })
    if not themes_out:
        themes_out.append({
            'themeId':    'news_scan',
            'themeIcon':  '📰',
            'themeTitle': 'World News Picks',
            'themeLogic': 'Stocks identified from today\'s world events and cross-referenced with Congressional disclosures.',
            'headlines':  [],
            'stocks':     results,
        })
    return themes_out

# ── HTTP server ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, status, content_type, body, extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type',   content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, clear_cookie=False):
        self.send_response(302)
        self.send_header('Location', location)
        if clear_cookie:
            self.send_header('Set-Cookie', 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
        self.end_headers()

    def _cookie_header(self, token):
        """Build Set-Cookie string. Adds Secure flag when behind HTTPS proxy (Railway)."""
        secure = '; Secure' if self.headers.get('X-Forwarded-Proto') == 'https' else ''
        return f'session={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax{secure}'

    def _authed(self):
        """Returns (uid, name) or (None, None)."""
        token = get_cookie(self.headers)
        info  = session_info(token)
        return info if info else (None, None)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]

        if path in ('/login', '/signup'):
            mode = 'login' if path == '/login' else 'signup'
            self._send(200, 'text/html; charset=utf-8', auth_page(mode))

        elif path == '/verify':
            self._redirect('/signup')  # GET verify → back to signup

        elif path == '/logout':
            self._redirect('/login', clear_cookie=True)

        elif path == '/':
            uid, name = self._authed()
            if not uid:
                self._redirect('/login')
                return
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
            with open(p, 'rb') as f:
                html = f.read().decode()
            html = html.replace(
                '<span class="badge">News-Driven</span>',
                f'<span class="badge">News-Driven</span>'
                f'<span style="margin-left:auto;color:#64748b;font-size:.82rem">👤 {htmllib.escape(name)}</span>'
                f'<a href="/logout" style="color:#ef4444;font-size:.78rem;text-decoration:none;margin-left:14px;font-weight:600">Sign out</a>'
            )
            self._send(200, 'text/html; charset=utf-8', html)

        elif path == '/debug-smtp':
            import json as _json, urllib.request as _req
            brevo_key  = os.environ.get('BREVO_API_KEY', '')
            smtp_email = os.environ.get('SMTP_EMAIL', '')
            result = 'Not tested'
            try:
                if not brevo_key:
                    result = '❌ BREVO_API_KEY not set'
                else:
                    # Hit Brevo account endpoint to verify key works
                    req2 = _req.Request(
                        'https://api.brevo.com/v3/account',
                        headers={'api-key': brevo_key, 'Accept': 'application/json'},
                        method='GET'
                    )
                    with _req.urlopen(req2, timeout=10) as r:
                        data = _json.loads(r.read())
                        result = f'✅ Brevo API key valid! Account: {data.get("email","?")}'
            except Exception as e:
                result = f'❌ Error: {e}'
            self._send(200, 'text/html; charset=utf-8', f'''
<html><body style="font-family:sans-serif;padding:40px;max-width:600px;margin:0 auto">
  <h2>🔧 Email Debug</h2>
  <p><b>BREVO_API_KEY:</b> {'✅ set (' + str(len(brevo_key)) + ' chars)' if brevo_key else '❌ NOT SET'}</p>
  <p><b>SMTP_EMAIL (sender):</b> {htmllib.escape(smtp_email) if smtp_email else '❌ NOT SET'}</p>
  <h3>API test: {result}</h3>
  <a href="/test-email">Send test email →</a>&nbsp;&nbsp;<a href="/">← Back</a>
</body></html>''')

        elif path == '/test-email':
            uid, uname = self._authed()
            if not uid:
                self._redirect('/login')
                return

            smtp_user = os.environ.get('SMTP_EMAIL', '')
            smtp_pass = os.environ.get('SMTP_PASSWORD', '')
            subscribers = get_all_subscribers()

            test_short = [
                {'symbol':'NVDA','name':'NVIDIA Corporation','signal':'Strong Momentum','score':91,'congressConfirmed':True},
                {'symbol':'AAPL','name':'Apple Inc','signal':'Strong Setup','score':82,'congressConfirmed':True},
                {'symbol':'MSFT','name':'Microsoft Corporation','signal':'Bullish Signal','score':78,'congressConfirmed':False},
                {'symbol':'AMD','name':'Advanced Micro Devices Inc','signal':'Breakout Watch','score':74,'congressConfirmed':False},
            ]
            test_long  = [
                {'symbol':'OXY','name':'Occidental Petroleum Corporation','signal':'Worth Watching','score':67,'congressConfirmed':True},
                {'symbol':'LMT','name':'Lockheed Martin Corporation','signal':'Conviction Hold','score':72,'congressConfirmed':True},
                {'symbol':'BA','name':'Boeing Company','signal':'Recovery Play','score':65,'congressConfirmed':False},
                {'symbol':'XOM','name':'Exxon Mobil Corporation','signal':'Steady Accumulation','score':70,'congressConfirmed':False},
            ]

            results_html = ''
            for email, name in subscribers:
                ok = send_alert_email(email, name, test_short, test_long)
                icon = '✅' if ok else '❌'
                results_html += f'<li>{icon} {htmllib.escape(email)} ({htmllib.escape(name)})</li>'

            if not subscribers:
                results_html = '<li>⚠️ No subscribers found in database</li>'

            self._send(200, 'text/html; charset=utf-8', f'''
<html><body style="font-family:sans-serif;padding:40px;max-width:600px;margin:0 auto">
  <h2>📧 Test Email Results</h2>
  <p><b>SMTP_EMAIL set:</b> {"✅ " + htmllib.escape(smtp_user) if smtp_user else "❌ NOT SET"}</p>
  <p><b>SMTP_PASSWORD set:</b> {"✅ yes" if smtp_pass else "❌ NOT SET"}</p>
  <p><b>Subscribers found:</b> {len(subscribers)}</p>
  <h3>Results:</h3>
  <ul>{results_html}</ul>
  <a href="/">← Back to StockScout</a>
</body></html>''')

        elif path == '/unsubscribe':
            params = urllib.parse.parse_qs(self.path.split('?',1)[1] if '?' in self.path else '')
            email  = params.get('email', [''])[0]
            if email:
                conn, pg = _get_conn()
                ph = _ph(pg)
                try:
                    if pg:
                        conn.cursor().execute(f'DELETE FROM users WHERE email={ph}', (email,))
                    else:
                        conn.execute(f'DELETE FROM users WHERE email={ph}', (email,))
                    conn.commit()
                finally:
                    conn.close()
            self._send(200, 'text/html; charset=utf-8',
                       '<html><body style="font-family:sans-serif;padding:40px;text-align:center">'
                       '<h2>✅ Unsubscribed</h2><p>You\'ve been removed from StockScout alerts.</p>'
                       '<a href="/">← Back to StockScout</a></body></html>')

        elif path == '/progress':
            uid, _ = self._authed()
            if not uid:
                self._send(401, 'application/json', json.dumps({'error': 'Not logged in'}))
                return
            self._send(200, 'application/json', json.dumps({
                'messages': _progress,
                'done': _scan_done,
            }))

        elif path == '/scan':
            uid, _ = self._authed()
            if not uid:
                self._send(401, 'application/json', json.dumps({'error': 'Not logged in'}))
                return
            t0 = time.time()
            try:
                results  = run_research()
                elapsed  = round(time.time() - t0, 1)
                n_stocks = sum(len(g['stocks']) for g in results)
                print(f'✅ Done in {elapsed}s — {n_stocks} picks\n')
                self._send(200, 'application/json', json.dumps(results))
            except Exception as e:
                import traceback; traceback.print_exc()
                self._send(500, 'application/json', json.dumps({'error': str(e)}))
        else:
            self._send(404, 'application/json', json.dumps({'error': 'not found'}))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length).decode()
        params = dict(urllib.parse.parse_qsl(body))
        path   = self.path.split('?')[0]

        if path == '/signup':
            name  = params.get('name','').strip()
            email = params.get('email','').strip().lower()
            phone = params.get('phone','').strip()
            pw    = params.get('password','')
            contact = email
            if not name or not contact or not pw:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'All fields are required.'))
                return
            if len(pw) < 6:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Password must be at least 6 characters.'))
                return
            if not is_email(contact):
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Please enter a valid email address.'))
                return
            token, code = create_pending(name, contact, pw)
            sent = send_email_code(contact, code, name)
            if sent:
                self._send(200, 'text/html; charset=utf-8', verify_page(token, contact, show_code=None))
            else:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Failed to send verification email. Please try again.'))

        elif path == '/verify':
            token = params.get('token','').strip()
            code  = params.get('code','').strip()
            p     = _pending.get(token)
            if not p:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Code expired. Please sign up again.'))
                return
            if time.time() > p['expires']:
                del _pending[token]
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Code expired. Please sign up again.'))
                return
            if code != p['code']:
                self._send(200, 'text/html; charset=utf-8', verify_page(token, p['contact'], 'Incorrect code — try again.'))
                return
            # Code correct — create the account
            del _pending[token]
            result = create_user(p['contact'], p['name'], None, pw_hash=p['pw'])
            if not result:
                self._send(200, 'text/html; charset=utf-8', auth_page('login', 'An account with that email/number already exists. Please sign in.'))
                return
            uid, uname = result
            sess = new_session(uid, uname)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', self._cookie_header(sess))
            self.end_headers()

        elif path == '/login':
            contact = params.get('contact','').strip().lower()
            pw      = params.get('password','')
            result  = check_user(contact, pw)
            if not result:
                self._send(200, 'text/html; charset=utf-8', auth_page('login', 'Incorrect email/number or password.'))
                return
            uid, uname = result
            token = new_session(uid, uname)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', self._cookie_header(token))
            self.end_headers()
        else:
            self._send(404, 'application/json', json.dumps({'error': 'not found'}))

def _picks_signature(short, long_):
    """Create a fingerprint from the set of tickers so we can detect changes."""
    tickers = sorted(p['symbol'] for p in short) + sorted(p['symbol'] for p in long_)
    return ','.join(tickers)

_last_alert_signature = None

def _scheduler():
    """Background thread: run a scan every 30 minutes and email subscribers only if picks changed."""
    global _last_alert_signature
    INTERVAL = 30 * 60
    print('⏰  Alert scheduler started — scanning every 30 minutes')
    while True:
        try:
            time.sleep(INTERVAL)
            print('⏰  Running scheduled scan...')
            themes = run_research()
            short  = next((t['stocks'] for t in themes if t['themeId'] == 'short_hold'), [])
            long_  = next((t['stocks'] for t in themes if t['themeId'] == 'long_hold'),  [])
            sig = _picks_signature(short, long_)
            if sig == _last_alert_signature:
                print('⏰  Picks unchanged — skipping alert')
            else:
                _last_alert_signature = sig
                send_alerts_to_all(short, long_)
                print('⏰  New picks detected — alerts sent')
        except Exception as e:
            print(f'⏰  Scheduler error: {e}')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    init_db()

    # Start daily scheduler in background
    threading.Thread(target=_scheduler, daemon=True).start()

    print(f'\n🚀 StockScout → http://localhost:{port}')
    print('   Open that URL, click "Find Opportunities"\n')
    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True
    ThreadingHTTPServer(('', port), Handler).serve_forever()
