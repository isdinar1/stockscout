#!/usr/bin/env python3
"""
StockScout — News-driven stock scanner.
Reads today's financial news, figures out what's happening in the world,
then finds small/mid-cap stocks in affected sectors that haven't moved yet.
No API key. No packages. Pure Python stdlib.
Run: python3 server.py
"""
import json, re, os, time, io, urllib.request, urllib.parse, html as htmllib
import zipfile, xml.etree.ElementTree as ET, sqlite3, hashlib, secrets
import http.cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
import warnings
warnings.filterwarnings('ignore')
import yfinance as yf
import pdfplumber

# ── Auth / Database ───────────────────────────────────────────────────────────
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')

def init_db():
    c = sqlite3.connect(DB)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name  TEXT NOT NULL,
        pw    TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires TIMESTAMP NOT NULL
    )''')
    c.commit(); c.close()

def _hash(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return f'{salt}:{h.hex()}'

def _verify(pw, stored):
    try:
        salt, h = stored.split(':')
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex() == h
    except:
        return False

def create_user(email, name, pw):
    try:
        c = sqlite3.connect(DB)
        cur = c.execute('INSERT INTO users (email, name, pw) VALUES (?,?,?)', (email.lower(), name, _hash(pw)))
        uid = cur.lastrowid
        c.commit(); c.close()
        return uid  # return the new user's id directly
    except sqlite3.IntegrityError:
        return None  # email already exists

def check_user(email, pw):
    c = sqlite3.connect(DB)
    row = c.execute('SELECT id, pw FROM users WHERE email=?', (email.lower(),)).fetchone()
    c.close()
    if row and _verify(pw, row[1]):
        return row[0]
    return None

def new_session(user_id):
    token = secrets.token_hex(32)
    c = sqlite3.connect(DB)
    c.execute('INSERT INTO sessions VALUES (?,?,datetime("now","+30 days"))', (token, user_id))
    c.commit(); c.close()
    return token

def session_user(token):
    if not token: return None
    c = sqlite3.connect(DB)
    row = c.execute('SELECT user_id FROM sessions WHERE token=? AND expires>datetime("now")', (token,)).fetchone()
    c.close()
    return row[0] if row else None

def delete_session(token):
    c = sqlite3.connect(DB)
    c.execute('DELETE FROM sessions WHERE token=?', (token,))
    c.commit(); c.close()

def get_cookie(headers):
    raw = headers.get('Cookie','')
    if not raw: return None
    jar = http.cookies.SimpleCookie(raw)
    return jar['session'].value if 'session' in jar else None

def get_user_name(user_id):
    c = sqlite3.connect(DB)
    row = c.execute('SELECT name FROM users WHERE id=?', (user_id,)).fetchone()
    c.close()
    return row[0] if row else 'User'

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
        <input type="text" name="name" placeholder="John Smith" required />
      </div>'''
    err_html = f'<div class="err">{htmllib.escape(error)}</div>' if error else ''
    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>StockScout — {title}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#07090f;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.box{{background:#0f1623;border:1px solid #1c2a40;border-radius:18px;padding:40px 44px;width:100%;max-width:420px}}
.logo{{text-align:center;margin-bottom:28px}}
.logo h1{{font-size:1.5rem;font-weight:800;color:#fff}}
.logo p{{color:#4b5e78;font-size:.85rem;margin-top:4px}}
h2{{font-size:1.1rem;font-weight:700;margin-bottom:22px;color:#fff}}
.field{{margin-bottom:16px}}
.field label{{display:block;font-size:.78rem;color:#64748b;margin-bottom:6px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}}
.field input{{width:100%;background:#07090f;border:1px solid #1c2a40;border-radius:9px;color:#e2e8f0;font-size:.9rem;padding:11px 14px;outline:none;transition:border-color .2s}}
.field input:focus{{border-color:#3b82f6}}
.btn{{width:100%;background:linear-gradient(135deg,#1d4ed8,#1e40af);border:none;border-radius:10px;color:#fff;cursor:pointer;font-size:.95rem;font-weight:700;padding:13px;margin-top:6px;transition:opacity .2s}}
.btn:hover{{opacity:.88}}
.switch{{text-align:center;margin-top:20px;font-size:.82rem;color:#4b5e78}}
.switch a{{color:#60a5fa;text-decoration:none;font-weight:600}}
.err{{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:8px;color:#fca5a5;font-size:.82rem;padding:10px 14px;margin-bottom:16px}}
</style></head><body>
<div class="box">
  <div class="logo"><h1>📡 StockScout</h1><p>News-driven stock research</p></div>
  <h2>{title}</h2>
  {err_html}
  <form method="POST" action="{action}">
    {name_field}
    <div class="field">
      <label>Email</label>
      <input type="email" name="email" placeholder="you@example.com" required />
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required minlength="6" />
    </div>
    <button class="btn" type="submit">{title}</button>
  </form>
  <div class="switch">{switch_text} <a href="{switch_link}">{switch_label}</a></div>
</div>
</body></html>'''

# ── Sector candidate pools (small/mid cap focus) ──────────────────────────────
# These are stocks we screen when a relevant news theme fires.
# Deliberately excludes mega-caps (AAPL, MSFT, etc.) — they're already priced in.
SECTORS = {
    'oil':       ['OXY','DVN','SM','CIVI','MGY','VTLE','CPE','NOG','MTDR','CTRA','MRO','CLR'],
    'nat_gas':   ['AR','EQT','RRC','SWN','CNX','GPOR','CRK'],
    'defense':   ['KTOS','AVAV','DRS','VSEC','HEI','MOOG','TDY','AXON','LDOS'],
    'semis':     ['WOLF','POWI','COHU','ONTO','ACLS','AMBA','CEVA','FORM','SITM','ALGM'],
    'gold':      ['AU','HL','CDE','EXK','AGI','MAG','GATO','SAND','ASA'],
    'uranium':   ['UEC','DNN','URG','UUUU','EU','LTBR','NXE'],
    'shipping':  ['SBLK','GOGL','NMM','GNK','SALT','EDRY','GRIN','EGLE'],
    'china':     ['BABA','JD','PDD','NIO','XPEV','LI','BILI','VIPS','TIGR'],
    'biotech':   ['SAVA','AGEN','SNDX','CTIC','ICAD','GLYC','PRME','APLT','AVDL'],
    'solar':     ['ARRY','CSIQ','JKS','DAQO','RUN','NOVA','SHLS','FLNC'],
    'retail':    ['FIVE','GCO','PLCE','CATO','DXLG','PRTY','GOOS','BIG','CONN'],
    'reit':      ['NXRT','SAFE','GMRE','GOOD','NLCP','BRSP','CLNC','KREF'],
    'ev':        ['RIDE','GOEV','WKHS','FSR','NKLA','SOLO','AYRO','ELMS'],
    'steel':     ['CLF','X','CMC','STLD','ATI','HAYN','KALU'],
    'airlines':  ['SAVE','ALGT','HA','SY','SKYW','MESA'],
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

# ── Congress trading data ─────────────────────────────────────────────────────

_congress_cache = None   # {ticker: [{name, date, type, amount}, ...]}
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

def get_congress_trades(max_ptrs=40):
    """
    Download recent House PTR filings and extract stock trades.
    Returns {ticker: [list of trades]} for all tickers found.
    Cached for 12 hours.
    """
    global _congress_cache, _congress_ts
    if _congress_cache is not None and time.time() - _congress_ts < 43200:
        return _congress_cache

    print('  [congress] Fetching House PTR index...')
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
        print(f'  [congress] index fetch failed: {e}')
        _congress_cache = {}
        return {}

    # Get most-recent PTR filings (P = Periodic Transaction Report = stock trades)
    ptrs = [(m.findtext('Last',''), m.findtext('First',''), m.findtext('DocID',''), m.findtext('FilingDate',''))
            for m in root.findall('.//Member') if m.findtext('FilingType') == 'P']
    ptrs.sort(key=lambda x: x[3], reverse=True)
    ptrs = ptrs[:max_ptrs]
    print(f'  [congress] Fetching {len(ptrs)} recent PTR PDFs...')

    ticker_trades = {}
    for last, first, doc_id, filed in ptrs:
        member = f'{first} {last}'
        try:
            req2 = urllib.request.Request(
                f'https://disclosures-clerk.house.gov/public_disc/ptr-pdfs/2026/{doc_id}.pdf',
                headers={'User-Agent': UA}
            )
            with urllib.request.urlopen(req2, timeout=15) as r2:
                pdf_bytes = r2.read()
            for trade in _parse_ptr_pdf(pdf_bytes, member):
                tk = trade['ticker']
                if tk not in ticker_trades:
                    ticker_trades[tk] = []
                ticker_trades[tk].append(trade)
            time.sleep(0.3)
        except Exception as e:
            pass

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

    # 1. Google News RSS — free, reliable, no rate limits, covers all major themes
    google_queries = [
        'oil prices ceasefire OPEC tariffs stock market',
        'federal reserve interest rates inflation',
        'china tariffs trade war sanctions',
        'gold price rally safe haven',
        'nuclear uranium energy AI data center',
        'shipping freight rates Red Sea',
    ]
    for q in google_queries:
        enc = urllib.parse.quote(q)
        text = fetch_text(
            f'https://news.google.com/rss/search?q={enc}&hl=en-US&gl=US&ceid=US:en'
        )
        parse_rss(text)

    # 2. Yahoo Finance search (a few targeted calls with delay to avoid 429)
    if len(headlines) < 10:
        yf_terms = ['oil ceasefire iran', 'tariff trump', 'gold price', 'fed rate']
        for term in yf_terms:
            time.sleep(0.8)
            q = urllib.parse.quote(term)
            data = fetch_json(
                f'https://query1.finance.yahoo.com/v1/finance/search?q={q}&newsCount=8&quotesCount=0'
            )
            if data:
                for n in data.get('news', []):
                    add(n.get('title', ''))

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

                results[sym] = {
                    'price':  round(curr, 2),
                    'hi52':   round(hi52, 2),
                    'lo52':   round(lo52, 2),
                    'w52':    w52,
                    'chg5':   round(chg5, 1),
                    'vol_r':  round(vol_r, 1),
                    'rsi':    round(rsi_val, 1),
                    'name':   sym,
                    'closes': [round(c, 2) for c in closes[-90:]],  # 90-day chart
                }
            except Exception as e:
                pass
    except Exception as e:
        print(f'  [batch_fetch] {e}')
    return results

def enrich_top(symbols):
    """Fetch name + market cap for top picks using yfinance."""
    out = {}
    try:
        for sym in symbols:
            try:
                t    = yf.Ticker(sym)
                info = t.info
                out[sym] = {
                    'name': info.get('longName') or info.get('shortName', sym),
                    'mc':   info.get('marketCap', 0),
                }
            except:
                out[sym] = {'name': sym, 'mc': 0}
            time.sleep(0.1)
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

# ── Main research pipeline ────────────────────────────────────────────────────

def run_research():
    print('\n📰 Fetching news...')
    news = get_news()

    if not news:
        print('  [warn] No news fetched — using fallback themes')
        active_themes = [(THEMES[0], []), (THEMES[8], [])]
    else:
        active_themes = detect_themes(news)

    if not active_themes:
        active_themes = [(THEMES[0], [])]

    # ── Collect ALL (symbol, theme, direction) combos ─────────────────────────
    # A symbol can appear in multiple themes — keep all assignments
    symbol_assignments = []  # list of (sym, theme, direction)
    seen_pairs = set()
    for theme, _ in active_themes:
        for direction, sector_ids in [('up', theme.get('up',[])), ('down', theme.get('down',[]))]:
            for sid in sector_ids:
                for sym in SECTORS.get(sid, []):
                    key = (sym, theme['id'])
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        symbol_assignments.append((sym, theme, direction))

    # Unique symbols for batch fetch
    all_symbols = list({sym for sym, _, _ in symbol_assignments})
    print(f'  → Batch-fetching {len(all_symbols)} symbols via yfinance...')

    # ── Single batch fetch for all price/technical data ───────────────────────
    chart_cache = batch_fetch(all_symbols)
    print(f'  → Got data for {len(chart_cache)} symbols')

    # ── Score all (sym, theme, direction) combos ─────────────────────────────
    all_scored = []
    for sym, theme, direction in symbol_assignments:
        ch = chart_cache.get(sym)
        if not ch:
            continue
        r = analyze(sym, theme, direction, ch, mc=0)
        if r:
            r['_theme'] = theme
            all_scored.append(r)

    # ── Fetch Congress trading data in parallel ───────────────────────────────
    import threading
    congress_data = {}
    def _fetch_congress():
        nonlocal congress_data
        congress_data = get_congress_trades(max_ptrs=40)
    ct = threading.Thread(target=_fetch_congress, daemon=True)
    ct.start()

    # ── Enrich top scorers with name + market cap ─────────────────────────────
    all_scored.sort(key=lambda x: -x['score'])
    top_syms = list({r['symbol'] for r in all_scored[:25]})
    print(f'  → Enriching top {len(top_syms)} picks with name/market cap...')
    enriched = enrich_top(top_syms)
    for r in all_scored:
        if r['symbol'] in enriched:
            e  = enriched[r['symbol']]
            mc = e.get('mc', 0)
            r['name']     = e.get('name', r['symbol'])
            r['capLabel'] = cap_label(mc)
            r['stats']['cap'] = fmt_mc(mc) if mc else 'N/A'
            if mc and mc > 60e9:
                r['score'] = 0  # demote mega caps

    all_scored.sort(key=lambda x: -x['score'])

    # ── Wait for Congress data, then annotate ─────────────────────────────────
    ct.join(timeout=60)
    for r in all_scored:
        sym    = r['symbol']
        trades = congress_data.get(sym, [])
        if trades:
            r['congressTrades'] = trades
            buys = sum(1 for t in trades if t['type'] == 'Buy')
            if buys >= 2:
                r['score'] = min(100, r['score'] + 10)
            elif buys == 1:
                r['score'] = min(100, r['score'] + 5)
        else:
            r['congressTrades'] = []

    all_scored.sort(key=lambda x: -x['score'])

    # ── Group by theme, pick top per theme ────────────────────────────────────
    output = []
    used_syms = set()
    for theme, matching_headlines in active_themes:
        theme_stocks_raw = [
            r for r in all_scored
            if r.get('_theme', {}).get('id') == theme['id'] and r['symbol'] not in used_syms
        ][:4]

        if not theme_stocks_raw:
            continue

        # Make clean copies without internal keys
        theme_stocks = []
        for r in theme_stocks_raw:
            used_syms.add(r['symbol'])
            arrow = '↑' if r['direction']=='up' else '↓'
            print(f'    {arrow} {r["symbol"]:6s} score={r["score"]:2d} [{r["capLabel"]}]')
            clean = {k: v for k, v in r.items() if not k.startswith('_')}
            theme_stocks.append(clean)

        output.append({
            'themeId':    theme['id'],
            'themeIcon':  theme['icon'],
            'themeTitle': theme['title'],
            'themeLogic': theme['logic'],
            'headlines':  [h['title'] for h in matching_headlines[:2]],
            'stocks':     theme_stocks,
        })

    return output

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
            self.send_header('Set-Cookie', 'session=; Path=/; Max-Age=0; HttpOnly')
        self.end_headers()

    def _authed_user(self):
        token = get_cookie(dict(self.headers))
        return session_user(token)

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

        elif path == '/logout':
            token = get_cookie(dict(self.headers))
            if token: delete_session(token)
            self._redirect('/login', clear_cookie=True)

        elif path == '/':
            uid = self._authed_user()
            if not uid:
                self._redirect('/login')
                return
            name = get_user_name(uid)
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
            with open(p, 'rb') as f:
                html = f.read().decode()
            # Inject username + logout button into header
            html = html.replace(
                '<span class="badge">News-Driven</span>',
                f'<span class="badge">News-Driven</span>'
                f'<span style="margin-left:auto;color:#64748b;font-size:.82rem">👤 {htmllib.escape(name)}</span>'
                f'<a href="/logout" style="color:#ef4444;font-size:.78rem;text-decoration:none;margin-left:14px;font-weight:600">Sign out</a>'
            )
            self._send(200, 'text/html; charset=utf-8', html)

        elif path == '/scan':
            uid = self._authed_user()
            if not uid:
                self._send(401, 'application/json', json.dumps({'error': 'Not logged in'}))
                return
            print('\n🔍 Scan started...')
            t0 = time.time()
            try:
                results  = run_research()
                elapsed  = round(time.time() - t0, 1)
                n_stocks = sum(len(g['stocks']) for g in results)
                print(f'✅ Done in {elapsed}s — {len(results)} themes, {n_stocks} picks\n')
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
            email = params.get('email','').strip()
            pw    = params.get('password','')
            if not name or not email or not pw:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'All fields are required.'))
                return
            if len(pw) < 6:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'Password must be at least 6 characters.'))
                return
            uid = create_user(email, name, pw)
            if not uid:
                self._send(200, 'text/html; charset=utf-8', auth_page('signup', 'An account with that email already exists.'))
                return
            token = new_session(uid)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'session={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax')
            self.end_headers()

        elif path == '/login':
            email = params.get('email','').strip()
            pw    = params.get('password','')
            uid   = check_user(email, pw)
            if not uid:
                self._send(200, 'text/html; charset=utf-8', auth_page('login', 'Incorrect email or password.'))
                return
            token = new_session(uid)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'session={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax')
            self.end_headers()
        else:
            self._send(404, 'application/json', json.dumps({'error': 'not found'}))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    init_db()
    print(f'\n🚀 StockScout → http://localhost:{port}')
    print('   Open that URL, click "Find Opportunities"\n')
    HTTPServer(('', port), Handler).serve_forever()
