# ttt-waf-panel · TTTWorks WAF & Security Operations Panel

**English** | [中文](README.zh-CN.md) | [日本語](README.ja.md)

> **An nginx-level WAF and security operations panel for WordPress servers**
> Zero external dependencies · Zero intrusion · No false positives · **Works with BT Panel**

A lightweight security operations panel: block malicious traffic at the nginx layer with
precise blacklists, then send every request into a panel you can read, filter and trace.

**No heavyweight WAF engine required** — no Docker, no Lua, no reverse proxy taking over
80/443. A `map` directive, some PHP and a bit of Python is the whole stack.

**Built to replace commercial nginx firewalls** — taking the strengths of several well-known
panels and avoiding their pain points (see [Trading off against alternatives](#trading-off-against-alternatives)).

---

## Why it exists

Containerised WAFs have three practical problems on **small multi-site servers**:

1. **Heavy** — often 7 containers and hundreds of MB of RAM, and they want to own 80/443
2. **False positives** — score-based rules regularly lock out real visitors
3. **Fragile** — when an internal component fails, **the whole site slows down or goes offline**

A real case: on one server a WAF's detector socket became an orphan inode because of a
kernel + overlay2 mount-propagation problem. Hitting the backend directly took **0.37s**;
going through the WAF took **20s** — and rebuilding, restarting or upgrading changed nothing.

So this was built the other way around: **keep the blocking decision inside nginx** (a `map`
is a C-implemented hash table, faster than any script engine), **act only on clearly bad
traffic, and let everything else through while recording it.**

---

## Features

### Protection layer (nginx)

- **Precise blacklists** — malicious user agents, malicious paths, **query-string injection**
  (`file_put_contents` / `base64_decode` / `gzinflate` and friends). String matching, not
  scoring → **real visitors are not blocked**
- **Per-site hardening** — `wp-login.php` rate limiting, no PHP execution under `uploads/`,
  `xmlrpc.php` 403, `/wp-json/wp/v2/users` 403
- **SEO crawler throttling** — AhrefsBot / meta-externalagent etc. rate-limited by a constant
  key, while normal users use a unique key (zero false positives)
- **Hotlink protection switch** — per site, `valid_referers` for images and media
- **fail2ban integration** — login-brute-force bans with jail status surfaced in the panel

### Data pipeline

```
nginx access_log (waf_full format, carries a $rule_hit marker)
   │  cron, incremental every 2 minutes
   ▼
ingest.py  ← GeoIP enrichment (geoip2 + GeoLite2)
   │
   ▼
SQLite (waf.db)  ← every request, with its rule-hit marker
   │
   ▼
api.php  →  index.html (single-page front end)
```

- **Incremental** — file offsets are recorded, only new lines are read
- **Site allow-list** — only your sites are ingested; scanner-faked hosts
  (`checkip.amazonaws.com` and similar) are dropped automatically
- **Raw IP connections** are skipped so they never pollute the site list

### Panel

| Page | Contents |
|---|---|
| **Overview** | Total / blocked / allow-listed counts, hourly trend, rule distribution, **world map** (compliant China borders), top-20 countries, server gauges (load / CPU / memory / disk) |
| **Sites** | Per-site requests and blocks, type detection (WordPress / static / custom), mail-stack detection, hotlink-protection switch |
| **Map** | One-click switch between 🌍 world map and 🇨🇳 China map, with top-20 source IPs |
| **Request log** | Every request, filterable by site / rule / time / IP |
| **Rules** | Edit user rule file online, view the main config read-only |
| **Optimisation status** | Detect and display OPcache / Memcached / **Redis** (native RESP protocol, **no PHP extension needed**) / BBR / Swap / MySQL, with one-click cache clearing. ⚠️ **Detection and clearing only — no component installation or tuning** (see below) |
| **Security scan** | Overview report · risk scan · **malware file detection** (heuristics + virus-database metadata, **detects and locates, never auto-deletes**) · **vulnerability scan** (WPScan API) · **server audit** (SSH config / open ports / pending updates / rootkit traces) |

> ⚠️ **On the "Optimisation status" page**: it **only detects and displays**, plus a one-click
> cache clear. **It does not install or tune anything.**
> It will tell you whether OPcache is installed and its hit rate, whether Memcached and Redis
> are running and how much memory they use, whether BBR is on, how much Swap is allocated, and
> what your key MySQL settings are.
> **It will not install OPcache for you, tune your `php-fpm` worker count, enable BBR, or edit
> your MySQL config.** Those actions change production parameters directly — on the wrong
> machine they are an incident. **What to run and how far to push it is your call; the panel
> only tells you what the current state is.**

### Interface preview

**Overview** — threat posture, request trend and source countries at a glance:

![Overview](docs/screenshots/overview.png)

**Sites** — per-site requests and blocks, type detection, mail-stack detection:

![Sites](docs/screenshots/sites.png)

> Screenshots come from a live production panel (server identity blurred, site names replaced).

### Engineering stance

- **Zero external dependencies** — ECharts bundled locally, **no CDN links in the front end**
  (no Google Fonts, no CDN jQuery)
- **Authentication** — `login.php` with bcrypt, 7-day cookie, IP locked for 15 minutes after
  5 failed attempts, login log with geolocation
- **Mobile-adapted** — breakpoints at 1024 / 767, drawer menu, responsive charts
- **Simple to deploy** — a single `api.php` and a single `index.html`; edit and it takes effect
  (no-store, no caching)
- **Nothing sensitive in git** — password hash, sessions, traffic database and GeoIP database
  are all outside the repository

---

## Map: compliant China borders (an important design decision here)

> Most open-source dashboards — and essentially every foreign mapping solution — get China
> **wrong**: the nine-dash line is missing, South Tibet is given to India, Taiwan is coloured
> separately. Published in China, such a map **may violate the Map Management Regulations**.

How this project handles it:

| Design | Detail |
|---|---|
| **Fully local rendering** | ECharts (Apache-2.0, bundled) plus local GeoJSON. **No online map service is called** — no OpenStreetMap, no Google/ArcGIS tiles, no external map request of any kind |
| **World map with national-standard China borders** | In `lib/world_cn.json`, **China's borders are replaced with the official DataV boundaries**, covering South Tibet, Aksai Chin and the South China Sea |
| **Nine-dash line drawn separately** | The South China Sea nine-dash line is **drawn as its own overlay** on the world map — extracted from the China GeoJSON feature `adcode = 100000_JD` and rendered as a red line. **This is exactly the part most solutions omit** |
| **China map mode** | One-click switch between 🌍 world and 🇨🇳 China; the China view only counts `CN / HK / MO / TW` source IPs |

**World map** (500 source points; the red line is the nine-dash line):

![World map](docs/screenshots/map-world.png)

**China map**:

![China map](docs/screenshots/map-china.png)

### Compliance notes (please read)

- This project **provides rendering code, not a map service** — it hosts no tiles, proxies no
  map requests and **ships no map data** (data is obtained by the user; see [`DATA.md`](DATA.md))
- **No foreign map service is introduced**, which removes the "uncompliant basemap" risk by
  construction
- ⚠️ **However**: if you expose the panel **as a public service**, the map content you display
  should still be confirmed against local regulations (for example by using a licensed basemap
  service, or by ensuring the boundary data source is compliant)
- This project does not constitute legal advice

---

## Requirements

| Component | Requirement | Notes |
|---|---|---|
| Linux | Any mainstream distribution | Runs on CentOS 7 / 8, Ubuntu 22.04 / 24.04 / 26.04 |
| nginx | 1.20+ | Both BT-Panel-compiled and system apt builds are supported (dual-path detection is built in) |
| PHP | 8.x | Required extensions: `pdo_sqlite`, `mbstring`, `curl`, `json` |
| Python | 3.8+ | `geoip2` module required |
| SQLite | Any | Provided via PHP's pdo_sqlite |
| fail2ban | Optional | Shows jail status if present; not required |

> **BT Panel users**: BT's nginx ships **without** `lua` and `auth_request` — this project
> **needs neither**. Everything is done with native `map` / `limit_req` / `internal`.

---

## Trading off against alternatives

> Some of what follows is a list of things **we deliberately chose not to do** — because getting
> them wrong hurts real users.

| | **This panel** | SafeLine (雷池) | BT Panel nginx firewall |
|---|---|---|---|
| Form | nginx native `map` + PHP panel | Multi-container Docker + reverse proxy owning 80/443 | BT Panel plugin (subscription) |
| Deployment cost | One config + a few cron entries | Needs Docker, more memory, port takeover | Installed inside BT Panel, tightly coupled to it |
| Decision method | **Precise blacklists** (UA / path / query string) | Rule scoring / semantic detection | Rule library (relatively opaque) |
| False positives | **Very rare** (exact string matching, not scoring) | Present (scoring thresholds) | Present |
| Traceability | ✅ Full requests + per-record detail + rule-hit marker | ✅ | Partial |
| External dependencies | **None** (no Docker / Lua / composer) | Docker | BT Panel |
| Panel access | Standalone panel on 8089, log in and read | Standalone panel | Inside BT Panel |
| Cost | **Open source, free** (Apache-2.0) | Free tier + commercial | Subscription |

### Capabilities we deliberately leave out (stated honestly)

- **No scoring or semantic analysis** — we would rather miss some suspicious traffic than block
  a real person. What we can't judge is left to the layer above (captcha / anti-spam plugins)
- **No POST body inspection** — nginx can't read the body natively; forcing Lua in would add
  dependencies and overhead, and would very easily break legitimate form submissions
- **No human-verification (JS challenge)** — needs extra services and front-end changes, without
  a matching benefit
- **No cloud threat intelligence** — rules are local, readable and editable (from the panel itself)
- **No "fully automatic install"** — see below

### Why nginx `map` rather than Lua or a reverse proxy

- `map` is a **C-implemented hash table**; matching is very cheap and introduces no new engine
- The blocking decision stays inside nginx, so **no extra network hop** is added (reverse-proxy
  designs forward every request one more time)
- BT Panel's bundled nginx **doesn't include** the `lua` module; switching to OpenResty means a
  reinstall and checking every site for compatibility — more cost than benefit

---

## Deployment notes (this needs hands-on ability)

> **This is not a one-click product. It is a tool for people who know servers.**
> It changes your nginx config, adds cron entries and touches PHP — actions that require
> judgement in any production environment.

**Prerequisites**

- You can read an nginx config and run `nginx -t`
- You know your PHP socket path and your log directory
- You're willing to try it on one machine before rolling it out

**Using an AI assistant is fine**

Hand this repository to an AI assistant (Claude / ChatGPT / WorkBuddy …) and tell it your
environment (BT Panel or system nginx, PHP version, site directory, log path) and let it
generate the three configs and the cron entries **for your actual setup** — usually faster and
less error-prone than copying from a document by hand.

`README.md` + `install.sh` + `DATA.md` are written for exactly this: give all three to an AI and
it can walk you through.

**On support**

This project **does not provide free deployment guidance or a deployment service**. The docs
here, the checks in `install.sh` and the FAQ below cover the vast majority of pitfalls. If, after
evaluating it, you'd like someone to help you land it, contact the author to discuss.

---

## Quick start (summary)

```bash
# 1) Put the files in place
mkdir -p /www/wwwroot/wafpanel
cp -r ttt-waf-panel/* /www/wwwroot/wafpanel/

# 2) Generate the panel password (on the server, so the $ in the hash isn't expanded by the shell)
php -r 'file_put_contents("/www/wwwroot/wafpanel/panel.passwd", password_hash("your-password", PASSWORD_BCRYPT));'
chown www:www /www/wwwroot/wafpanel/panel.passwd && chmod 600 /www/wwwroot/wafpanel/panel.passwd
#   ↑ the owner must be the php-fpm user: www on BT Panel, www-data on Ubuntu

# 3) Machine identity
cp server_identity.example.json /www/wwwroot/wafpanel/server_identity.json

# 4) Site allow-list (★ must be edited — without it the panel shows 0 forever)
cp ingest.py /www/wwwroot/wafpanel/
vi /www/wwwroot/wafpanel/ingest.py
#   SITES = ('your-site-short-name',)   ← drop www, take the segment before the first dot

# 5) Download the two data files (see DATA.md — not shipped for licence reasons)

# 6) nginx configuration — panel vhost, global rules, per-site include
nginx -t && nginx -s reload

# 7) Cron (7 entries)
```

**Verification**

```bash
nginx -t
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8089/                          # 200
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8089/api.php?action=version'  # 200 (no login needed — proves PHP + PDO are healthy)
curl -s -o /dev/null -w '%{http_code}\n' -A 'sqlmap' https://your-site/                  # 403
curl -s -o /dev/null -w '%{http_code}\n' https://your-site/xmlrpc.php                    # 403
```

> ⚠️ On a cloud server you also need to open the panel port (8089 by default) in the cloud
> console's security group. A BT Panel install enables UFW/firewalld automatically — open it there too.

---

## Data you must download yourself

For licence reasons the following files are **not** distributed with this repository — see [`DATA.md`](DATA.md):

| File | Location | Purpose | Licence |
|---|---|---|---|
| `GeoLite2-City.mmdb` | panel root | IP → country/city | MaxMind EULA (**redistribution prohibited**) |
| `lib/china.json` | `lib/` | China map outline | Alibaba DataV (see source terms) |
| `lib/world_cn.json` | `lib/` | World map outline | Same as above |

> It runs without them: the world map is simply empty and country statistics show "unknown".
> Everything else is unaffected.

---

## Configuration

| File | Purpose | Note |
|---|---|---|
| `panel.passwd` | Panel password (bcrypt hash) | **The owner must be the php-fpm user**, otherwise login always reports a wrong password |
| `server_identity.json` | Machine identity (`{"no":"server 1","ip":"..."}`) | Falls back to "hostname (IP)" |
| `site_alias.json` | Site display aliases (directory → public domain) | For when the two differ; copy `site_alias.example.json` |
| `ingest.py` `SITES` | **Site allow-list** | ★ Every new site must be added, or its data is dropped |
| `waf_rules_user.conf` | User-defined WAF rules | Editable from the panel's Rules page |
| `wpscan_token.json` | WPScan API token | Set from the vulnerability-scan page |

---

## Repository layout

```
ttt-waf-panel/
├── api.php                  # Backend API (single file, includes a Redis RESP client)
├── index.html               # Single-page front end (ECharts charts + local GeoJSON maps)
├── login.php                # Login page (bcrypt + cookie session + brute-force protection)
│
├── ingest.py                # Log ingestion: waf_full.log → GeoIP → SQLite
├── fail2ban_dump.py         # fail2ban jail / site status → JSON
├── login_log_geo.py         # Geocode login log entries
├── scan.py                  # Heuristic malware file scan
├── vuln_scan.py             # WPScan vulnerability detection
├── sys_check.py             # Server security audit
├── gen_site_status.py       # Site status generation (for non-BT-Panel machines)
├── reload_nginx.sh          # root cron: apply rule changes and reload nginx
│
├── waf_protect.conf         # nginx global rules (map / zone / limit)
├── waf_intercept.conf       # Per-site include fragment
├── waf_rules_user.conf      # User-defined rules
├── wafpanel.conf            # Panel vhost (8089)
│
├── lib/echarts.min.js       # ECharts, bundled locally (no CDN)
│                             └── china.json / world_cn.json  ← download these yourself
├── data/                    # Data you download yourself (see DATA.md)
├── site_alias.example.json
├── server_identity.example.json
├── DATA.md                  # Data download guide
├── THIRD-PARTY-NOTICES.md   # Third-party licence notices
└── LICENSE                  # Apache-2.0
```

---

## FAQ

**The panel shows 0 requests for a site, but the log file keeps growing?**
The `SITES` allow-list in `ingest.py` is wrong. It strips `www.` from the host and matches the
segment before the first dot exactly — so `example.com` will not match, you need `example`.

```bash
tail -3000 /www/wwwlogs/waf_full.log | awk -F'|' '{print $3}' | sed 's/"//g; s/^www\.//' | cut -d. -f1 | sort | uniq -c | sort -rn
```

**The front page opens but every API call returns 500?**
PHP is missing the `pdo_sqlite` extension. Check with `php -m | grep pdo_sqlite`; on Ubuntu,
`apt install php8.x-sqlite3`. Tip: `api.php?action=version` **needs no login** — if it returns
200, PHP and PDO are fine.

**The panel front page returns 403, but `/index.html` and `/api.php` are 200?**
The vhost `index` points at a non-existent `index.php` (the panel front end is plain static HTML).
Change it to:

```nginx
index index.html;
location / { try_files $uri $uri/ /index.html; }
```

**Data stopped updating on a certain day?**
Most likely the log was rotated, while the ingestion offset logic only advances on the main file.
When the main file is 0 bytes and the content is in `.1`, it silently does nothing. Fix: configure
logrotate with `copytruncate`, or make ingestion read back across rotations.

**Redis shows as "not running" although Redis is installed?**
This project reads Redis through the native RESP protocol and **does not depend on the PHP `redis`
extension**. Confirm `127.0.0.1:6379` is reachable and that no `requirepass` is set.

**Login always says the password is wrong?**
Check the **owner** of `panel.passwd` is the php-fpm user (www on BT Panel, www-data on Ubuntu)
and that it is `chmod 600`. With root as owner, php-fpm cannot read it.
Always generate the hash on the machine: `php -r 'file_put_contents("...panel.passwd", password_hash("new", PASSWORD_BCRYPT));'`
— never put a bcrypt string containing `$` inside `bash -c "..."`, the shell will expand it.

---

## Security notes

- The panel listens on **8089** by default. Please ① **restrict the source IP** in your cloud
  security group ② use a strong password
- Business endpoints require authentication; a `401 {"error":"unauthorized"}` when not logged in
  is **expected behaviour**
- `panel.passwd`, `waf.db`, `sessions/` and `GeoLite2-City.mmdb` are all in `.gitignore` —
  **never commit them**
- Malware scanning is **heuristic**: expect some false positives and false negatives. Treat it as
  operational input, not the sole authority

---

## Development notes

- The backend has no framework and no composer dependencies — plain PHP with PDO
- The front end has no build step and no bundler — just `index.html`
- Single files are a deliberate trade-off for **minimal deployment** (edit and upload); the cost
  is lengthier files
- After any change: `php -l api.php` → `curl 'api.php?action=version'` → verify `action=overview`
  while logged in

---

## Author

**Aloysius Luo** · [TTTWorks](https://tttworks.com)

Production WordPress engineering — performance, security, and custom Elementor widgets for sites
that have to hold up in the real world.

---

## License

Apache License 2.0 — permissive, **commercial use permitted**, trademark rights not granted.
Third-party licences are listed in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
