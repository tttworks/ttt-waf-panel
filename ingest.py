#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF 全量数据管道：解析 waf_full.log -> GeoIP 富化 -> 入 SQLite
运行：python3 /www/wwwroot/wafpanel/ingest.py
"""
import os, re, json, sqlite3, sys

LOGFILE = '/www/wwwlogs/waf_full.log'
DB = '/www/wwwroot/wafpanel/waf.db'
OFFSET = '/www/wwwroot/wafpanel/offsets2.json'
MMDB = '/www/wwwroot/wafpanel/GeoLite2-City.mmdb'

# 真实站点白名单（与 site 提取逻辑一致：去 www 后取首个点前段）。仅收录这些站点的请求；
# 其他 Host（如 checkip.amazonaws.com / detectportal.firefox.com 等探活/扫描伪装的域名）一律跳过，避免污染站点列表。
SITES = ('__CHANGE_ME__',)

_reader = None
def get_reader():
    global _reader
    if _reader is None:
        import geoip2.database
        _reader = geoip2.database.Reader(MMDB)
    return _reader

_geo_cache = {}
def geo_lookup(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = get_reader().city(ip)
        country = r.country.iso_code or ''
        cn = r.country.names.get('zh-CN', r.country.names.get('en',''))
        city = r.city.names.get('zh-CN', r.city.names.get('en','')) if r.city else ''
        lat, lng = r.location.latitude, r.location.longitude
        res = (country, cn, city, lat or 0, lng or 0)
    except Exception:
        res = ('', '', '', 0, 0)
    _geo_cache[ip] = res
    return res

LINE_RE = re.compile(r'^(\S+)\|([^\|]+)\|"([^\|]+)\|([^|]+)\|([^"]*)"\|(\d+)\|"([^"]*)"\|"([^"]*)"\|(\w+)\|(\d+)$')

def main():
    db = sqlite3.connect(DB)
    db.execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT, ip TEXT, time TEXT, method TEXT, uri TEXT, status INTEGER, ua TEXT, referer TEXT, rule TEXT, bytes_sent INTEGER, country TEXT, country_cn TEXT, city TEXT, lat REAL, lng REAL, created_at TEXT DEFAULT (datetime(\'now\',\'localtime\')))')
    db.execute('CREATE INDEX IF NOT EXISTS idx_req_time ON requests(time)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_req_site ON requests(site)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_req_rule ON requests(rule)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_req_ip ON requests(ip)')

    if not os.path.exists(LOGFILE):
        print('no log'); sys.exit(0)
    filesize = os.path.getsize(LOGFILE)
    offset = 0
    if os.path.exists(OFFSET):
        try: offset = json.load(open(OFFSET)).get('pos', 0)
        except: offset = 0
    if filesize < offset: offset = 0
    if filesize == offset:
        print('no new'); sys.exit(0)

    rows = []
    with open(LOGFILE, 'r') as f:
        if offset > 0: f.seek(offset)
        for line in f:
            m = LINE_RE.match(line.rstrip('\n'))
            if not m: continue
            ip, ts, host, method, uri, status, ua, ref, rule, bsent = m.groups()
            # 跳过纯 IP 直连（Host 形如 203.0.113.10 的扫描流量），避免污染站点列表
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                continue
            site = host.replace('www.','').split('.')[0]
            # 站点白名单：不在真实站点列表的 Host（探活/扫描伪装的知名域名）跳过
            if site not in SITES:
                continue
            country, cn, city, lat, lng = geo_lookup(ip)
            rows.append((site, ip, ts, method, uri, int(status), ua, ref, rule, int(bsent or 0), country, cn, city, lat, lng))
        pos = f.tell()

    if rows:
        db.executemany('INSERT INTO requests (site,ip,time,method,uri,status,ua,referer,rule,bytes_sent,country,country_cn,city,lat,lng) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
        db.commit()
    json.dump({'pos': pos}, open(OFFSET,'w'))
    print('ingested %d requests' % len(rows))

if __name__ == '__main__':
    main()
