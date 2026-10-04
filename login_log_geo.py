#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""登录日志 IP 位置解析：读 login_log.txt(JSONL) -> geoip2 解析国家/城市 -> login_log.json（最新在前，最多 200 条）
root cron 每 5 分钟运行一次。"""
import json, os

BASE = '/www/wwwroot/wafpanel'
LOG = BASE + '/login_log.txt'
OUT = BASE + '/login_log.json'
OFFSET = BASE + '/login_log_offset.json'
MMDB = BASE + '/GeoLite2-City.mmdb'

_reader = None
def get_reader():
    global _reader
    if _reader is None:
        import geoip2.database
        _reader = geoip2.database.Reader(MMDB)
    return _reader

_geo_cache = {}
def geo(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = get_reader().city(ip)
        cn = r.country.names.get('zh-CN', r.country.names.get('en', ''))
        city = r.city.names.get('zh-CN', r.city.names.get('en', '')) if r.city else ''
        res = (cn, city)
    except Exception:
        res = ('', '')
    _geo_cache[ip] = res
    return res

def main():
    if not os.path.exists(LOG):
        return
    offset = 0
    if os.path.exists(OFFSET):
        try:
            offset = json.load(open(OFFSET)).get('pos', 0)
        except Exception:
            offset = 0
    size = os.path.getsize(LOG)
    if size < offset:
        offset = 0
    records = []
    if os.path.exists(OUT):
        try:
            records = json.load(open(OUT, encoding='utf-8'))
        except Exception:
            records = []
    new_rows = []
    with open(LOG, 'r', encoding='utf-8') as f:
        if offset > 0:
            f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                cn, city = geo(d.get('ip', ''))
                new_rows.append({'time': d.get('time', ''), 'ip': d.get('ip', ''), 'country': cn, 'city': city, 'ua': d.get('ua', '')})
            except Exception:
                continue
        pos = f.tell()
    if new_rows:
        records = new_rows + records
        records = records[:200]
        with open(OUT, 'w', encoding='utf-8') as f:
            json.dump(records, f, ensure_ascii=False)
        json.dump({'pos': pos}, open(OFFSET, 'w'))
    print('login_log_geo ok, total', len(records))

if __name__ == '__main__':
    main()
