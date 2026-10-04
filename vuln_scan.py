#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPScan 自动漏洞检测 · 定制安全运维面板
识别各 WP 站点已装插件/主题版本 → 调 WPScan API 查漏洞 → 写 vuln_scan.json
- token 配置在 wpscan_token.json（面板可写，未配置则跳过）
- 本地计数今日调用次数（免费额度约 25 次/天，超出部分标记未扫）
- root cron 每日：40 2 * * * /usr/bin/python3 /www/wwwroot/wafpanel/vuln_scan.py
"""
import os, re, json, datetime, urllib.request

BASE = '/www/wwwroot/wafpanel'
ROOTS = ['/www/wwwroot', '/datamount/wwwroot']
DAILY_LIMIT = 25

def load(p, d):
    try:
        with open(p, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return d

def wpscan_get(path, token):
    req = urllib.request.Request('https://wpscan.com/api/v3' + path,
                                 headers={'Authorization': 'Token token=' + token, 'User-Agent': 'WAFPanel/1.3'})
    r = urllib.request.urlopen(req, timeout=20)
    return json.loads(r.read().decode())

def site_dirs():
    sites = {}
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for d in sorted(os.listdir(root)):
            p = os.path.join(root, d)
            if os.path.isdir(os.path.join(p, 'wp-content')):
                sites[d] = p
    return sites

def file_version(path, regex, head_len=2000):
    if not os.path.isfile(path):
        return None
    try:
        head = open(path, encoding='utf-8', errors='ignore').read(head_len)
    except Exception:
        return None
    m = re.search(regex, head)
    return m.group(1) if m else None

def plugin_version(plug_dir):
    for fn in sorted(os.listdir(plug_dir)):
        if not fn.endswith('.php'):
            continue
        v = file_version(os.path.join(plug_dir, fn), r'Version:\s*([0-9][\w.\-]*)')
        if v:
            return v
    return None

def theme_version(theme_dir):
    return file_version(os.path.join(theme_dir, 'style.css'), r'Version:\s*([0-9][\w.\-]*)')

def main():
    token_cfg = load(BASE + '/wpscan_token.json', {})
    token = (token_cfg.get('token') or '').strip()
    if not token:
        print('no wpscan token, skip')
        return

    # usage counter (daily)
    today = datetime.date.today().isoformat()
    usage = load(BASE + '/wpscan_usage.json', {})
    if usage.get('date') != today:
        usage = {'date': today, 'count': 0}
    used = usage['count']
    calls = 0
    skipped_limit = 0

    out = {'scanned_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
           'token_configured': True, 'sites': {},
           'usage': {'date': today, 'count': used, 'limit': DAILY_LIMIT}}

    checked = set()  # 去重：同 slug 只查一次
    prev = load(BASE + '/vuln_scan.json', {})
    prev_sites = prev.get('sites') or {}

    for sname, root in site_dirs().items():
        prev_pl = {(p.get('slug')): p for p in (prev_sites.get(sname) or {}).get('plugins', [])}
        prev_th = {(t.get('slug')): t for t in (prev_sites.get(sname) or {}).get('themes', [])}
        res = {'plugins': [], 'themes': [], 'skipped_limit': 0}
        # plugins
        wp_plugins = os.path.join(root, 'wp-content', 'plugins')
        if os.path.isdir(wp_plugins):
            for slug in sorted(os.listdir(wp_plugins)):
                if slug in ('.', '..') or not os.path.isdir(os.path.join(wp_plugins, slug)):
                    continue
                if slug in checked:
                    continue
                checked.add(slug)
                ver = plugin_version(os.path.join(wp_plugins, slug))
                if used + calls >= DAILY_LIMIT:
                    skipped_limit += 1
                    if slug in prev_pl: res['plugins'].append(prev_pl[slug])  # 额度不足沿用上次
                    continue
                try:
                    d = wpscan_get('/plugins/' + slug, token)
                    calls += 1
                    vulns = (d.get(slug) or {}).get('vulnerabilities') or []
                    rel = [v for v in vulns if ver and v.get('fixed_in') and ver < v['fixed_in']]
                    if rel:
                        res['plugins'].append({'slug': slug, 'version': ver, 'vulns': [
                            {'title': v.get('title'), 'fixed_in': v.get('fixed_in'),
                             'cve': ((v.get('references') or {}).get('cve') or [])[:3]} for v in rel[:8]]})
                    # 查了无漏洞 → 不保留 prev 记录（覆盖）
                except SystemExit:
                    raise
                except Exception:
                    if slug in prev_pl: res['plugins'].append(prev_pl[slug])  # 异常沿用上次
        # themes
        wp_themes = os.path.join(root, 'wp-content', 'themes')
        if os.path.isdir(wp_themes):
            for slug in sorted(os.listdir(wp_themes)):
                if slug in ('.', '..') or not os.path.isdir(os.path.join(wp_themes, slug)):
                    continue
                key = 'theme:' + slug
                if key in checked:
                    continue
                checked.add(key)
                ver = theme_version(os.path.join(wp_themes, slug))
                if used + calls >= DAILY_LIMIT:
                    skipped_limit += 1
                    if slug in prev_th: res['themes'].append(prev_th[slug])
                    continue
                try:
                    d = wpscan_get('/themes/' + slug, token)
                    calls += 1
                    vulns = (d.get(slug) or {}).get('vulnerabilities') or []
                    rel = [v for v in vulns if ver and v.get('fixed_in') and ver < v['fixed_in']]
                    if rel:
                        res['themes'].append({'slug': slug, 'version': ver, 'vulns': [
                            {'title': v.get('title'), 'fixed_in': v.get('fixed_in'),
                             'cve': ((v.get('references') or {}).get('cve') or [])[:3]} for v in rel[:8]]})
                except Exception:
                    if slug in prev_th: res['themes'].append(prev_th[slug])
        res['skipped_limit'] = skipped_limit
        out['sites'][sname] = res

    if calls == 0:
        # 无成功调用（限流 429 / 网络异常），保留上次结果不覆盖
        print('no successful api calls (rate limited?), keep previous result')
        return
    usage['count'] = used + calls
    with open(BASE + '/wpscan_usage.json', 'w', encoding='utf-8') as f:
        json.dump(usage, f)
    out['usage']['count'] = usage['count']
    with open(BASE + '/vuln_scan.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False)
    os.chmod(BASE + '/vuln_scan.json', 0o644)
    print('vuln_scan done: calls=%d used=%d skipped=%d' % (calls, usage['count'], skipped_limit))

if __name__ == '__main__':
    main()
