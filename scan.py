#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""恶意文件扫描模块 · 定制安全运维面板
启发式检测 WordPress 站点可疑 PHP 文件（只检测+定位+报告，绝不自动删除）
输出: scan_status.json（面板读取）
白名单: scan_whitelist.json（面板"标记误报"写入）
基线:   scan_baseline.json（首次扫描自动建立，基线文件除非命中高危组合否则不报）
cron:   30 2 * * * /usr/bin/python3 /www/wwwroot/wafpanel/scan.py >> /www/wwwroot/wafpanel/scan.log 2>&1
"""
import os, re, json, time, datetime

BASE = '/www/wwwroot/wafpanel'
ROOTS = ['/www/wwwroot', '/datamount/wwwroot']
SKIP_DIR_NAMES = {'cache', 'backup', 'ai1wm-backups', 'updraft', 'updraftplus', 'tmp',
                  'node_modules', '.git', '.svn', '.idea', 'wflogs'}
MAX_SIZE = 5 * 1024 * 1024      # 单文件 5MB 上限
RECENT_DAYS = 7                 # 新近修改窗口
PHP_EXTS = ('.php', '.php5', '.php7', '.phtml', '.pht')

# ---- 高危组合规则 R1-R7（命中即高危）----
HIGH_PATTERNS = [
    (r'eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|gzdecode)\s*\(', 'R1: 解码链+eval'),
    (r'\beval\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[', 'R1b: eval+用户输入'),
    (r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[', 'R2: 命令执行+用户输入'),
    (r'\b(?:assert|call_user_func|create_function)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[', 'R3: 动态执行用户输入'),
    (r'\bassert\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(', 'R3b: assert+解码链'),
    (r'preg_replace\s*\([^)]*["\']/[^"\']*["\']\s*[a-z]*e\s*["\']', 'R6: preg_replace /e 后门'),
    (r'\beval\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(', 'R7: 多层混淆'),
    (r'\b(?:base64_decode|gzinflate|str_rot13)\s*\(\s*["\'][A-Za-z0-9+/=]{1200,}', 'R4: 超长混淆载荷'),
]
# ---- 已知恶意特征库 K ----
KNOWN_BAD = [
    r'@\s*eval\s*\(\s*\$_POST',
    r'@\s*eval\s*\(\s*\$_REQUEST',
    r'<\?php\s*eval\s*\(\s*\$_POST',
    r'\$_(?:POST|REQUEST)\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*;\s*$',
]
WEBSHELL_IDS = ['b374k', 'filesman', 'marijuana', 'alfashell', 'r57shell', 'c99shell',
                'phpspy', 'wso-shell', 'andale', 'k1ller', 'c99.php', 'r57.php', 'wso.php']
# ---- 危险函数（单词边界，仅用于"新近修改"组合判定；单函数本身不报）----
DANGEROUS_RE = re.compile(r'\b(?:eval|base64_decode|gzinflate|str_rot13|system|shell_exec|passthru|popen|proc_open|assert|call_user_func|create_function)\b', re.I)

# ---- 病毒库元数据（面板「病毒库信息」展示）----
VIRUS_DB = {
    'version': '1.0.0',
    'updated': '2026-08-29',
    'high_rules': len(HIGH_PATTERNS),      # 高危组合规则条数
    'known_bad': len(KNOWN_BAD),           # 已知恶意特征条数
    'webshell_ids': len(WEBSHELL_IDS),     # webshell 标识数
    'danger_funcs': 14,                    # 危险函数数
    'engine': '启发式特征扫描 v' + '1.0.0',
    'refs': 'PHP-Malware-Scanner / ClamAV / YARA / Loki / WPScan·Patchstack / PHP-Sentinel-AST',
    'tech': '启发式特征：R1-R7高危组合(解码链+eval/命令执行+用户输入/webshell标识等) + uploads位置异常 + 新文件+危险函数 + 已知恶意库；基线白名单+三级分级；只检测不删除',
}


def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


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


def is_skipped(rel):
    parts = rel.split('/')
    return any(p in SKIP_DIR_NAMES for p in parts)


def analyze(text, is_uploads, is_baseline, baseline_established):
    low = text.lower()
    matched = []
    for pat, label in HIGH_PATTERNS:
        if re.search(pat, text, re.I):
            matched.append(label)
    for pat in KNOWN_BAD:
        if re.search(pat, text, re.I):
            matched.append('K: 已知恶意特征')
    for wid in WEBSHELL_IDS:
        if wid in low:
            matched.append('R5: webshell标识(' + wid + ')')
    # 高危：命中组合规则 / 已知恶意库（基线文件也报）
    if matched:
        return {'level': 'high', 'matched': matched}
    # 中危：uploads 目录出现 .php（强信号）
    if is_uploads:
        return {'level': 'medium', 'matched': ['P1: uploads出现php']}
    # 低危：新出现的非基线文件 + 明确危险函数（基线建立后才有意义，抓新写入后门）
    if baseline_established and not is_baseline and DANGEROUS_RE.search(text):
        return {'level': 'low', 'matched': ['新文件+危险函数']}
    return None


def main():
    t0 = time.time()
    whitelist = load_json(BASE + '/scan_whitelist.json', {}).get('whitelisted', {})
    baseline = load_json(BASE + '/scan_baseline.json', {}).get('files', {})
    baseline_established = len(baseline) > 0
    sites = {}
    total_scanned = 0
    totals = {'high': 0, 'medium': 0, 'low': 0}
    now = time.time()

    for sname, root in site_dirs().items():
        findings = []
        files_scanned = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for fn in filenames:
                if not fn.lower().endswith(PHP_EXTS):
                    continue
                fp = os.path.join(dirpath, fn)
                rel = os.path.relpath(fp, root).replace('\\', '/')
                if is_skipped(rel) or ('/' + rel) in whitelist:
                    continue
                try:
                    st = os.stat(fp)
                except Exception:
                    continue
                if st.st_size > MAX_SIZE or st.st_size == 0:
                    continue
                files_scanned += 1
                total_scanned += 1
                is_uploads = '/wp-content/uploads/' in ('/' + rel)
                # 豁免：uploads 下的 index.php 小文件（防目录浏览，常见合法文件）
                if is_uploads and fn.lower() == 'index.php' and st.st_size < 200:
                    baseline[rel] = [st.st_size, int(st.st_mtime)]
                    continue
                try:
                    with open(fp, 'rb') as f:
                        data = f.read()
                except Exception:
                    continue
                text = data.decode('utf-8', 'ignore')
                res = analyze(text, is_uploads, rel in baseline, baseline_established)
                if not res:
                    baseline[rel] = [st.st_size, int(st.st_mtime)]
                    continue
                # 基线文件：命中高危组合才报，否则跳过（避免重复报告已知文件）
                if rel in baseline and res['level'] != 'high':
                    continue
                finding = {
                    'path': '/' + rel,
                    'level': res['level'],
                    'matched': res['matched'],
                    'size': st.st_size,
                    'mtime': datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                }
                findings.append(finding)
                totals[res['level']] += 1
        sites[sname] = {'root': root, 'files_scanned': files_scanned, 'findings': findings}

    with open(BASE + '/scan_baseline.json', 'w', encoding='utf-8') as f:
        json.dump({'files': baseline}, f, ensure_ascii=False)

    out = {
        'scanned_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'ok',
        'duration_sec': round(time.time() - t0, 1),
        'virus_db': VIRUS_DB,
        'summary': {
            'files_scanned': total_scanned,
            'high': totals['high'], 'medium': totals['medium'], 'low': totals['low'],
            'total': totals['high'] + totals['medium'] + totals['low'],
        },
        'sites': sites,
    }
    tmp = BASE + '/scan_status.json.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False)
    os.replace(tmp, BASE + '/scan_status.json')
    os.chmod(BASE + '/scan_status.json', 0o644)
    print('scan done:', json.dumps(out['summary'], ensure_ascii=False))


if __name__ == '__main__':
    main()
