#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ttt-waf-panel - 为 WordPress 服务器打造的 nginx 层 WAF + 安全运营面板
#
# Copyright 2026 TTTWorks (Aloysius Luo)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""服务器防护状态 dump：root cron 每 1 分钟生成 JSON（fail2ban + 站点WAF接入），供面板（www）读取。
只统计用户自己配置的 jail（jail.local + jail.d/*.local），排除宝塔插件自动加的 jail。"""
import subprocess, json, re, os, configparser, glob

BASE = '/www/wwwroot/wafpanel'

# ===== 用户自定义 jail（排除宝塔插件 .conf）=====
def user_jails():
    cp = configparser.ConfigParser()
    files = ['/etc/fail2ban/jail.local'] + sorted(glob.glob('/etc/fail2ban/jail.d/*.local'))
    try:
        cp.read(files, encoding='utf-8')
    except Exception:
        try:
            cp.read(files)
        except Exception:
            return []
    jails = []
    for sec in cp.sections():
        if sec.strip().lower() == 'default':
            continue
        try:
            if cp.getboolean(sec, 'enabled', fallback=False):
                jails.append(sec.strip())
        except Exception:
            pass
    return jails

# ===== fail2ban =====
res = {'running': False, 'error': None}
try:
    r = subprocess.run(['/usr/bin/fail2ban-client', 'status'], capture_output=True, text=True, timeout=10)
    txt = r.stdout
    if 'Jail list' in txt:
        res['running'] = True
        active = set(j.strip() for j in txt.split('Jail list:')[1].split(','))
        my = user_jails()
        res['jails'] = my
        res['user_configured'] = my
        res['skipped_bt'] = sorted(active - set(my))  # 被排除的宝塔 jail
        by = {}
        cur_tot = 0; all_tot = 0
        for j in my:
            rj = subprocess.run(['/usr/bin/fail2ban-client', 'status', j], capture_output=True, text=True, timeout=10)
            jt = rj.stdout
            def g(pat):
                m = re.search(pat, jt); return int(m.group(1)) if m else 0
            cur = g(r'Currently banned:\s+(\d+)')
            tot = g(r'Total banned:\s+(\d+)')
            by[j] = {'current': cur, 'total': tot}
            cur_tot += cur; all_tot += tot
        res['banned_current'] = cur_tot
        res['banned_total'] = all_tot
        res['by_jail'] = by
    else:
        res['error'] = 'no jail list'
except Exception as e:
    res['error'] = str(e)
try:
    with open(BASE + '/fail2ban_status.json', 'w') as f:
        json.dump(res, f, ensure_ascii=False)
except Exception as e:
    pass


import subprocess, json, re, os, configparser, glob
BASE = '/www/wwwroot/wafpanel'
# ===== 站点状态 dump（root 才能读 vhost 目录）：每个站点的停站状态 + WAF 接入 =====
try:
    sites = {}
    vdir = '/www/server/panel/vhost/nginx'
    for f in glob.glob(vdir + '/*.conf'):
        name = os.path.basename(f)[:-5]
        if name.startswith('0.') or name in ('phpmyadmin','phpfpm_status','wafpanel'): continue
        try:
            c = open(f, encoding='utf-8', errors='ignore').read()
            # 跳过非站点配置（map/limit/upstream 等无 server 块，如 waf2monitor_data.conf；宝塔 server 与 { 分行）
            if not re.search(r'\bserver\s*\{', c):
                continue
            root_m = re.search(r'root\s+([^;]+);', c)
            root = root_m.group(1).strip() if root_m else ''
            if not root: continue
            stopped = '/www/server/stop' in root
            # server_name
            sn_m = re.search(r'server_name\s+([^;]+);', c)
            server_names = [x.strip() for x in sn_m.group(1).split()] if sn_m else []
            # WAF 接入
            waf = os.path.exists(vdir + '/extension/%s/waf_intercept.conf' % name)
            sites[name] = {'stopped': stopped, 'root': root, 'server_names': server_names, 'waf': waf}
        except Exception as e:
            pass
    with open(BASE + '/site_status.json', 'w') as f:
        json.dump(sites, f, ensure_ascii=False)
except Exception as e:
    pass
# 兼容旧 waf_sites_status.json
try:
    waf = {k: v.get('waf', False) for k, v in sites.items()}
    with open(BASE + '/waf_sites_status.json', 'w') as f:
        json.dump(waf, f, ensure_ascii=False)
except Exception:
    pass
