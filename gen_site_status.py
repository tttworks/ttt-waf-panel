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

"""非宝塔/系统 nginx 站点状态生成：合并扫描宝塔与系统 vhost 目录"""
import os, re, glob, json, grp

BASE = '/www/wwwroot/wafpanel'
VDIRS = ['/www/server/panel/vhost/nginx', '/etc/nginx/sites-enabled']

sites = {}
for vdir in VDIRS:
    if not os.path.isdir(vdir):
        continue
    for f in sorted(glob.glob(vdir + '/*')):
        if not os.path.isfile(f):
            continue
        name = os.path.basename(f)
        if name.endswith('.conf'):
            name = name[:-5]
        if name.startswith('0.') or name in ('phpmyadmin', 'phpfpm_status', 'wafpanel'):
            continue
        try:
            c = open(f, encoding='utf-8', errors='ignore').read()
            if not re.search(r'\bserver\s*\{', c):
                continue
            m = re.search(r'root\s+([^;]+);', c)
            if not m:
                continue
            root = m.group(1).strip()
            sn = re.search(r'server_name\s+([^;]+);', c)
            names = [x.strip() for x in sn.group(1).split()] if sn else []
            waf = (os.path.exists('/etc/nginx/waf_intercept/%s/waf_intercept.conf' % name)
                   or os.path.exists(vdir + '/extension/%s/waf_intercept.conf' % name))
            sites[name] = {'stopped': ('/www/server/stop' in root), 'root': root,
                           'server_names': names, 'waf': waf}
        except Exception:
            pass

gid = None
try:
    gid = grp.getgrnam('www-data').gr_gid
except Exception:
    pass


def w(p, obj):
    open(p, 'w').write(json.dumps(obj, ensure_ascii=False))
    os.chmod(p, 0o644)
    if gid is not None:
        os.chown(p, gid, gid)


w(BASE + '/site_status.json', sites)
w(BASE + '/waf_sites_status.json', {k: v.get('waf', False) for k, v in sites.items()})
print('sites=', len(sites), sites)
