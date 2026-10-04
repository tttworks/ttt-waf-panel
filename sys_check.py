#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统安全巡检 · 定制安全运维面板
检查系统级安全状态（不扫描文件内容，只做状态巡检）：
  关键软件版本 / 待装安全更新 / SSH 配置风险 / 开放端口 / fail2ban / rootkit 常见痕迹
输出: sys_check.json（面板读取）；root cron 每日一次（可手动跑）
"""
import os, re, json, datetime, subprocess

BASE = '/www/wwwroot/wafpanel'

def sh(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return r.stdout.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''

out = {
    'scanned_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'os': {}, 'services': {}, 'updates': {}, 'ssh': {}, 'ports': [],
    'fail2ban': {}, 'rootkit': [],
}

# ---- OS ----
rel = sh('cat /etc/os-release')
m = re.search(r'PRETTY_NAME="?([^"]+)"?', rel)
out['os']['name'] = m.group(1) if m else ''
out['os']['kernel'] = sh('uname -r')
out['os']['uptime'] = sh("cat /proc/uptime | awk '{print int($1)}'")

# ---- 关键软件版本 ----
php_ver = sh('/www/server/php/*/bin/php -v 2>/dev/null') or sh('php -v 2>&1')
out['services'] = {
    'nginx': sh('nginx -v 2>&1') or sh('/www/server/nginx/sbin/nginx -v 2>&1'),
    'php': php_ver.split('\n')[0] if php_ver else '',
    'mysql': sh('mysql --version 2>&1') or sh('mysqld --version 2>&1'),
    'openssh': sh('ssh -V 2>&1'),
    'memcached': sh('memcached -h 2>&1 | head -1'),
    'mysql_running': sh('ps aux 2>/dev/null | grep -v grep | grep -c mysqld') or '0',
    'mysql_params': {
        'datadir_size': sh("du -sh /www/server/data 2>/dev/null | awk '{print $1}'"),
        'max_connections': sh("grep -rE '^max_connections' /etc/my.cnf /www/server/mysql/etc/my.cnf 2>/dev/null | tail -1 | awk '{print $3}'"),
        'innodb_buffer': sh("grep -rE 'innodb_buffer_pool_size' /etc/my.cnf /www/server/mysql/etc/my.cnf 2>/dev/null | tail -1 | awk '{print $3}'"),
        'port': '3306',
    },
}

# ---- 待装安全更新（基于 apt 缓存列表，不主动 update 以免耗时）----
upd = sh("apt-get -s upgrade 2>/dev/null | grep -c '^Inst'", timeout=20)
sec = sh("apt-get -s upgrade 2>/dev/null | grep -i security | grep -c '^Inst'", timeout=20)
out['updates'] = {
    'pending_total': upd or '0',
    'pending_security': sec or '0',
    'note': '基于上次 apt 缓存，未主动 update',
}

# ---- SSH 配置风险 ----
sshd_cfg = ''
try:
    with open('/etc/ssh/sshd_config', encoding='utf-8', errors='ignore') as f:
        sshd_cfg = f.read()
except Exception:
    pass
def ssh_opt(key, default):
    m = re.search(r'^\s*' + key + r'\s+(\S+)', sshd_cfg, re.M)
    return m.group(1) if m else default
permit_root = ssh_opt('PermitRootLogin', 'prohibit-password')
password_auth = ssh_opt('PasswordAuthentication', 'yes')
ssh_port = ssh_opt('Port', '22')
risks = []
if permit_root == 'yes':
    risks.append('PermitRootLogin yes（root 允许密码登录，建议 prohibit-password）')
if password_auth.lower() in ('yes', ''):
    risks.append('SSH 允许密码认证（建议密钥认证或限制来源 IP）')
out['ssh'] = {
    'port': ssh_port, 'permit_root': permit_root, 'password_auth': password_auth, 'risks': risks,
}

# ---- 开放端口（对外监听）----
ports = []
for line in sh('ss -tlnp 2>/dev/null | tail -n +2').split('\n'):
    parts = line.split()
    if len(parts) < 5:
        continue
    m = re.match(r'^(?:0\.0\.0\.0|\*|\[::\]|::):(\d+)$', parts[3])
    if m:
        ports.append(m.group(1))
out['ports'] = sorted(set(ports))

# ---- fail2ban ----
out['fail2ban'] = {'running': 'Jail list' in sh('fail2ban-client status 2>&1')}

# ---- rootkit 常见痕迹（提示性，不判恶意）----
rk = []
for d in ['/tmp', '/var/tmp', '/dev/shm']:
    try:
        for f in os.listdir(d):
            if f.startswith('.') and f not in ('.', '..'):
                p = os.path.join(d, f)
                if os.path.exists(p):
                    rk.append({'type': '隐藏文件', 'path': p})
    except Exception:
        pass
if os.path.exists('/etc/ld.so.preload'):
    c = open('/etc/ld.so.preload', encoding='utf-8', errors='ignore').read().strip()
    if c:
        rk.append({'type': 'LD_PRELOAD', 'path': '/etc/ld.so.preload', 'detail': c[:120]})
if os.path.exists('/etc/rc.local'):
    rk.append({'type': 'rc.local', 'path': '/etc/rc.local', 'detail': ''})
# 可疑计划任务（含 eval/wget/curl/base64 的 cron 行）
cron_all = sh("cat /etc/crontab /etc/cron.*/* /var/spool/cron/crontabs/* 2>/dev/null")
for line in cron_all.split('\n'):
    if re.search(r'\b(wget|curl|base64 -d|nc |python -c|\.sh)\b', line) and not line.strip().startswith('#'):
        rk.append({'type': 'cron 可疑', 'path': 'cron', 'detail': line.strip()[:120]})
out['rootkit'] = rk[:30]

tmp = BASE + '/sys_check.json.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(out, f, ensure_ascii=False)
os.replace(tmp, BASE + '/sys_check.json')
os.chmod(BASE + '/sys_check.json', 0o644)
print('sys_check done:', json.dumps(out, ensure_ascii=False)[:200])
