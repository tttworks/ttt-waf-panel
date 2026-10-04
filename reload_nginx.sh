#!/bin/bash
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

# WAF 面板规则重载脚本：检测标记文件，执行 nginx reload
# v2（2026-08-29）：增加防外链请求处理（root 写 extension 目录）+ 状态 dump
BASE=/www/wwwroot/wafpanel
REQ=$BASE/hotlink_request.json

# 1) 处理防外链请求（www 只写请求文件，root 写入 extension）
if [ -f "$REQ" ]; then
  SITE=$(python3 -c "import json;print(json.load(open('$REQ')).get('site',''))" 2>/dev/null)
  EN=$(python3 -c "import json;print('1' if json.load(open('$REQ')).get('enable') else '0')" 2>/dev/null)
  DIR=/www/server/panel/vhost/nginx/extension/$SITE
  if [ -n "$SITE" ] && [ -d "$DIR" ]; then
    if [ "$EN" = "1" ]; then
      cat > "$DIR/anti_hotlink.conf" <<'HT'
# 防盗链（面板开关，默认关闭）
location ~* \.(jpg|jpeg|png|gif|webp|avif|svg|ico|bmp|mp4|webm|mp3|pdf|zip|rar|7z)$ {
    valid_referers none blocked *._SITE_ _SITE_;
    if ($invalid_referer) { return 403; }
    try_files $uri =404;
}
HT
      sed -i "s/_SITE_/$SITE/g" "$DIR/anti_hotlink.conf"
    else
      rm -f "$DIR/anti_hotlink.conf"
    fi
    echo "$(date '+%F %T') hotlink $SITE=$EN" >> $BASE/reload.log
  fi
  rm -f "$REQ"
  touch "$$BASE/.reload_nginx"
fi

# 2) 生成防外链状态（www 可读）
python3 - <<'PY' 2>/dev/null
import os, json
base = '/www/server/panel/vhost/nginx/extension'
items = {}
if os.path.isdir(base):
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d)
        if os.path.isdir(p):
            items[d] = os.path.isfile(os.path.join(p, 'anti_hotlink.conf'))
out = '/www/wwwroot/wafpanel/hotlink_status.json'
with open(out, 'w') as f:
    f.write(json.dumps({'items': items}, ensure_ascii=False))
os.chmod(out, 0o644)
PY

# 4) 手动 WPScan 漏洞检测请求（root 执行 vuln_scan.py）
VSCAN=$BASE/vuln_scan_request
if [ -f "$VSCAN" ]; then
  rm -f "$VSCAN"
  /usr/bin/python3 $BASE/vuln_scan.py >> $BASE/vuln_scan.log 2>&1
  echo "$(date '+%F %T') vuln_scan run" >> $BASE/reload.log
fi

# 6) 手动恶意文件扫描请求（root 执行 scan.py）
VSCAN_REQ=$BASE/scan_request
if [ -f "$VSCAN_REQ" ]; then
  rm -f "$VSCAN_REQ"
  /usr/bin/python3 $BASE/scan.py >> $BASE/scan.log 2>&1
  echo "$(date '+%F %T') scan run" >> $BASE/reload.log
fi

# 5) 原有规则重载逻辑
MARKER=$BASE/.reload_nginx
if [ -f "$MARKER" ]; then
  rm -f "$MARKER"
  /www/server/nginx/sbin/nginx -t -c /www/server/nginx/conf/nginx.conf 2>/tmp/nginxt.err
  if [ $? -eq 0 ]; then
    sudo -n /www/server/nginx/sbin/nginx -s reload -c /www/server/nginx/conf/nginx.conf 2>/dev/null || /etc/init.d/nginx reload >/dev/null 2>&1
    echo "$(date '+%F %T') reload OK" >> $BASE/reload.log
  else
    echo "$(date '+%F %T') nginx -t FAIL: $(cat /tmp/nginxt.err)" >> $BASE/reload.log
  fi
fi
