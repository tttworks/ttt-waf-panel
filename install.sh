#!/usr/bin/env bash
#
# ttt-waf-panel 安装脚本
#   - 自动完成：环境探测 / 复制文件 / 生成密码与标识
#   - 需要你确认：nginx 配置 / cron / 数据文件下载（脚本会打印现成命令）
#
# 用法：sudo bash install.sh
#
set -euo pipefail

PANEL_DIR="${PANEL_DIR:-/www/wwwroot/wafpanel}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PANEL_PORT:-8089}"

c_ok=$'\033[32m'; c_wn=$'\033[33m'; c_er=$'\033[31m'; c_b=$'\033[1m'; c_0=$'\033[0m'
ok(){   printf "  ${c_ok}✓${c_0} %s\n" "$1"; }
warn(){ printf "  ${c_wn}!${c_0} %s\n" "$1"; }
err(){  printf "  ${c_er}✗${c_0} %s\n" "$1"; }
step(){ printf "\n${c_b}[%s] %s${c_0}\n" "$1" "$2"; }
todo(){ printf "    ${c_wn}→${c_0} %s\n" "$1"; }

# ---------------------------------------------------------------- 0. 探测
step 0 "环境探测"

if [ "$(id -u)" != "0" ]; then err "需要 root 权限：sudo bash install.sh"; exit 1; fi
ok "root 权限"

if [ -d /www/server/panel ]; then
  WEB_USER="www"; IS_BT=1; ok "检测到宝塔面板（php-fpm 用户 = www）"
else
  WEB_USER="www-data"; IS_BT=0; warn "非宝塔环境（php-fpm 用户按 www-data 处理）"
fi

PHP_BIN=""
for p in /www/server/php/*/bin/php; do [ -x "$p" ] && PHP_BIN="$p"; done
[ -z "$PHP_BIN" ] && PHP_BIN="$(command -v php || true)"
if [ -n "$PHP_BIN" ]; then ok "PHP: $PHP_BIN"; else err "未找到 PHP，请先安装 PHP 8.x"; exit 1; fi

PY_BIN=""
[ -x /www/server/panel/pyenv/bin/python3 ] && PY_BIN="/www/server/panel/pyenv/bin/python3"
[ -z "$PY_BIN" ] && PY_BIN="$(command -v python3 || true)"
if [ -n "$PY_BIN" ]; then ok "Python: $PY_BIN"; else warn "未找到 python3 —— 日志采集与安全检测将不可用"; fi

MISSING=""
for ext in pdo_sqlite mbstring curl json; do
  if "$PHP_BIN" -m 2>/dev/null | grep -qi "^${ext}$"; then ok "PHP 扩展 $ext"; else warn "缺 PHP 扩展 $ext"; MISSING="$MISSING $ext"; fi
done
[ -n "$MISSING" ] && todo "Ubuntu 系可执行：apt install php8.x-sqlite3 php8.x-mbstring php8.x-curl"

if command -v nginx >/dev/null 2>&1 || [ -x /www/server/nginx/sbin/nginx ]; then ok "nginx 已安装"; else warn "未检测到 nginx"; fi
if [ -n "$PY_BIN" ] && "$PY_BIN" -c 'import geoip2' 2>/dev/null; then ok "python geoip2 模块"; else warn "python 缺 geoip2（GeoIP 解析不可用）"; fi
todo "安装 geoip2：$PY_BIN -m pip install geoip2"

# ---------------------------------------------------------------- 1. 复制文件
step 1 "部署文件到 $PANEL_DIR"
mkdir -p "$PANEL_DIR/lib"
for f in api.php index.html login.php ingest.py scan.py sys_check.py vuln_scan.py \
         fail2ban_dump.py login_log_geo.py reload_nginx.sh gen_site_status.py \
         waf_protect.conf waf_intercept.conf waf_rules_user.conf wafpanel.conf; do
  [ -f "$SRC_DIR/$f" ] && cp -f "$SRC_DIR/$f" "$PANEL_DIR/" || true
done
cp -f "$SRC_DIR/lib/echarts.min.js" "$PANEL_DIR/lib/" 2>/dev/null || warn "缺 lib/echarts.min.js"
[ -f "$SRC_DIR/site_alias.example.json" ] && cp -f "$SRC_DIR/site_alias.example.json" "$PANEL_DIR/"
chown -R "$WEB_USER:$WEB_USER" "$PANEL_DIR" 2>/dev/null || true
ok "文件已就位（$(ls -1 "$PANEL_DIR" | wc -l) 项）"

# ---------------------------------------------------------------- 2. 面板密码
step 2 "设置面板密码"
if [ -f "$PANEL_DIR/panel.passwd" ]; then
  ok "panel.passwd 已存在，跳过（如需重置，删除该文件后重跑）"
else
  printf "  请输入面板登录密码: "
  read -rs PANEL_PW; echo
  printf "  再输入一次确认: "
  read -rs PANEL_PW2; echo
  if [ "$PANEL_PW" != "$PANEL_PW2" ] || [ -z "$PANEL_PW" ]; then err "两次输入不一致或为空"; exit 1; fi
  # 在机内生成，避免 bcrypt 里的 $ 被 shell 展开
  "$PHP_BIN" -r "file_put_contents('$PANEL_DIR/panel.passwd', password_hash(getenv('PW'), PASSWORD_BCRYPT));" PW="$PANEL_PW" 2>/dev/null \
    || PW="$PANEL_PW" "$PHP_BIN" -r "file_put_contents('$PANEL_DIR/panel.passwd', password_hash(getenv('PW'), PASSWORD_BCRYPT));"
  chown "$WEB_USER:$WEB_USER" "$PANEL_DIR/panel.passwd"; chmod 600 "$PANEL_DIR/panel.passwd"
  ok "已生成 panel.passwd（属主 $WEB_USER，600）"
fi

# ---------------------------------------------------------------- 3. 本机标识
step 3 "本机标识"
if [ -f "$PANEL_DIR/server_identity.json" ]; then
  ok "server_identity.json 已存在，跳过"
else
  HN="$(hostname 2>/dev/null || echo unknown)"
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat > "$PANEL_DIR/server_identity.json" <<EOF
{"no": "$HN", "ip": "$IP"}
EOF
  chown "$WEB_USER:$WEB_USER" "$PANEL_DIR/server_identity.json"
  ok "已生成：{\"no\":\"$HN\",\"ip\":\"$IP\"}（可自行改成 server 编号）"
fi

# ---------------------------------------------------------------- 4. 待办
step 4 "接下来需要你做的（脚本不便代劳的部分）"

printf "\n  ${c_b}A) 站点白名单（★ 最容易漏，漏了面板数据永远是 0）${c_0}\n"
todo "编辑 $PANEL_DIR/ingest.py 里的 SITES"
todo "取值方法：tail -3000 <日志> | awk -F'|' '{print \$3}' | sed 's/\"//g; s/^www\.//' | cut -d. -f1 | sort -u"
todo "注意：填「短名」而非完整域名（www.example.com → example）"

printf "\n  ${c_b}B) 下载数据文件（许可原因不随仓库分发，见 DATA.md）${c_0}\n"
todo "GeoLite2-City.mmdb → $PANEL_DIR/（MaxMind 注册后下载）"
todo "lib/china.json + lib/world_cn.json → $PANEL_DIR/lib/"
todo "不下载也能跑：只是地图为空、国家统计显示「未知」"

printf "\n  ${c_b}C) nginx 配置${c_0}\n"
todo "面板 vhost：复制 wafpanel.conf 到 nginx conf.d/（或宝塔 vhost 目录），"
todo "            改 fastcgi_pass 为你的 PHP socket（宝塔 /tmp/php-cgi-82.sock，apt /run/php/php8.x-fpm.sock）"
todo "全局规则：复制 waf_protect.conf 到 nginx conf 目录，并在 nginx.conf 的 http{} 内 include"
todo "站点接入：复制 waf_intercept.conf 到站点的 extension 目录，并在该站 vhost 内 include"
todo "然后：nginx -t && nginx -s reload"

printf "\n  ${c_b}D) 定时任务（crontab -e）${c_0}\n"
todo "*/2 * * * * ${PY_BIN:-python3} $PANEL_DIR/ingest.py"
todo "*/1 * * * * bash $PANEL_DIR/reload_nginx.sh"
todo "*/1 * * * * ${PY_BIN:-python3} $PANEL_DIR/fail2ban_dump.py"
todo "*/5 * * * * ${PY_BIN:-python3} $PANEL_DIR/login_log_geo.py"
todo "30 2 * * * ${PY_BIN:-python3} $PANEL_DIR/scan.py      >> $PANEL_DIR/scan.log 2>&1"
todo "35 2 * * * ${PY_BIN:-python3} $PANEL_DIR/sys_check.py >> $PANEL_DIR/sys_check.log 2>&1"
todo "40 2 * * * ${PY_BIN:-python3} $PANEL_DIR/vuln_scan.py >> $PANEL_DIR/vulnscan.log 2>&1"

printf "\n  ${c_b}E) 放行端口 $PORT${c_0}\n"
todo "云控制台安全组放行 TCP $PORT（建议限定来源 IP）"
todo "宝塔安装会自动启用 UFW/firewalld，也需放行：firewall-cmd --permanent --add-port=$PORT/tcp && firewall-cmd --reload"

# ---------------------------------------------------------------- 5. 自检
step 5 "自检"
if [ -n "$PHP_BIN" ] && "$PHP_BIN" -l "$PANEL_DIR/api.php" >/dev/null 2>&1; then ok "api.php 语法检查通过"; else err "api.php 语法检查失败"; fi
if [ -f "$PANEL_DIR/panel.passwd" ]; then ok "panel.passwd 就位"; fi
if [ -s "$PANEL_DIR/GeoLite2-City.mmdb" ]; then ok "GeoLite2 数据库就位"; else warn "GeoLite2-City.mmdb 未就位（地图/国家统计将为空）"; fi
if [ -f "$PANEL_DIR/lib/china.json" ]; then ok "地图数据就位"; else warn "lib/china.json 未就位"; fi

printf "\n${c_b}安装脚本执行完毕。${c_0}完成上面 A~E 后，浏览器打开：\n"
printf "  http://<服务器IP>:%s/\n\n" "$PORT"
printf "验证命令（version 不需要登录，可判断 PHP+PDO 是否正常）：\n"
printf "  curl -s 'http://127.0.0.1:%s/api.php?action=version'\n\n" "$PORT"
