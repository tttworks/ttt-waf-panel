<?php
/**
 * 定制安全运维面板 API
 * 品牌：TTTWorks · 作者：Aloysius Luo
 * 数据源：requests 表（ingest.py 填充）+ rules 配置（nginx 文件）
 */
header('Content-Type: application/json; charset=utf-8');

// 面板版本号与作者信息（页头/页脚显示 version；author 等仅接口返回，不前台展示）
$PANEL_VERSION = '1.4.1';
$PANEL_PRODUCT = '定制安全运维面板';
$PANEL_BRAND   = 'TTTWorks';
$PANEL_AUTHOR  = 'Aloysius Luo';

// 服务器标识（可选项）：按台账编号填如 'server 5'；留空则自动用本机 IP（SERVER_ADDR）
// 服务器标识（通用版 v1.3.1）：优先读 server_identity.json（含 no/ip），未配置则自动用主机名 + SERVER_ADDR
$_srv_idf = @json_decode(@file_get_contents('/www/wwwroot/wafpanel/server_identity.json'), true) ?: [];
$SERVER_NO  = $_srv_idf['no'] ?? '';
$SERVER_IP  = $_srv_idf['ip'] ?? ($_SERVER['SERVER_ADDR'] ?? '');
$SERVER_LABEL = @php_uname('n') . '（' . $SERVER_IP . '）' . ($SERVER_NO ? (' - 内部编号 ' . $SERVER_NO) : '');

$db = new PDO('sqlite:/www/wwwroot/wafpanel/waf.db');
$db->exec("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT, ip TEXT, time TEXT, method TEXT, uri TEXT, status INTEGER, ua TEXT, referer TEXT, rule TEXT, bytes_sent INTEGER, country TEXT, country_cn TEXT, city TEXT, lat REAL, lng REAL, created_at TEXT DEFAULT (datetime('now','localtime')))");
$db->exec("CREATE INDEX IF NOT EXISTS idx_req_time ON requests(time)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_req_site ON requests(site)");

$action = $_GET['action'] ?? 'overview';

// —— 登录态校验（cookie session，替代 Basic Auth；手机浏览器友好）——
function waf_auth_ok() {
    $t = $_COOKIE['waf_token'] ?? '';
    if ($t === '') return false;
    $t = preg_replace('/[^a-f0-9]/', '', $t);
    if (strlen($t) !== 32) return false;
    $f = '/www/wwwroot/wafpanel/sessions/' . $t;
    if (!is_file($f)) return false;
    $ts = (int)@file_get_contents($f);
    return (time() - $ts) < 7 * 86400; // 7 天有效
}
if (!in_array($action, ['version', 'check'])) {
    if (!waf_auth_ok()) {
        http_response_code(401);
        echo json_encode(['error' => 'unauthorized']);
        exit;
    }
}
if ($action === 'check') {
    echo json_encode(['authenticated' => waf_auth_ok()]);
    exit;
}
if ($action === 'login_log') {
    $f = '/www/wwwroot/wafpanel/login_log.json';
    $log = is_readable($f) ? @json_decode(@file_get_contents($f), true) : [];
    echo json_encode(['log' => is_array($log) ? $log : []], JSON_UNESCAPED_UNICODE);
    exit;
}

function site_filter($db) {
    $w = ''; $p = [];
    if (!empty($_GET['site'])) {
        // 站点名归一化（2026-08-29）：目录全名(example.com) ↔ 请求表简写(example) 双向前缀匹配，
        // 保证站点卡/下拉筛选（全名）与请求数据（简写）都能命中
        $site = $_GET['site'];
        $siteN = preg_replace('/^www\./', '', $site);
        $known = $db->query("SELECT DISTINCT site FROM requests")->fetchAll(PDO::FETCH_COLUMN);
        $matched = [$site];
        foreach ($known as $k) {
            $kN = preg_replace('/^www\./', '', $k);
            if ($kN === $siteN) { $matched[] = $k; continue; }
            if ($k === $site) continue;
            if ($siteN !== '' && (strpos($siteN, $kN) === 0 || strpos($kN, $siteN) === 0)) $matched[] = $k;
        }
        $matched = array_values(array_unique($matched));
        $w .= ' AND site IN (' . implode(',', array_fill(0, count($matched), '?')) . ')';
        $p = array_merge($p, $matched);
    }
    if (!empty($_GET['rule'])) { $w .= ' AND rule=?'; $p[] = $_GET['rule']; }
    if (!empty($_GET['country'])) { $w .= ' AND country=?'; $p[] = $_GET['country']; }
    if (!empty($_GET['ip'])) { $w .= ' AND ip LIKE ?'; $p[] = '%'.$_GET['ip'].'%'; }
    if (!empty($_GET['q'])) { $w .= ' AND (uri LIKE ? OR ua LIKE ?)'; $p[] = '%'.$_GET['q'].'%'; $p[] = '%'.$_GET['q'].'%'; }
    // 时间范围（基于 created_at，导入时刻，与请求时间差 ≤2 分钟）
    $range = $_GET['range'] ?? '';
    $map = [
        '1h'   => "-1 hour",
        '24h'  => "-1 day",
        '48h'  => "-2 days",
        '7d'   => "-7 days",
        'month'=> "-1 month",
        'year' => "-1 year",
    ];
    if (isset($map[$range])) {
        $w .= " AND created_at >= datetime('now','".$map[$range]."','localtime')";
    }
    return [$w, $p];
}

// Memcached 原始协议 stats（不依赖 PHP 扩展）
function waf_memcached_stats($host, $port) {
    $fp = @fsockopen($host, $port, $errno, $errstr, 1);
    if (!$fp) return null;
    stream_set_timeout($fp, 2);
    fwrite($fp, "stats\r\n");
    $res = [];
    while (($line = fgets($fp, 512)) !== false) {
        if (trim($line) === 'END') break;
        if (preg_match('/^STAT (\S+) (\S+)/', $line, $m)) $res[$m[1]] = $m[2];
    }
    fclose($fp);
    return $res;
}


// Redis 原生 RESP 协议（不依赖 PHP 扩展，便于跨服务器通用）
function waf_redis_read_reply($fp) {
    $line = fgets($fp, 65536);
    if ($line === false || $line === '') return null;
    $type = $line[0];
    $body = trim(substr($line, 1));
    switch ($type) {
        case '+': return $body;
        case '-': return null;
        case ':': return (int) $body;
        case '$':
            $len = (int) $body;
            if ($len < 0) return null;
            $data = '';
            while (strlen($data) < $len) {
                $chunk = fread($fp, $len - strlen($data));
                if ($chunk === false || $chunk === '') break;
                $data .= $chunk;
            }
            fread($fp, 2);
            return $data;
        case '*':
            $n = (int) $body;
            if ($n < 0) return null;
            $arr = array();
            for ($i = 0; $i < $n; $i++) { $arr[] = waf_redis_read_reply($fp); }
            return $arr;
    }
    return null;
}

function waf_redis_cmd($fp, $args) {
    $cmd = '*' . count($args) . "\r\n";
    foreach ($args as $a) { $cmd .= '$' . strlen($a) . "\r\n" . $a . "\r\n"; }
    @fwrite($fp, $cmd);
    return waf_redis_read_reply($fp);
}

function waf_redis_stats($host, $port, $timeout = 1.5) {
    $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if (!$fp) return null;
    stream_set_timeout($fp, 2);
    $info = waf_redis_cmd($fp, array('INFO'));
    if (!is_string($info) || $info === '') { fclose($fp); return null; }

    $out = array();
    foreach (preg_split('/\r?\n/', $info) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $p = explode(':', $line, 2);
        if (count($p) === 2) { $out[ $p[0] ] = $p[1]; }
    }

    $db = waf_redis_cmd($fp, array('DBSIZE'));
    $out['_dbsize'] = is_int($db) ? $db : 0;

    $mm = waf_redis_cmd($fp, array('CONFIG', 'GET', 'maxmemory'));
    $out['_maxmemory'] = (is_array($mm) && count($mm) === 2) ? $mm[1] : (isset($out['maxmemory']) ? $out['maxmemory'] : '0');

    $mp = waf_redis_cmd($fp, array('CONFIG', 'GET', 'maxmemory-policy'));
    $out['_maxmemory_policy'] = (is_array($mp) && count($mp) === 2) ? $mp[1] : '';

    fclose($fp);
    return $out;
}

// 读 /proc 系统值（无需 exec）
function waf_read_proc($path) {
    $v = @file_get_contents($path);
    return $v === false ? null : trim($v);
}

// Nginx 进程状态（扫描 /proc）
function waf_nginx_status() {
    $masters = 0; $workers = 0;
    foreach (glob('/proc/[0-9]*/comm') as $f) {
        $c = @file_get_contents($f);
        if (trim($c) !== 'nginx') continue;
        $pid = (int)basename(dirname($f));
        $ppid = 0;
        $st = @file_get_contents('/proc/'.$pid.'/status');
        if ($st !== false && preg_match('/^PPid:\s+(\d+)/m', $st, $m)) $ppid = (int)$m[1];
        if ($ppid <= 1) $masters++; else $workers++;
    }
    return ['running'=>($masters+$workers)>0, 'master'=>$masters, 'workers'=>$workers, 'total'=>$masters+$workers];
}

// CPU ticks（/proc/stat）
function waf_cpu_ticks() {
    $st = @file_get_contents('/proc/stat');
    if ($st === false) return null;
    if (preg_match('/^cpu\s+([\d\s]+)/m', $st, $m)) {
        $parts = preg_split('/\s+/', trim($m[1]));
        $idle = (int)($parts[3] ?? 0) + (int)($parts[4] ?? 0);
        $total = 0; foreach ($parts as $p) $total += (int)$p;
        return ['idle'=>$idle, 'total'=>$total];
    }
    return null;
}

// CPU 使用率（两次采样取增量）
function waf_cpu_usage() {
    $a = waf_cpu_ticks();
    usleep(400000);
    $b = waf_cpu_ticks();
    if (!$a || !$b) return null;
    $dT = $b['total'] - $a['total'];
    $dI = $b['idle'] - $a['idle'];
    return $dT > 0 ? round(100 * ($dT - $dI) / $dT, 1) : 0.0;
}

// 磁盘分区使用（真实分区，跳过虚拟 fs）
function waf_disks() {
    $mounts = @file_get_contents('/proc/mounts');
    if ($mounts === false) return [];
    $out = []; $seen = [];
    foreach (explode("\n", $mounts) as $line) {
        if (!preg_match('/^(\S+) (\S+) (\S+)/', $line, $m)) continue;
        $dev = $m[1]; $mp = $m[2]; $fstype = $m[3];
        if (strpos($fstype, 'ext') === 0 || strpos($fstype, 'xfs') === 0 || strpos($fstype, 'btrfs') === 0) {
            $key = $mp === '/' ? '/' : rtrim($mp, '/');
            if (isset($seen[$key])) continue;
            $seen[$key] = true;
            $total = @disk_total_space($mp); $free = @disk_free_space($mp);
            if ($total && $free) $out[] = ['mount'=>$key, 'total'=>(int)$total, 'free'=>(int)$free, 'used'=>(int)($total-$free)];
        }
    }
    return $out;
}

// nginx 层 WAF 状态
function waf_nginx_waf_status() {
    // 2026-09-10 兼容非宝塔（系统 nginx）部署：多路径探测
    $confCands = ['/www/server/nginx/conf/waf_protect.conf', '/etc/nginx/conf.d/waf_protect.conf', '/usr/local/nginx/conf/waf_protect.conf'];
    $conf = ''; foreach ($confCands as $p) { if (is_readable($p)) { $conf = $p; break; } }
    $ncCands = ['/www/server/nginx/conf/nginx.conf', '/etc/nginx/nginx.conf', '/usr/local/nginx/conf/nginx.conf'];
    $nc = false; foreach ($ncCands as $p2) { if (is_readable($p2)) { $nc = @file_get_contents($p2); break; } }
    $c = $conf ? @file_get_contents($conf) : false;
    $s = ['enabled'=>false, 'included'=>false, 'rules'=>['whitelist_ua'=>0,'blacklist_ua'=>0,'blacklist_uri'=>0], 'wp_login_limit'=>null, 'conf_path'=>$conf];
    if ($nc !== false && (strpos($nc, 'waf_protect.conf') !== false || strpos($nc, 'conf.d/*.conf') !== false)) $s['included'] = true;
    if ($c !== false) {
        $s['enabled'] = true;
        foreach (['whitelist_ua','blacklist_ua','blacklist_uri'] as $t) {
            if (preg_match('/map \$[^}]+?\$'.$t.' \{([^}]*)\}/s', $c, $m)) {
                $s['rules'][$t] = substr_count($m[1], '~*(');
            }
        }
        if (preg_match('/rate=([\d]+[a-z\/]+)/', $c, $m)) $s['wp_login_limit'] = $m[1];
    }
    $s['sites_waf'] = waf_sites_waf();
    return $s;
}

// 站点 WAF 接入状态（读 root cron 生成的 JSON，因宝塔 vhost 目录 www 不可读）
// 站点显示别名（外部配置驱动）：目录名 → 公网域名
// 配置在 site_alias.json，形如 {"dir-name.example.com": "public.example.com"}
// 用途：目录名与公网域名不一致时（Hostinger / 镜像站常见），避免面板里出现两条同站条目
function waf_alias_site($name) {
    static $map = null;
    if ($map === null) {
        $f = '/www/wwwroot/wafpanel/site_alias.json';
        $map = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
        if (!is_array($map)) $map = [];
    }
    return isset($map[$name]) ? $map[$name] : $name;
}

function waf_sites_waf() {
    $f = '/www/wwwroot/wafpanel/waf_sites_status.json';
    if (!is_readable($f)) return [];
    $d = @json_decode(@file_get_contents($f), true);
    if (!is_array($d)) return [];
    $out = [];
    foreach ($d as $k => $v) { $out[waf_alias_site($k)] = $v; }
    return $out;
}

// fail2ban 状态（读 root cron 生成的 JSON，www 可读）
function waf_fail2ban_status() {
    $f = '/www/wwwroot/wafpanel/fail2ban_status.json';
    if (!is_readable($f)) return ['running'=>null, 'error'=>'status file not ready'];
    $d = @json_decode(@file_get_contents($f), true);
    return $d ?: ['running'=>null, 'error'=>'bad status file'];
}

// 各站点自动发信状态（文件探测：SMTP 插件 / 表单 / 防垃圾插件 / 发信安全层）
function waf_sites_mail() {
    // 自动扫描服务器 WP 站点目录（自适应，不写死站点；任何服务器部署都正确）
    $roots = ['/www/wwwroot', '/datamount/wwwroot'];
    $sites = [];
    foreach ($roots as $root) {
        if (!is_dir($root)) continue;
        foreach (scandir($root) as $d) {
            if ($d === '.' || $d === '..' || $d === 'index.html' || $d === 'index.php' || $d === 'wafpanel' || $d === 'default' || $d === 'phpmyadmin') continue;
            $dir = $root.'/'.$d;
            if (!is_dir($dir)) continue;
            // 类型探测：WordPress / 静态站 / 自定义应用（2026-08-29 增强，非 WP 站也识别）
            if (is_dir($dir.'/wp-content')) {
                $sites[$d] = ['root'=>$dir, 'type'=>'wordpress'];
            } elseif (is_dir($dir.'/public_html/wp-content')) {
                // Hostinger 布局：WP 在 public_html 子目录（2026-09-10 实测漏检修复）
                $sites[$d] = ['root'=>$dir.'/public_html', 'type'=>'wordpress'];
            } elseif (file_exists($dir.'/index.html')) {
                $sites[$d] = ['root'=>$dir, 'type'=>'static'];
            } elseif (file_exists($dir.'/package.json') || is_dir($dir.'/.git')) {
                $sites[$d] = ['root'=>$dir, 'type'=>'custom'];
            }
        }
    }
    $known_smtp = ['wp-mail-smtp'=>'WP Mail SMTP','wp-mail-smtp-pro'=>'WP Mail SMTP Pro','easy-wp-smtp'=>'Easy WP SMTP','fluent-smtp'=>'FluentSMTP','post-smtp'=>'Post SMTP'];
    $known_forms = ['contact-form-7'=>'Contact Form 7','wpforms'=>'WPForms','wpforms-lite'=>'WPForms Lite','elementor'=>'Elementor 表单','forminator'=>'Forminator','ninja-forms'=>'Ninja Forms'];
    $known_antispam = ['captcha-for-contact-form-7'=>'SilentShield','akismet'=>'Akismet','antispam-bee'=>'Antispam Bee','wp-spamshield'=>'WP SpamShield','invisible-recaptcha'=>'Invisible reCaptcha','advanced-nocaptcha-recaptcha'=>'reCaptcha','wordfence'=>'Wordfence 安全','wc-captcha'=>'WooCommerce 验证码'];
    // 读取站点状态（root cron 生成：停站/在跑 + WAF 接入），www 可读
    $site_status = [];
    $ss_file = '/www/wwwroot/wafpanel/site_status.json';
    if (is_readable($ss_file)) {
        $site_status = @json_decode(@file_get_contents($ss_file), true) ?: [];
    }
    $out = [];
    foreach ($sites as $s => $info) {
        $root = $info['root'];
        $type = $info['type'];
        // 跳过停站站点（site_status.json 标记 stopped=true；无记录则用 vhost root 判断）
        $stopped = false;
        if (isset($site_status[$s.'']) && isset($site_status[$s.''] ['stopped'])) {
            $stopped = $site_status[$s.''] ['stopped'];
        } else {
            $stopped = (is_link($root) || strpos(realpath($root) ?: $root, '/www/server/stop') !== false);
        }
        if ($stopped) {
            continue;
        }
        // 2026-09-10：site_status 非空时，WP 目录以 site_status 白名单为准（排除无 vhost 的副本/残留，如 weierman_yimingnet_cc）
        if ($type === 'wordpress' && !empty($site_status) && !isset($site_status[$s.''])) {
            continue;
        }
        $plugs = [];
        $plug_dir = $root.'/wp-content/plugins/';
        if (is_dir($plug_dir)) {
            foreach (scandir($plug_dir) as $x) {
                if ($x === '.' || $x === '..' || $x === 'index.php') continue;
                if (is_dir($plug_dir.$x)) $plugs[] = $x;
            }
        }
        // 从 active_plugins 判断 SMTP 插件是否真正激活（插件目录存在 ≠ 激活）
        $active_plugs = [];
        $active_file = $root.'/wp-content/plugins/index.php'; // 占位，实际从 DB 读
        $wpconfig = $root.'/wp-config.php';
        if (file_exists($wpconfig) && preg_match("/define\s*\(\s*'DB_NAME'\s*,\s*'([^']+)'/", file_get_contents($wpconfig), $dm) &&
            preg_match("/define\s*\(\s*'DB_USER'\s*,\s*'([^']+)'/", file_get_contents($wpconfig), $um) &&
            preg_match("/define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'/", file_get_contents($wpconfig), $pm) &&
            preg_match("/table_prefix\s*=\s*'([^']+)'/", file_get_contents($wpconfig), $tm)) {
            try {
                $wdb = new PDO('mysql:host=localhost;dbname='.$dm[1], $um[1], $pm[1], [PDO::ATTR_TIMEOUT=>2]);
                $ap = $wdb->query("SELECT option_value FROM {$tm[1]}options WHERE option_name='active_plugins'")->fetchColumn();
                $active_plugs = $ap ? @unserialize($ap) : [];
                if (!is_array($active_plugs)) $active_plugs = [];
            } catch (Exception $e) { $active_plugs = []; }
        }
        // SMTP 插件：仅当激活时才显示
        $smtp_plugins = [];
        foreach ($known_smtp as $dir=>$label) {
            $active_dir = preg_replace('#^([^/]+)/.*$#', '$1', $dir);
            $is_active = false;
            foreach ($active_plugs as $ap) {
                if (strpos($ap, $dir) === 0 || strpos($ap, $active_dir) === 0) { $is_active = true; break; }
            }
            if ($is_active) $smtp_plugins[] = $label;
        }
        // 检测 force-163-smtp mu-plugin（自定义 SMTP 强制方案，WP Mail SMTP 替代）
        $force_163 = file_exists($root.'/wp-content/mu-plugins/force-163-smtp.php');
        if ($force_163) $smtp_plugins[] = 'Force-163 mu-plugin';
        // 2026-09-10：读取 force-163 mu-plugin 中的发信账号，供面板展示
        $mail_account = '';
        if ($force_163) {
            $mu = @file_get_contents($root.'/wp-content/mu-plugins/force-163-smtp.php');
            if ($mu !== false && preg_match("/Username\s*=\s*'([^']+)'/", $mu, $ma)) $mail_account = $ma[1];
        }
        // 若 WP Mail SMTP 目录存在但未激活，标注「未激活」
        if (empty($smtp_plugins) && (in_array('wp-mail-smtp',$plugs) || in_array('wp-mail-smtp-pro',$plugs))) {
            $smtp_plugins[] = 'WP Mail SMTP(未激活)';
        }
        $detect = function($known) use ($plugs) {
            $found = [];
            foreach ($known as $dir=>$label) if (in_array($dir,$plugs)) $found[] = $label;
            return $found;
        };
        $out[] = [
            'site'=>$s,
            'type'=>$type,
            'smtp_plugins'=>$smtp_plugins,
            'forms'=>$detect($known_forms),
            'antispam'=>$detect($known_antispam),
            'mail_account'=>$mail_account,
            'mail_guard'=>file_exists($root.'/wp-content/mu-plugins/wp-mail-guard.php'),
            'mail_guard_log'=>file_exists($root.'/wp-content/uploads/wp-mail-guard.log'),
        ];
    }
    // 应用站点显示别名（目录名 → 公网域名）
    foreach ($out as $i => $item) { $out[$i]['site'] = waf_alias_site($item['site']); }
    return $out;
}

// ===== 版本号 / 作者信息 =====
if ($action === 'version') {
    $upt = @file_get_contents('/proc/uptime');
    $uptime = $upt !== false ? (float)explode(' ', $upt)[0] : 0;
    echo json_encode(['version'=>$PANEL_VERSION, 'product'=>$PANEL_PRODUCT, 'brand'=>$PANEL_BRAND, 'author'=>$PANEL_AUTHOR, 'server_label'=>$SERVER_LABEL ?: ($_SERVER['SERVER_ADDR'] ?? ''), 'uptime'=>$uptime]);
}
// ===== 概览 =====
elseif ($action === 'overview') {
    [$w, $p] = site_filter($db);
    $st = $db->prepare("SELECT COUNT(*) c, SUM(status>=400) err FROM requests WHERE 1=1 $w"); $st->execute($p); $row = $st->fetch(PDO::FETCH_ASSOC);
    $total = $row['c'] ?? 0; $err = $row['err'] ?? 0;
    $st_rule = $db->prepare("SELECT rule, COUNT(*) c FROM requests WHERE 1=1 $w GROUP BY rule"); $st_rule->execute($p); $by_rule = $st_rule->fetchAll(PDO::FETCH_ASSOC);
    $st_site = $db->prepare("SELECT site, COUNT(*) c FROM requests WHERE 1=1 $w GROUP BY site ORDER BY c DESC"); $st_site->execute($p); $by_site = $st_site->fetchAll(PDO::FETCH_ASSOC);
    // 拦截率
    $blocked = 0; foreach ($by_rule as $r) if ($r['rule']=='blacklist_ua'||$r['rule']=='blacklist_uri') $blocked+=$r['c'];
    $whitelist = 0; foreach ($by_rule as $r) if ($r['rule']=='whitelist_ua') $whitelist+=$r['c'];
    $by_hour = $db->query("SELECT substr(time,1,13) h, COUNT(*) c FROM requests GROUP BY h ORDER BY h DESC LIMIT 48")->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['total'=>$total,'error'=>$err,'blocked'=>$blocked,'whitelist'=>$whitelist,'by_rule'=>$by_rule,'by_site'=>$by_site,'by_hour'=>$by_hour], JSON_UNESCAPED_UNICODE);
}
// ===== 拦截明细 =====
elseif ($action === 'list') {
    [$w, $p] = site_filter($db);
    $limit = min(intval($_GET['limit'] ?? 200), 500);
    $offset = intval($_GET['offset'] ?? 0);
    $st = $db->prepare("SELECT * FROM requests WHERE 1=1 $w ORDER BY id DESC LIMIT $limit OFFSET $offset"); $st->execute($p);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    $cnt = $db->prepare("SELECT COUNT(*) FROM requests WHERE 1=1 $w"); $cnt->execute($p);
    echo json_encode(['rows'=>$rows,'total'=>$cnt->fetchColumn()], JSON_UNESCAPED_UNICODE);
}
// ===== 地图数据 =====
elseif ($action === 'map') {
    [$w, $p] = site_filter($db);
    // 按 IP 聚合（带坐标）
    $st = $db->prepare("SELECT ip, country, country_cn, city, lat, lng, COUNT(*) c, MAX(time) last, MAX(uri) uri, MAX(rule) rule
        FROM requests WHERE 1=1 $w AND lat!=0 GROUP BY ip ORDER BY c DESC LIMIT 500");
    $st->execute($p);
    $points = $st->fetchAll(PDO::FETCH_ASSOC);
    // 按国家聚合
    $by_country = $db->prepare("SELECT CASE WHEN country='' THEN '未知' ELSE country END country, CASE WHEN country_cn='' THEN '未知' ELSE country_cn END country_cn, COUNT(*) c FROM requests WHERE 1=1 $w GROUP BY country, country_cn ORDER BY c DESC");
    $by_country->execute($p);
    echo json_encode(['points'=>$points,'countries'=>$by_country->fetchAll(PDO::FETCH_ASSOC)], JSON_UNESCAPED_UNICODE);
}
// ===== 站点列表 =====
elseif ($action === 'sites') {
    // 合并：请求表 DISTINCT + 文件系统识别站点（含非 WP 站），保证已接入但暂无请求的站也显示
    $from_db = array_column($db->query("SELECT DISTINCT site FROM requests ORDER BY site")->fetchAll(PDO::FETCH_ASSOC), 'site');
    $meta = [];
    foreach (waf_sites_mail() as $info) { $meta[waf_alias_site($info['site'])] = $info['type']; }
    // 归一化：请求表站点简写（example）→ 目录全名（example.com），避免 unknown 重复项
    $dirs = array_keys($meta);
    $norm = [];
    foreach ($from_db as $s) {
        $mapped = $s;
        foreach ($dirs as $d) {
            $dNoWww = preg_replace('/^www\./', '', $d);
            if ($s !== $d && (strpos($d, $s) === 0 || strpos($dNoWww, $s) === 0)) { $mapped = $d; break; }
        }
        $norm[] = $mapped;
    }
    $sites = array_values(array_unique(array_merge($norm, $dirs)));
    // 应用站点显示别名（目录名 → 公网域名），再做一次去重
    $sites = array_values(array_unique(array_map('waf_alias_site', $sites)));
    sort($sites);
    $out = array_map(function($s) use ($meta) { return ['site'=>$s, 'type'=>($meta[$s] ?? 'unknown')]; }, $sites);
    echo json_encode(['sites'=>$out], JSON_UNESCAPED_UNICODE);
}
// ===== 规则读取（内置 + 用户自定义） =====
elseif ($action === 'rules') {
    $user_file = '/www/wwwroot/wafpanel/waf_rules_user.conf';
    $user = file_exists($user_file) ? file_get_contents($user_file) : '';
    $main = false;
    foreach (['/www/server/nginx/conf/waf_protect.conf', '/etc/nginx/conf.d/waf_protect.conf', '/usr/local/nginx/conf/waf_protect.conf'] as $p) {
        if (is_readable($p)) { $main = @file_get_contents($p); break; }
    }
    echo json_encode(['user_config'=>$user, 'main_config'=>$main], JSON_UNESCAPED_UNICODE);
}
// ===== 规则编辑（写用户规则文件，www 可写，无需 exec）=====
elseif ($action === 'rule_edit') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo json_encode(['error'=>'POST only']); exit; }
    $body = json_decode(file_get_contents('php://input'), true);
    $type = $body['type'] ?? '';
    $value = $body['value'] ?? '';
    $value = trim($value);
    if (!$type || !$value) { echo json_encode(['error'=>'type and value required']); exit; }
    if (!in_array($type, ['whitelist_ua','blacklist_ua','blacklist_uri'])) { echo json_encode(['error'=>'bad type']); exit; }
    // 防误伤：只能追加"词"，不能改结构。允许字母数字下划线连字符点斜杠
    if (!preg_match('/^[A-Za-z0-9_\-\/\.]+$/', $value)) { echo json_encode(['error'=>'bad value, only alnum/_-./ allowed']); exit; }

    $user_file = '/www/wwwroot/wafpanel/waf_rules_user.conf';
    $escaped = str_replace('/', '\/', $value);

    // 读当前用户规则
    $user = file_exists($user_file) ? file_get_contents($user_file) : '';
    // 去重
    if (strpos($user, $escaped) !== false) { echo json_encode(['error'=>'rule already exists']); exit; }

    // 确定插入位置：对应 map 的 default 0; 前
    $map_marker = ['whitelist_ua'=>'$user_whitelist_ua','blacklist_ua'=>'$user_blacklist_ua','blacklist_uri'=>'$user_blacklist_uri'];
    $needle = 'map $' . ($type=='blacklist_uri' ? 'uri $user_blacklist_uri' : ($type=='whitelist_ua' ? 'http_user_agent $user_whitelist_ua' : 'http_user_agent $user_blacklist_ua')) . ' {';
    $pos = strpos($user, $needle);
    if ($pos === false) { echo json_encode(['error'=>'user map block not found: '.$needle]); exit; }
    $default_pos = strpos($user, 'default 0;', $pos);
    if ($default_pos === false) { echo json_encode(['error'=>'default not found']); exit; }

    $line = "    \"~*($escaped)\" 1;\n";
    $user = substr($user, 0, $default_pos) . $line . substr($user, $default_pos);

    // 写回（www 可写）
    if (file_put_contents($user_file, $user) === false) { echo json_encode(['error'=>'write failed']); exit; }
    // 触发 nginx 重载：通过写一个标记文件，由 cron 检测执行 sudo reload
    // 方案：面板目录放一个 reload 请求文件，cron 每30秒检测并 sudo nginx reload
    file_put_contents('/www/wwwroot/wafpanel/.reload_nginx', date('c'));
    echo json_encode(['ok'=>true,'msg'=>'规则已写入，正在生效','type'=>$type,'value'=>$value]);
}

// ===== 服务器加速优化状态（OPcache / Memcached / Redis）=====
elseif ($action === 'optim') {
    $out = [];
    $out['php'] = [
        'version' => PHP_VERSION,
        'sapi' => php_sapi_name(),
        'ext' => [
            'opcache' => extension_loaded('Zend OPcache'),
            'memcached' => extension_loaded('memcached'),
            'memcache' => extension_loaded('memcache'),
            'redis' => extension_loaded('redis'),
        ],
    ];
    // OPcache
    if (function_exists('opcache_get_status')) {
        $st = @opcache_get_status(false);
        $cfg = function_exists('opcache_get_configuration') ? @opcache_get_configuration() : null;
        $dir = $cfg['directives'] ?? [];
        $mem = $st['memory_usage'] ?? [];
        $os = $st['opcache_statistics'] ?? [];
        $out['opcache'] = [
            'loaded' => extension_loaded('Zend OPcache'),
            'enabled' => !empty($st['opcache_enabled']),
            'cache_full' => !empty($st['cache_full']),
            'memory_used' => $mem['used_memory'] ?? 0,
            'memory_free' => $mem['free_memory'] ?? 0,
            'memory_wasted' => $mem['wasted_memory'] ?? 0,
            'wasted_percent' => $mem['wasted_memory_percentage'] ?? 0,
            'hit_rate' => round((float)($os['opcache_hit_rate'] ?? 0), 1),
            'hits' => $os['hits'] ?? 0,
            'misses' => $os['misses'] ?? 0,
            'num_cached_scripts' => $os['num_cached_scripts'] ?? 0,
            'num_cached_keys' => $os['num_cached_keys'] ?? 0,
            'max_accelerated_files' => $dir['opcache.max_accelerated_files'] ?? null,
            'memory_consumption' => $dir['opcache.memory_consumption'] ?? null,
            'validate_timestamps' => $dir['opcache.validate_timestamps'] ?? null,
            'revalidate_freq' => $dir['opcache.revalidate_freq'] ?? null,
        ];
    } else {
        $out['opcache'] = ['loaded' => false, 'enabled' => false];
    }
    // Memcached
    $out['memcached'] = ['php_ext' => extension_loaded('memcached') ? 'memcached' : (extension_loaded('memcache') ? 'memcache' : null)];
    $mem = waf_memcached_stats('127.0.0.1', 11211);
    if ($mem) {
        $hits = (int)($mem['get_hits'] ?? 0); $misses = (int)($mem['get_misses'] ?? 0);
        $out['memcached'] = array_merge($out['memcached'], [
            'daemon' => true,
            'version' => $mem['version'] ?? '',
            'uptime' => (int)($mem['uptime'] ?? 0),
            'curr_connections' => (int)($mem['curr_connections'] ?? 0),
            'get_hits' => $hits, 'get_misses' => $misses,
            'hit_rate' => round(100 * $hits / max($hits + $misses, 1), 1),
            'evictions' => (int)($mem['evictions'] ?? 0),
            'bytes' => (int)($mem['bytes'] ?? 0),
            'limit_maxbytes' => (int)($mem['limit_maxbytes'] ?? 0),
            'curr_items' => (int)($mem['curr_items'] ?? 0),
            'total_items' => (int)($mem['total_items'] ?? 0),
            'cmd_get' => (int)($mem['cmd_get'] ?? 0),
            'cmd_set' => (int)($mem['cmd_set'] ?? 0),
        ]);
    } else {
        $out['memcached']['daemon'] = false;
    }
    // Redis（原生 RESP 协议采集，不依赖 PHP 扩展）
    $out['redis'] = ['php_ext' => extension_loaded('redis'), 'daemon' => false];
    $rd = waf_redis_stats('127.0.0.1', 6379);
    if ($rd) {
        $rh = (int)($rd['keyspace_hits'] ?? 0);
        $rm = (int)($rd['keyspace_misses'] ?? 0);
        // 解析 keyspace（db0:keys=123,expires=0,avg_ttl=0）
        $db_keys = 0; $db_expires = 0;
        if (preg_match('/keys=(\d+)/', (string)($rd['db0'] ?? ''), $mk)) { $db_keys = (int)$mk[1]; }
        if (preg_match('/expires=(\d+)/', (string)($rd['db0'] ?? ''), $me)) { $db_expires = (int)$me[1]; }

        $out['redis'] = array_merge($out['redis'], [
            'daemon'                     => true,
            'version'                    => $rd['redis_version'] ?? '',
            'mode'                       => $rd['redis_mode'] ?? '',
            'uptime'                     => (int)($rd['uptime_in_seconds'] ?? 0),
            'port'                       => (int)($rd['tcp_port'] ?? 6379),
            'connected_clients'          => (int)($rd['connected_clients'] ?? 0),
            'blocked_clients'            => (int)($rd['blocked_clients'] ?? 0),
            'used_memory'                => (int)($rd['used_memory'] ?? 0),
            'used_memory_human'          => $rd['used_memory_human'] ?? '',
            'used_memory_peak_human'     => $rd['used_memory_peak_human'] ?? '',
            'used_memory_rss'            => (int)($rd['used_memory_rss'] ?? 0),
            'maxmemory'                  => (int)($rd['_maxmemory'] ?? 0),
            'maxmemory_policy'           => $rd['_maxmemory_policy'] ?? '',
            'mem_fragmentation_ratio'    => (float)($rd['mem_fragmentation_ratio'] ?? 0),
            'total_connections_received' => (int)($rd['total_connections_received'] ?? 0),
            'total_commands_processed'   => (int)($rd['total_commands_processed'] ?? 0),
            'instantaneous_ops_per_sec'  => (int)($rd['instantaneous_ops_per_sec'] ?? 0),
            'keyspace_hits'              => $rh,
            'keyspace_misses'            => $rm,
            'hit_rate'                   => round(100 * $rh / max($rh + $rm, 1), 1),
            'expired_keys'               => (int)($rd['expired_keys'] ?? 0),
            'evicted_keys'               => (int)($rd['evicted_keys'] ?? 0),
            'dbsize'                     => (int)($rd['_dbsize'] ?? 0),
            'db_keys'                    => $db_keys,
            'db_expires'                 => $db_expires,
            'aof_enabled'                => (int)($rd['aof_enabled'] ?? 0),
            'rdb_last_save_time'         => (int)($rd['rdb_last_save_time'] ?? 0),
        ]);
    } else {
        $fp = @fsockopen('127.0.0.1', 6379, $e, $s, 1);
        if ($fp) { fclose($fp); $out['redis']['daemon'] = true; }
    }
    // 系统 / 网络加速（BBR/TCP）/ Nginx
    $sys = [];
    $cc = waf_read_proc('/proc/sys/net/ipv4/tcp_congestion_control');
    $sys['net'] = [
        'tcp_congestion_control' => $cc,
        'bbr' => ($cc === 'bbr'),
        'available_cc' => waf_read_proc('/proc/sys/net/ipv4/tcp_available_congestion_control'),
        'tcp_fastopen' => waf_read_proc('/proc/sys/net/ipv4/tcp_fastopen'),
        'tcp_tw_reuse' => waf_read_proc('/proc/sys/net/ipv4/tcp_tw_reuse'),
        'tcp_syncookies' => waf_read_proc('/proc/sys/net/ipv4/tcp_syncookies'),
        'tcp_max_syn_backlog' => waf_read_proc('/proc/sys/net/ipv4/tcp_max_syn_backlog'),
        'somaxconn' => waf_read_proc('/proc/sys/net/core/somaxconn'),
        'swappiness' => waf_read_proc('/proc/sys/vm/swappiness'),
    ];
    $mi = @file_get_contents('/proc/meminfo');
    $mem = [];
    if ($mi !== false) { foreach (['MemTotal','MemFree','MemAvailable','SwapTotal','SwapFree','Cached'] as $k) { if (preg_match('/^'.$k.':\s+(\d+) kB/m', $mi, $m)) $mem[$k] = (int)$m[1] * 1024; } }
    $sys['mem'] = $mem;
    $sys['load'] = waf_read_proc('/proc/loadavg');
    $up = waf_read_proc('/proc/uptime');
    $sys['uptime'] = $up ? (float)explode(' ', $up)[0] : null;
    $cpu = @file_get_contents('/proc/cpuinfo');
    $cores = 0; $model = null;
    if ($cpu !== false) { $cores = preg_match_all('/^processor\s*:/m', $cpu); if (preg_match('/^model name\s*:\s*(.+)$/m', $cpu, $m)) $model = trim($m[1]); }
    $sys['cpu'] = ['cores'=>$cores, 'model'=>$model];
    $sys['nginx'] = array_merge(waf_nginx_status(), ['server_software'=>$_SERVER['SERVER_SOFTWARE'] ?? null]);
    // OS / 内核
    $osrel = @file_get_contents('/etc/os-release');
    $sys['os'] = ['os'=>php_uname('s'), 'kernel'=>php_uname('r'), 'arch'=>php_uname('m'), 'hostname'=>php_uname('n')];
    if ($osrel !== false) {
        if (preg_match('/^PRETTY_NAME="?([^"\n]+)"?/m', $osrel, $m)) $sys['os']['name'] = $m[1];
        if (preg_match('/^VERSION_ID="?([^"\n]+)"?/m', $osrel, $m)) $sys['os']['version'] = $m[1];
    }
    // CPU 使用率（两次采样）
    $sys['cpu_usage'] = waf_cpu_usage();
    // 磁盘分区
    $sys['disks'] = waf_disks();
    // nginx 层 WAF / fail2ban / 各站点发信状态
    $sys['nginx_waf'] = waf_nginx_waf_status();
    $sys['fail2ban'] = waf_fail2ban_status();
    $sys['sites_mail'] = waf_sites_mail();
    $out['sys'] = $sys;
    echo json_encode($out, JSON_UNESCAPED_UNICODE);
}

elseif ($action === 'cache_flush') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $type = $in['type'] ?? ($_GET['type'] ?? '');
    if ($type === 'opcache') {
        if (function_exists('opcache_reset')) {
            $ok = @opcache_reset();
            echo json_encode($ok ? ['ok'=>true,'msg'=>'OPcache 已清除'] : ['ok'=>false,'msg'=>'opcache_reset 失败（可能未启用）'], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['ok'=>false,'msg'=>'OPcache 扩展未加载'], JSON_UNESCAPED_UNICODE);
        }
    } elseif ($type === 'memcached') {
        $fp = @fsockopen('127.0.0.1', 11211, $e, $s, 1);
        if ($fp) {
            stream_set_timeout($fp, 2);
            fwrite($fp, "flush_all\r\n");
            $resp = trim((string)fgets($fp, 512));
            fclose($fp);
            echo json_encode($resp === 'OK' ? ['ok'=>true,'msg'=>'Memcached 已清空'] : ['ok'=>false,'msg'=>'响应异常：'.($resp?:'无响应')], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['ok'=>false,'msg'=>'Memcached 未运行'], JSON_UNESCAPED_UNICODE);
        }
    } elseif ($type === 'redis') {
        $fp = @fsockopen('127.0.0.1', 6379, $e, $s, 1);
        if ($fp) {
            stream_set_timeout($fp, 2);
            fwrite($fp, "FLUSHALL\r\n");
            $resp = trim((string)fgets($fp, 512));
            fclose($fp);
            echo json_encode($resp === '+OK' ? ['ok'=>true,'msg'=>'Redis 已清空'] : ['ok'=>false,'msg'=>'响应异常：'.($resp?:'无响应')], JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['ok'=>false,'msg'=>'Redis 未运行'], JSON_UNESCAPED_UNICODE);
        }
    } else {
        echo json_encode(['ok'=>false,'msg'=>'未知缓存类型'], JSON_UNESCAPED_UNICODE);
    }
}

elseif ($action === 'scan') {
    $f = '/www/wwwroot/wafpanel/scan_status.json';
    if (is_readable($f)) {
        $d = @json_decode(@file_get_contents($f), true);
        if (is_array($d)) { echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
    }
    echo json_encode(['scanned_at'=>'-','status'=>'notrun','summary'=>['files_scanned'=>0,'high'=>0,'medium'=>0,'low'=>0,'total'=>0],'sites'=>[]], JSON_UNESCAPED_UNICODE);
}
elseif ($action === 'scan_whitelist') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $path = $in['path'] ?? '';
    $reason = $in['reason'] ?? '面板人工标记误报';
    if ($path === '') { echo json_encode(['ok'=>false,'error'=>'缺少 path']); exit; }
    $f = '/www/wwwroot/wafpanel/scan_whitelist.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    if (!isset($data['whitelisted'])) $data['whitelisted'] = [];
    $data['whitelisted'][$path] = ['reason'=>$reason, 'at'=>date('Y-m-d H:i:s')];
    @file_put_contents($f, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    @chmod($f, 0664);
    echo json_encode(['ok'=>true,'msg'=>'已加入白名单，下次扫描不再报告']);
}

elseif ($action === 'vulns') {
    $f = '/www/wwwroot/wafpanel/vulns.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    echo json_encode(['items' => $data['items'] ?? []], JSON_UNESCAPED_UNICODE);
}
elseif ($action === 'vuln_add') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $item = $in['item'] ?? [];
    if (empty($item['name'])) { echo json_encode(['ok'=>false,'error'=>'缺少漏洞名称']); exit; }
    $f = '/www/wwwroot/wafpanel/vulns.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    if (!isset($data['items'])) $data['items'] = [];
    if (!empty($item['id'])) {
        foreach ($data['items'] as &$x) { if (($x['id'] ?? 0) == $item['id']) $x = $item; }
        unset($x);
    } else {
        $item['id'] = time();
        $data['items'][] = $item;
    }
    @file_put_contents($f, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    @chmod($f, 0664);
    echo json_encode(['ok'=>true,'msg'=>'已保存']);
}
elseif ($action === 'vuln_del') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $id = $in['id'] ?? 0;
    $f = '/www/wwwroot/wafpanel/vulns.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    if (isset($data['items'])) {
        $data['items'] = array_values(array_filter($data['items'], fn($x) => ($x['id'] ?? 0) != $id));
    }
    @file_put_contents($f, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    @chmod($f, 0664);
    echo json_encode(['ok'=>true,'msg'=>'已删除']);
}

elseif ($action === 'hotlink') {
    $f = '/www/wwwroot/wafpanel/hotlink_status.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    echo json_encode(['items' => $data['items'] ?? []], JSON_UNESCAPED_UNICODE);
}
elseif ($action === 'hotlink_set') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $site = $in['site'] ?? '';
    $enable = !empty($in['enable']);
    if (!$site || !preg_match('/^[A-Za-z0-9\.\-]+$/', $site)) { echo json_encode(['ok'=>false,'error'=>'bad site']); exit; }
    @file_put_contents('/www/wwwroot/wafpanel/hotlink_request.json', json_encode(['site'=>$site,'enable'=>$enable,'at'=>date('c')]));
    @file_put_contents('/www/wwwroot/wafpanel/.reload_nginx', date('c'));
    echo json_encode(['ok'=>true,'msg'=>($enable?'开启':'关闭') . '「' . $site . '」防外链请求已提交，约1分钟内生效']);
}

elseif ($action === 'syscheck') {
    $f = '/www/wwwroot/wafpanel/sys_check.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    echo json_encode($data ?: ['scanned_at'=>'-','os'=>[],'services'=>[],'updates'=>[],'ssh'=>[],'ports'=>[],'fail2ban'=>[],'rootkit'=>[]], JSON_UNESCAPED_UNICODE);
}

elseif ($action === 'wpscan_config') {
    $tok = is_readable('/www/wwwroot/wafpanel/wpscan_token.json') ? (json_decode(@file_get_contents('/www/wwwroot/wafpanel/wpscan_token.json'), true) ?: []) : [];
    $use = is_readable('/www/wwwroot/wafpanel/wpscan_usage.json') ? (json_decode(@file_get_contents('/www/wwwroot/wafpanel/wpscan_usage.json'), true) ?: []) : [];
    echo json_encode(['configured'=>!empty($tok['token']), 'today_count'=>$use['count'] ?? 0, 'limit'=>25, 'date'=>$use['date'] ?? ''], JSON_UNESCAPED_UNICODE);
}
elseif ($action === 'wpscan_config_set') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $token = trim($in['token'] ?? '');
    if ($token !== '' && !preg_match('/^[A-Za-z0-9]+$/', $token)) { echo json_encode(['ok'=>false,'error'=>'Token 格式不对']); exit; }
    @file_put_contents('/www/wwwroot/wafpanel/wpscan_token.json', json_encode(['token'=>$token, 'updated'=>date('c')], JSON_PRETTY_PRINT));
    @chmod('/www/wwwroot/wafpanel/wpscan_token.json', 0664);
    echo json_encode(['ok'=>true,'msg'=>$token ? '已保存 WPScan API Token' : '已清除 Token（未配置）']);
}
elseif ($action === 'vuln_scan') {
    $f = '/www/wwwroot/wafpanel/vuln_scan.json';
    $data = is_readable($f) ? (json_decode(@file_get_contents($f), true) ?: []) : [];
    echo json_encode($data ?: ['scanned_at'=>'-','token_configured'=>false,'sites'=>[],'usage'=>['count'=>0,'limit'=>25]], JSON_UNESCAPED_UNICODE);
}
elseif ($action === 'scan_run') {
    @file_put_contents('/www/wwwroot/wafpanel/scan_request', date('c'));
    echo json_encode(['ok'=>true,'msg'=>'文件扫描已启动，约 1 分钟内完成']);
}

elseif ($action === 'vuln_scan_run') {
    @file_put_contents('/www/wwwroot/wafpanel/vuln_scan_request', date('c'));
    echo json_encode(['ok'=>true,'msg'=>'漏洞检测已启动，约 1 分钟内完成']);
}

else {
    echo json_encode(['error'=>'unknown action']);
}
