<?php
/**
 * ttt-waf-panel - 为 WordPress 服务器打造的 nginx 层 WAF + 安全运营面板
 *
 * Copyright 2026 TTTWorks (Aloysius Luo)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 定制安全运维面板 · 登录页（替代 HTTP Basic Auth，手机浏览器友好）
 * 密码来源：/www/wwwroot/wafpanel/panel.passwd（bcrypt，password_verify）
 * 登录成功：生成随机 token 写入 sessions/ 目录 + setcookie('waf_token', ...) 7 天有效
 * 登出：/login.php?logout
 * 防爆破：同一 IP 失败 5 次锁定 15 分钟
 * 登录日志：成功写 /www/wwwroot/wafpanel/login_log.txt（JSONL），由 login_log_geo.py 解析位置
 */
$err = '';
$BASE = '/www/wwwroot/wafpanel';
$SESS = $BASE . '/sessions';

function waf_client_ip() {
    foreach (array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR') as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = trim(explode(',', $_SERVER[$k])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}

// 登出
if (isset($_GET['logout'])) {
    $t = $_COOKIE['waf_token'] ?? '';
    if ($t) @unlink($SESS . '/' . preg_replace('/[^a-f0-9]/', '', $t));
    setcookie('waf_token', '', time() - 3600, '/', '', false, true);
    header('Location: /login.php'); exit;
}

// —— 防爆破：IP 失败计数 ——
$ip = waf_client_ip();
$fail_file = $SESS . '/fail_' . md5($ip);
function waf_fail_state($f) {
    $raw = @file_get_contents($f);
    if ($raw === false) return array(0, 0);
    $p = explode('|', trim($raw));
    return array((int)($p[0] ?? 0), (int)($p[1] ?? 0));
}
$lock_limit = 5;      // 失败 5 次
$lock_minutes = 15;   // 锁 15 分钟
list($fail_count, $fail_time) = waf_fail_state($fail_file);
$locked = ($fail_count >= $lock_limit && (time() - $fail_time) < $lock_minutes * 60);

// 登录校验
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($locked) {
        $mins = ceil(($lock_minutes * 60 - (time() - $fail_time)) / 60);
        $err = '尝试次数过多，已锁定，请 ' . $mins . ' 分钟后重试';
    } else {
        $pass = $_POST['password'] ?? '';
        $ok = false;
        // 首选 panel.passwd（bcrypt）
        $pp = @file_get_contents($BASE . '/panel.passwd');
        if ($pp !== false && trim($pp) !== '' && password_verify($pass, trim($pp))) {
            $ok = true;
        } else {
            // fallback：.htpasswd（apr1）
            $htpasswd = @file($BASE . '/.htpasswd');
            if ($htpasswd !== false) {
                foreach ($htpasswd as $line) {
                    $line = trim($line);
                    if ($line === '' || strpos($line, ':') === false) continue;
                    list($user, $hash) = explode(':', $line, 2);
                    if ($hash !== '' && crypt($pass, $hash) === $hash) { $ok = true; break; }
                }
            }
        }
        if ($ok) {
            // 清除失败记录
            @unlink($fail_file);
            // 写登录日志（时间/IP/UA，位置由 cron 解析）
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200);
            $line = json_encode(array('time' => date('Y-m-d H:i:s'), 'ip' => $ip, 'ua' => $ua), JSON_UNESCAPED_UNICODE);
            $logfile = $BASE . '/login_log.txt';
            if (!file_exists($logfile)) { @touch($logfile); }
            @chmod($logfile, 0666); // 确保 www 可写（避免文件被 root 重建后 php 写不进）
            @file_put_contents($logfile, $line . "\n", FILE_APPEND | LOCK_EX);
            // 发 token + cookie
            $token = bin2hex(random_bytes(16));
            if (!is_dir($SESS)) @mkdir($SESS, 0755, true);
            @file_put_contents($SESS . '/' . $token, (string)time());
            setcookie('waf_token', $token, time() + 7 * 86400, '/', '', false, true);
            header('Location: /index.html'); exit;
        } else {
            // 失败计数 +1
            $fail_count++;
            @file_put_contents($fail_file, $fail_count . '|' . time());
            $err = '密码错误，请重试' . ($fail_count >= $lock_limit ? '（已达 ' . $lock_limit . ' 次上限，将锁定 ' . $lock_minutes . ' 分钟）' : '');
        }
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 · 超方 WAF 防火墙 · 安全运营面板</title>
<style>
:root{--primary:#343ced;--bg:#f5f6fa;--card:#fff;--border:#e5e7eb;--muted:#6b7280;--red:#ff492c}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#1a1a2e}
.box{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:36px 32px;width:340px;box-shadow:0 10px 30px rgba(0,0,0,.05)}
.box h1{font-size:18px;margin-bottom:6px}
.box .sub{font-size:13px;color:var(--muted);margin-bottom:24px}
input[type=password]{width:100%;padding:12px 14px;border:1px solid var(--border);border-radius:8px;font-size:15px;margin-bottom:14px}
button{width:100%;padding:12px;background:var(--primary);color:#fff;border:none;border-radius:8px;font-size:15px;cursor:pointer}
.err{color:var(--red);font-size:13px;margin-bottom:10px;line-height:1.5}
.foot{font-size:12px;color:var(--muted);text-align:center;margin-top:16px}
</style>
</head>
<body>
<div class="box">
  <h1>🛡️ 超方 WAF 防火墙 · 安全运营面板</h1>
  <div class="sub">登录以查看运维状态</div>
  <?php if ($err): ?><div class="err"><?= htmlspecialchars($err) ?></div><?php endif; ?>
  <form method="post" autocomplete="on">
    <input type="password" name="password" placeholder="访问密码" required autofocus>
    <button type="submit">登 录</button>
  </form>
  <div class="foot">超方 WAF 防火墙 · 安全运营面板</div>
</div>
</body>
</html>
