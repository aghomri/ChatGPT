<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
session_start();
require_once __DIR__ . '/db.php';
if (!empty($_SESSION['user_id'])) { header('Location: systems.php'); exit; }
$err = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    $row = get_user_by_username($u);
    if (!$row || !password_verify($p, $row['password_hash'])) {
        $err = 'Invalid username or password.';
    } else {
        $_SESSION['user_id']   = (int)$row['id'];
        $_SESSION['username']  = $row['username'];
        $_SESSION['is_master'] = ((int)$row['is_master'] === 1);
        header('Location: systems.php'); exit;
    }
}
?><!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>Login - Snom Provisioning Manager</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Inter,Roboto,system-ui,Arial,sans-serif;background:#f5f7fa;margin:0}
.brandbar{background:#fff;padding:10px 0;border-bottom:1px solid #e5e7eb}
.brandbar-inner{max-width:1100px;margin:0 auto;display:flex;gap:12px;align-items:center;justify-content:center}
.logo-bar{height:48px;width:auto;object-fit:contain}
.auth-card{max-width:420px;margin:40px auto;background:#fff;border-radius:14px;box-shadow:0 8px 28px rgba(0,0,0,.08);padding:22px;text-align:center}
.auth-form{display:flex;flex-direction:column;gap:10px;align-items:center}
.auth-form input{max-width:320px;width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:10px}
.btn{border:0;border-radius:10px;padding:10px 14px;cursor:pointer;background:#0073e6;color:#fff;width:320px;font-weight:600}
.muted{color:#667085;font-size:13px}
.alert{padding:10px;border-radius:10px;margin:8px 0;background:#ffeded;color:#a30e1b}
</style></head><body>
<div class="brandbar"><div class="brandbar-inner">
<img src="https://data.web.snom.com/m/filer_public/b2/61/b2619b3b-3dd2-471d-acc7-ba3bdb01258c/snom_logo_gray_60.svg"
     class="logo-bar"
     alt="Snom"
     onerror="this.onerror=null;this.src='assets/logos/snom_logo_gray_60.svg'">
</div></div>
<div class="auth-card"><h1>Snom Provisioning Manager</h1><p class="muted">Sign in to continue</p>
<?php if ($err): ?><div class="alert"><?= htmlspecialchars($err, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></div><?php endif; ?>
<form method="post" class="auth-form" autocomplete="off">
<label style="align-self:flex-start;margin-left:50px;color:#1f2a45;font-size:13px">Username</label>
<input name="username" value="admin" required autofocus>
<label style="align-self:flex-start;margin-left:50px;color:#1f2a45;font-size:13px">Password</label>
<input type="password" name="password" required>
<button type="submit" class="btn">Login</button>
<p class="muted" style="margin-top:8px">Default: <code>admin / admin123</code></p>
</form></div></body></html>