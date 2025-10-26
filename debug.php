<?php
// Minimal temporary extensions.php — safe fallback to eliminate 500 errors.
// Backup original first (extensions.php.bak). Replace with this file to restore service immediately.

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

// Simple logout handling
if (isset($_REQUEST['logout'])) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit;
}

// If user clicks "restore backup", attempt to restore saved backup (requires file perms)
if (isset($_POST['restore_backup'])) {
    $bak = __DIR__ . '/extensions.php.bak';
    $cur = __DIR__ . '/extensions.php';
    if (file_exists($bak) && is_readable($bak)) {
        @copy($bak, $cur);
        // small pause so file system settles
        sleep(1);
        header('Location: '.$_SERVER['REQUEST_URI']);
        exit;
    } else {
        $restore_msg = "Backup not found at {$bak}";
    }
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Extensions — Temporary Safe Mode</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f6f8fb;color:#111;padding:28px}
.container{max-width:900px;margin:0 auto;background:#fff;padding:18px;border-radius:10px;box-shadow:0 8px 30px rgba(2,6,23,0.06)}
h1{margin-top:0}
.btn{display:inline-block;padding:8px 12px;border-radius:8px;background:#2563eb;color:#fff;text-decoration:none}
.note{color:#6b7280;margin-top:10px}
.small{font-size:13px;color:#6b7280}
</style>
</head>
<body>
<div class="container">
  <h1>Extensions — Temporary Safe Mode</h1>
  <p class="small">The full extensions UI is temporarily disabled while we fix a server error. Use the links below to continue working in the admin area or restore the original file.</p>

  <p>
    <a class="btn" href="systems.php">Back to Systems</a>
    <a class="btn" href="?logout=1" style="background:#ef4444">Logout</a>
  </p>

  <h3>Status</h3>
  <p class="note">
    This is a minimal fallback page that avoids DB / network calls and should not produce HTTP 500.
  </p>

  <h3>If you want to restore the previous file</h3>
  <form method="post" onsubmit="return confirm('Restore backup extensions.php.bak to extensions.php?');">
    <button type="submit" name="restore_backup" style="padding:8px 12px;border-radius:8px;background:#10b981;color:#fff;border:0;cursor:pointer">Restore Backup</button>
  </form>
  <?php if (!empty($restore_msg)): ?>
    <p class="note"><?= htmlspecialchars($restore_msg) ?></p>
  <?php endif; ?>

  <h3>Next steps (recommended)</h3>
  <ol>
    <li>Load this page in your browser. If this page loads OK, the 500 was caused by code in the original extensions.php (or something it called).</li>
    <li>Open a terminal on the server and run these commands while you reload the original page (to capture fresh errors):
      <pre style="background:#f1f5f9;padding:8px;border-radius:6px">sudo tail -f /var/log/apache2/error.log</pre>
      If your system uses a different log path, substitute it (e.g. /var/log/nginx/error.log or journalctl -u apache2).</li>
    <li>If you prefer I can keep helping: once this fallback page confirms the server is serving PHP, paste the last 60 lines from Apache error log after you attempt to open the original extensions.php (I’ll parse and give the fix).</li>
  </ol>
</div>
</body>
</html>