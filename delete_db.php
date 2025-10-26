<?php
// reset_db.php
// Small utility to reset the SQLite DB (data/app.db) so the app behaves like first-run.
//
// Usage (web):
//  - Open reset_db.php in your browser, type DELETE and click "Reset database".
// Usage (CLI):
//  - php reset_db.php --yes
//
// Safety:
//  - Web requires typing the exact word DELETE in the confirmation box.
//  - CLI requires the --yes (or -y) flag to proceed.
//
// After deletion db.php will recreate the DB automatically when the app is accessed
// and will seed the default admin user (admin / admin123).
//
// Note: ensure the webserver user (e.g., www-data) or the user running CLI has filesystem
// permissions to remove and create files in the data/ directory.

declare(strict_types=1);

ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();

$dbPath = __DIR__ . '/data/app.db';

function is_cli(): bool {
    return php_sapi_name() === 'cli' || defined('STDIN');
}

$notice = null;

// CLI flow
if (is_cli()) {
    $argv = $_SERVER['argv'] ?? [];
    $confirmed = in_array('--yes', $argv, true) || in_array('-y', $argv, true);

    if (!$confirmed) {
        echo "WARNING: This will delete the SQLite DB file at: {$dbPath}\n";
        echo "If you really want to delete it, run:\n";
        echo "  php reset_db.php --yes\n";
        exit(0);
    }

    // attempt removal
    if (file_exists($dbPath)) {
        if (@unlink($dbPath)) {
            // Clear sessions (best effort)
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_unset();
                session_destroy();
            }
            echo "Database file deleted successfully. The application will recreate the DB on next access.\n";
            exit(0);
        } else {
            echo "Failed to delete {$dbPath}. Check file permissions.\n";
            exit(2);
        }
    } else {
        echo "Database file not found at {$dbPath}. Nothing to delete.\n";
        exit(0);
    }
}

// Web flow
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm'])) {
    $in = (string)$_POST['confirm'];
    if ($in === 'DELETE') {
        if (file_exists($dbPath)) {
            if (@unlink($dbPath)) {
                // Clear session so logged-in state doesn't persist
                session_unset();
                session_destroy();
                $notice = "Database file deleted successfully. The application will recreate the DB on next access. Default admin is 'admin' / 'admin123'.";
            } else {
                $notice = "Failed to delete {$dbPath}. Please check file permissions for the webserver user.";
            }
        } else {
            $notice = "Database file not found at {$dbPath}. The application already looks fresh.";
        }
    } else {
        $notice = "Confirmation text didn't match. Type DELETE (uppercase) to confirm.";
    }
}
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Reset Application Database</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:Inter,Roboto,Arial,sans-serif;background:#f6f8fb;padding:24px}
    .card{max-width:800px;margin:0 auto;background:#fff;padding:20px;border-radius:10px;box-shadow:0 8px 24px rgba(2,6,23,0.06)}
    input[type=text]{padding:8px;width:100%;box-sizing:border-box;border-radius:6px;border:1px solid #d1d5db}
    button{padding:10px 14px;border-radius:8px;background:#ef4444;color:#fff;border:0;cursor:pointer}
    .muted{color:#6b7280;font-size:13px}
    .ok{background:#ecfccb;color:#365314;padding:10px;border-radius:8px}
    .warn{background:#fff7ed;color:#92400e;padding:10px;border-radius:8px}
    pre.code{background:#f3f4f6;padding:8px;border-radius:6px}
    a.inline{color:#0b63d6}
  </style>
</head>
<body>
<div class="card">
  <h1>Reset Application Database</h1>

  <p class="muted">
    This utility deletes the SQLite database file at
    <pre class="code"><?php echo htmlspecialchars($dbPath, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></pre>
    so the app will behave as if it was launched for the first time. The installer code (db.php) will re-create the DB
    and seed an admin user (default username: <code>admin</code>, password: <code>admin123</code>).
  </p>

  <?php if ($notice !== null): ?>
    <div class="<?php echo (strpos($notice, 'Failed') !== false) ? 'warn' : 'ok'; ?>">
      <?php echo htmlspecialchars($notice, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>
    </div>
    <p style="margin-top:12px"><a class="inline" href="login.php">Go to Login</a></p>
  <?php else: ?>
    <p class="muted">Type the word <strong>DELETE</strong> in the box below and click Reset to confirm. This action is destructive and cannot be undone.</p>
    <form method="post">
      <label for="confirm">Type DELETE to confirm:</label>
      <input id="confirm" name="confirm" type="text" autocomplete="off" required>
      <div style="height:12px"></div>
      <button type="submit">Reset database</button>
    </form>

    <hr>

    <p class="muted">
      If the web server cannot delete the file because of permissions, run this script from the server shell:
    </p>
    <pre class="code">php reset_db.php --yes</pre>
    <p class="muted">Make sure the CLI user or the webserver user has read/write access to <code>data/</code>.</p>
  <?php endif; ?>
</div>
</body>
</html>