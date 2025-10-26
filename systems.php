<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
session_start();
require_once __DIR__ . '/db.php';
if (empty($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$pdo = db(); $uid=(int)$_SESSION['user_id']; $msg=null;

/**
 * TCP probe to test host:port reachability (short timeout).
 * Returns true if connect succeeds.
 */
function tcp_check(string $host, int $port, float $timeout = 0.8): bool {
    if ($host === '' || $port <= 0 || $port > 65535) return false;
    // strip scheme and path
    $h = preg_replace('#^\w+://#', '', $host);
    $h = strtok($h, '/');
    $address = $h . ':' . $port;
    $flags = STREAM_CLIENT_CONNECT;
    // Using stream_socket_client with a small timeout
    $ctx = stream_context_create(['socket' => ['connect_timeout' => (int)ceil($timeout)]]);
    $fp = @stream_socket_client($address, $errno, $errstr, $timeout, $flags, $ctx);
    if ($fp === false) return false;
    fclose($fp);
    return true;
}

// handle add system (unchanged)
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['add_system'])) {
    $label=trim($_POST['label']??''); $host=trim($_POST['host']??''); $port=(int)($_POST['port']??8089);
    $user=trim($_POST['ucm_user']??''); $pass=trim($_POST['ucm_pass']??'');
    if ($label && $host && $port && $user && $pass) {
        $enc=base64_encode($pass);
        $pdo->prepare('INSERT INTO systems(user_id,label,host,port,username,password_encrypted) VALUES(?,?,?,?,?,?)')->execute([$uid,$label,$host,$port,$user,$enc]);
        // Use plain ASCII quotes to avoid encoding issues (removed curly quotes that produced  )
        $msg = "System \"{$label}\" saved.";
    } else { $msg="All fields are required."; }
}

// handle delete (unchanged)
if (isset($_GET['delete'])) { $id=(int)$_GET['delete']; $pdo->prepare('DELETE FROM systems WHERE id=? AND user_id=?')->execute([$id,$uid]); $msg="System deleted."; }

// search query (by IP / FQDN / label) via GET param 'q'
$q = trim((string)($_GET['q'] ?? ''));

// fetch systems for this user, filtered by q if provided
if ($q !== '') {
    $term = '%' . str_replace(['%','_'], ['',''], $q) . '%';
    $st = $pdo->prepare('SELECT * FROM systems WHERE user_id = ? AND (host LIKE ? OR label LIKE ?) ORDER BY id DESC');
    $st->execute([$uid, $term, $term]);
} else {
    $st = $pdo->prepare('SELECT * FROM systems WHERE user_id=? ORDER BY id DESC');
    $st->execute([$uid]);
}
$systems = $st->fetchAll(PDO::FETCH_ASSOC);

// For each displayed system perform a short TCP probe to determine online/offline
foreach ($systems as &$s) {
    $port = (int)($s['port'] ?? 8089);
    $s['online'] = tcp_check($s['host'], $port, 0.8) ? true : false;
}
unset($s);
?><!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>Snom Provisioning Manager — Systems</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Inter,Roboto,system-ui,Arial;background:#f5f7fa;margin:0}
.brandbar{background:#fff;padding:10px 0;border-bottom:1px solid #e5e7eb}
.brandbar-inner{max-width:1100px;margin:0 auto;display:flex;align-items:center;justify-content:center}
.logo-bar{height:48px}
.wrap{max-width:1000px;margin:30px auto;background:#fff;border-radius:14px;box-shadow:0 6px 24px rgba(0,0,0,.05);padding:24px}
h1{margin-top:0;font-size:20px;text-align:center}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{padding:8px 10px;border-bottom:1px solid #eef2f6;text-align:left;font-size:14px}
th{background:#f4f6f9;font-weight:600}
form.add{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:20px}
input{padding:8px;border:1px solid #ccc;border-radius:8px;font-size:14px;width:100%}
.btn{background:#0073e6;color:#fff;padding:10px 16px;border:0;border-radius:8px;cursor:pointer;font-weight:600}
.msg{background:#e7f4ff;color:#004a99;padding:10px;border-radius:8px;margin:10px 0}
.action{display:flex;gap:6px}
a.btn-small{background:#0073e6;color:#fff;padding:6px 10px;border-radius:6px;text-decoration:none;font-size:13px}
a.btn-del{background:#ff4d4d}
.logout{float:right;font-size:13px;margin-top:-10px}

/* status dot next to label - minimal and matches existing design */
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:middle;border:1px solid rgba(0,0,0,0.06)}
.status-online{background:#059669}
.status-offline{background:#ef4444}

/* search input: keep same look as other inputs, no extra buttons added */
.search-input{padding:8px;border:1px solid #ccc;border-radius:8px;font-size:14px;width:100%;max-width:380px}
</style></head><body>
<div class="brandbar"><div class="brandbar-inner">
<img src="https://data.web.snom.com/m/filer_public/b2/61/b2619b3b-3dd2-471d-acc7-ba3bdb01258c/snom_logo_gray_60.svg" class="logo-bar" alt="Snom" onerror="this.src='assets/logos/snom_logo_gray_60.svg'">
</div></div>
<div class="wrap">
<h1>Snom Provisioning Manager</h1>
<div class="logout"><a href="logout.php">Logout</a></div>
<?php if($msg): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

<h2 style="font-size:17px;margin-top:0">Add UCM System</h2>
<form method="post" class="add" autocomplete="off">
<input name="label" placeholder="Label (e.g., Main Office)" required>
<input name="host" placeholder="UCM IP or FQDN" required>
<input name="port" type="number" placeholder="Port (default 8089)" value="8089" required>
<input name="ucm_user" placeholder="API Username" required>
<input name="ucm_pass" type="password" placeholder="API Password" required>
<button class="btn" name="add_system" value="1">Save System</button>
</form>

<?php if($systems): ?>
<!-- search field (simple, no extra buttons; pressing Enter will submit) -->
<form method="get" style="margin-top:18px">
  <input class="search-input" type="text" name="q" value="<?= htmlspecialchars($q) ?>" placeholder="Search by IP, FQDN or Label and press Enter">
</form>

<h2 style="font-size:17px;margin-top:20px">Saved Systems</h2>
<table><thead><tr><th>Label</th><th>Host</th><th>Port</th><th>Username</th><th>Actions</th></tr></thead><tbody>
<?php foreach($systems as $s): 
    $online = !empty($s['online']);
?>
<tr>
<td>
  <span class="status-dot <?= $online ? 'status-online' : 'status-offline' ?>" aria-hidden="true"></span>
  <?= htmlspecialchars($s['label']) ?>
</td>
<td><?= htmlspecialchars($s['host']) ?></td>
<td><?= htmlspecialchars($s['port']) ?></td>
<td><?= htmlspecialchars($s['username']) ?></td>
<td class="action">
<a class="btn-small" href="extensions.php?system_id=<?= (int)$s['id'] ?>">Configure Devices</a>
<a class="btn-small btn-del" href="?delete=<?= (int)$s['id'] ?>" onclick="return confirm('Delete system?')">Delete</a>
</td>
</tr>
<?php endforeach; ?>
</tbody></table>
<?php else: ?>
<p class="muted">No systems yet. Add one above.</p>
<?php endif; ?>
</div></body></html>