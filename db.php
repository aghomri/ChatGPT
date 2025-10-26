<?php
/**
 * db.php — UTF-8 safe version (for SQLite)
 * ----------------------------------------
 * - Works identically to your original version
 * - Ensures UTF-8 for all I/O and browser output
 * - Compatible with Ti?ng Vi?t, ??????????, and all Unicode text
 */

// --- Global UTF-8 enforcement ---
if (!headers_sent()) header('Content-Type: text/html; charset=UTF-8');
ini_set('default_charset', 'UTF-8');
if (function_exists('mb_internal_encoding')) mb_internal_encoding('UTF-8');
if (function_exists('mb_http_output')) mb_http_output('UTF-8');

ini_set('display_errors', 0);
error_reporting(E_ALL);

/**
 * Returns the PDO handle for SQLite database.
 */
function db() {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $path = __DIR__ . '/data/app.db';
    $dir  = dirname($path);
    if (!is_dir($dir)) { @mkdir($dir, 0777, true); }

    $isNew = !file_exists($path);

    // Open SQLite DB
    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 5,
    ]);

    // --- PRAGMAs ---
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA temp_store = MEMORY');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    // Only applies when DB is first created
    if ($isNew) {
        $pdo->exec("PRAGMA encoding = 'UTF-8'");
    }

    // --- Tables ---
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_master INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS systems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        label TEXT,
        host TEXT,
        port INTEGER,
        username TEXT,
        password_encrypted TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS system_wiz (
        system_id INTEGER,
        user_id INTEGER,
        data TEXT NOT NULL,
        updated_at TEXT,
        PRIMARY KEY (system_id, user_id)
    )');

    // --- Seed admin if DB is empty ---
    $cnt = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($cnt === 0) {
        $hash = password_hash('admin123', PASSWORD_DEFAULT);
        $stmt = $pdo->prepare('INSERT INTO users(username, password_hash, is_master) VALUES(?,?,1)');
        $stmt->execute(['admin', $hash]);
    }

    return $pdo;
}

/**
 * Fetch user record by username.
 */
function get_user_by_username($u) {
    $st = db()->prepare('SELECT * FROM users WHERE username=?');
    $st->execute([$u]);
    return $st->fetch(PDO::FETCH_ASSOC);
}
?>
