<?php
// extensions-db-persistence.php
// DB persistence helpers for extensions.php
// Save as: /var/www/html/v2.6.1c/extensions-db-persistence.php
//
// CREATE TABLE (run once, for SQLite):
//   CREATE TABLE IF NOT EXISTS system_wiz (
//     system_id INTEGER PRIMARY KEY,
//     user_id INTEGER NOT NULL,
//     data TEXT NOT NULL,
//     updated_at TEXT
//   );
//
// MySQL variant (if needed):
//   CREATE TABLE IF NOT EXISTS system_wiz (
//     system_id INT PRIMARY KEY,
//     user_id INT NOT NULL,
//     data LONGTEXT NOT NULL,
//     updated_at DATETIME
//   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
//
// The functions below are defensive and log errors to ../provision_debug.log.

function load_wiz_from_db(PDO $pdo, int $sysId, int $uid): ?array {
    try {
        $st = $pdo->prepare('SELECT data FROM system_wiz WHERE system_id = ? AND user_id = ? LIMIT 1');
        $st->execute([$sysId, $uid]);
        $row = $st->fetchColumn();
        if ($row) {
            $arr = json_decode($row, true);
            if (is_array($arr)) return $arr;
        }
    } catch (Throwable $e) {
        @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' load_wiz_from_db error: '.$e->getMessage().PHP_EOL, FILE_APPEND);
    }
    return null;
}

function save_wiz_to_db(PDO $pdo, int $sysId, int $uid, array $wiz): bool {
    $json = json_encode($wiz, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' save_wiz_to_db error: json_encode failed'.PHP_EOL, FILE_APPEND);
        return false;
    }
    $ts = date('c');
    try {
        // Try update first
        $st = $pdo->prepare('UPDATE system_wiz SET data = ?, updated_at = ? WHERE system_id = ? AND user_id = ?');
        $st->execute([$json, $ts, $sysId, $uid]);
        if ($st->rowCount() === 0) {
            $st2 = $pdo->prepare('INSERT INTO system_wiz (system_id, user_id, data, updated_at) VALUES (?,?,?,?)');
            $st2->execute([$sysId, $uid, $json, $ts]);
        }
        return true;
    } catch (Throwable $e) {
        @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' save_wiz_to_db error: '.$e->getMessage().PHP_EOL, FILE_APPEND);
        return false;
    }
}