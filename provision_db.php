<?php
// Shared DB helpers for persisting per-system UI state and SRAPS assignments.
// Merge-on-save semantics so we never clobber other subtrees.
// Guard against double include.
if (defined('PROVISION_DB_LOADED')) return;
define('PROVISION_DB_LOADED', true);

/* ========== Utils ========== */
if (!function_exists('normalize_mac_pd')) {
    function normalize_mac_pd(string $s): string { return strtoupper(preg_replace('/[^A-Fa-f0-9]/','',$s)); }
}

/* ========== system_wiz (JSON payload per system/user) ========== */
function ensure_system_wiz_table(PDO $pdo) {
    try {
        $pdo->exec("\n            CREATE TABLE IF NOT EXISTS system_wiz (\n                system_id INTEGER NOT NULL,\n                user_id   INTEGER NOT NULL,\n                data      TEXT NOT NULL,\n                updated_at TEXT,\n                PRIMARY KEY (system_id, user_id)\n            )\n        ");
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('ensure_system_wiz_table error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('ensure_system_wiz_table error: '.$e->getMessage());
    }
}

function load_wiz_from_db(PDO $pdo, int $sysId, int $userId): ?array {
    try {
        $st = $pdo->prepare('SELECT data FROM system_wiz WHERE system_id = ? AND user_id = ? LIMIT 1');
        $st->execute([$sysId, $userId]);
        $json = $st->fetchColumn();
        if ($json === false || $json === null || $json === '') return null;
        $arr = json_decode($json, true);
        return is_array($arr) ? $arr : null;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('load_wiz_from_db error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('load_wiz_from_db error: '.$e->getMessage());
        return null;
    }
}

/**
* Merge-on-save: reads current row, array_replace_recursive with $incoming, writes back.
* Pass only the subtree you want to update (e.g. ['sraps'=>...]) or a wider structure if you intend to merge more.
*/
function save_wiz_to_db(PDO $pdo, int $sysId, int $userId, array $incoming): bool {
    try {
        $cur = load_wiz_from_db($pdo, $sysId, $userId) ?: [];
        $merged = array_replace_recursive($cur, $incoming);
        $json = json_encode($merged, JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $msg = 'save_wiz_to_db json_encode failed: '.json_last_error_msg();
            if (function_exists('provision_log')) provision_log($msg);
            if (function_exists('dbg_write')) dbg_write($msg);
            return false;
        }
        $ts = date('c');
        $up = $pdo->prepare('UPDATE system_wiz SET data = ?, updated_at = ? WHERE system_id = ? AND user_id = ?');
        $up->execute([$json, $ts, $sysId, $userId]);
        if ($up->rowCount() === 0) {
            $ins = $pdo->prepare('INSERT INTO system_wiz (system_id, user_id, data, updated_at) VALUES (?,?,?,?)');
            $ins->execute([$sysId, $userId, $json, $ts]);
        }
        return true;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('save_wiz_to_db error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('save_wiz_to_db error: '.$e->getMessage());
        return false;
    }
}

/* ========== dect_assignments (optional: persistent record of SRAPS assignments) ========== */
function ensure_dect_assign_table(PDO $pdo) {
    try {
        $pdo->exec("\n            CREATE TABLE IF NOT EXISTS dect_assignments (\n                system_id     INTEGER NOT NULL,\n                mac           TEXT NOT NULL,      -- normalized 12 hex uppercase\n                profile_id    TEXT,\n                profile_label TEXT,\n                assigned_at   TEXT,\n                assigned_by   INTEGER,\n                resp_json     TEXT,\n                PRIMARY KEY (system_id, mac)\n            )\n        ");
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('ensure_dect_assign_table error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('ensure_dect_assign_table error: '.$e->getMessage());
    }
}

function save_dect_assignment(PDO $pdo, int $systemId, string $mac, array $meta, int $byUserId): bool {
    $mac = normalize_mac_pd($mac);
    if ($mac === '' || strlen($mac) !== 12) return false;
    $profile_id = (string)($meta['profile_id'] ?? '');
    $profile_label = (string)($meta['profile_label'] ?? '');
    $resp = $meta['resp'] ?? null;
    $resp_json = is_string($resp) ? $resp : (is_null($resp) ? '' : json_encode($resp, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    $assigned_at = date('c');
    try {
        $st = $pdo->prepare('INSERT INTO dect_assignments (system_id, mac, profile_id, profile_label, assigned_at, assigned_by, resp_json)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(system_id, mac) DO UPDATE SET
                profile_id=excluded.profile_id,
                profile_label=excluded.profile_label,
                assigned_at=excluded.assigned_at,
                assigned_by=excluded.assigned_by,
                resp_json=excluded.resp_json
        ');
        $st->execute([$systemId, $mac, $profile_id, $profile_label, $assigned_at, $byUserId, $resp_json]);
        return true;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('save_dect_assignment error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('save_dect_assignment error: '.$e->getMessage());
        return false;
    }
}

function delete_dect_assignment(PDO $pdo, int $systemId, string $mac): bool {
    $mac = normalize_mac_pd($mac);
    if ($mac === '' || strlen($mac) !== 12) return false;
    try {
        $st = $pdo->prepare('DELETE FROM dect_assignments WHERE system_id = ? AND mac = ?');
        $st->execute([$systemId, $mac]);
        return true;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('delete_dect_assignment error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('delete_dect_assignment error: '.$e->getMessage());
        return false;
    }
}

function load_dect_assignment(PDO $pdo, int $systemId, string $mac): ?array {
    $mac = normalize_mac_pd($mac);
    if ($mac === '' || strlen($mac) !== 12) return null;
    try {
        $st = $pdo->prepare('SELECT profile_id, profile_label, assigned_at, assigned_by, resp_json FROM dect_assignments WHERE system_id = ? AND mac = ? LIMIT 1');
        $st->execute([$systemId, $mac]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        if (!$r) return null;
        $r['resp'] = $r['resp_json'] ? json_decode($r['resp_json'], true) : null;
        unset($r['resp_json']);
        return $r;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('load_dect_assignment error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('load_dect_assignment error: '.$e->getMessage());
        return null;
    }
}

function load_all_dect_assignments(PDO $pdo, int $systemId): array {
    try {
        $st = $pdo->prepare('SELECT mac, profile_id, profile_label, assigned_at, assigned_by, resp_json FROM dect_assignments WHERE system_id = ? ORDER BY assigned_at DESC');
        $st->execute([$systemId]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        foreach ($rows as &$r) {
            $r['resp'] = $r['resp_json'] ? json_decode($r['resp_json'], true) : null;
            unset($r['resp_json']);
        }
        return $rows;
    } catch (Throwable $e) {
        if (function_exists('provision_log')) provision_log('load_all_dect_assignments error: '.$e->getMessage());
        if (function_exists('dbg_write')) dbg_write('load_all_dect_assignments error: '.$e->getMessage());
        return [];
    }
}
