<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();

$UI_BUILD = '2025-10-27 v18.7: removed global force-admin-password, added user_srtp/user_savp/filter_registrar, Lock LCD removed, custom XML sub-tabs for families, added D7xx/D1xx models';
header('X-UI-Build: '.$UI_BUILD);

ini_set('default_charset', 'UTF-8');
if (function_exists('mb_internal_encoding')) mb_internal_encoding('UTF-8');
if (function_exists('mb_http_output')) mb_http_output('UTF-8');
header('Content-Type: text/html; charset=UTF-8');

function provision_log($line){
    @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' '.$line.PHP_EOL, FILE_APPEND);
}

function clean_utf8($s) {
    if ($s === null) return '';
    if (!is_string($s)) $s = (string)$s;
    if (function_exists('mb_detect_encoding') && function_exists('mb_convert_encoding')) {
        $enc = @mb_detect_encoding($s, ['UTF-8','UTF-16','Windows-1252','ISO-8859-1'], true);
        if ($enc && $enc !== 'UTF-8') {
            $s = @mb_convert_encoding($s, 'UTF-8', $enc);
        }
    }
    return $s;
}
function sanitize_for_ui(string $s): string {
    $s = clean_utf8($s);
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $s);
    $s = preg_replace('/\s+/u', ' ', $s);
    return trim($s);
}
function e($s){
    return htmlspecialchars(sanitize_for_ui((string)$s), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function normalize_mac(string $s): string { return strtoupper(preg_replace('/[^A-Fa-f0-9]/','',$s)); }
function is_valid_mac(string $s): bool { $m = normalize_mac($s); return ($m !== '') && preg_match('/^[A-F0-9]{12}$/', $m) === 1; }
function random_password($len = 16) {
    if ($len < 1) $len = 16;
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*()-_=+[]{}?,.:;~';
    $out = ''; $max = strlen($chars)-1;
    for ($i=0;$i<$len;$i++) $out .= $chars[random_int(0,$max)];
    return $out;
}
function random_password_no_symbols($len = 16) {
    if ($len < 1) $len = 16;
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    $out = ''; $max = strlen($chars)-1;
    for ($i=0;$i<$len;$i++) $out .= $chars[random_int(0,$max)];
    return $out;
}
function fkey_cap_for_model(string $model): int {
    $m = strtoupper(trim($model));
    if ($m === 'D895') return 236;
    if (in_array($m, ['D815','D892','D865'], true)) return 220;
    if (in_array($m, ['D862','D812'], true)) return 212;
    return 212;
}
function dscp_to_tos(?string $dscp): ?int {
    if ($dscp === null) return null;
    $dscp = trim((string)$dscp);
    if ($dscp === '' || !preg_match('/^\d+$/', $dscp)) return null;
    $v = (int)$dscp;
    if ($v < 0) $v = 0;
    if ($v > 63) $v = 63;
    return $v * 4;
}

if (!file_exists(__DIR__ . '/db.php')) { provision_log('db.php missing'); die("Missing db.php - cannot continue"); }
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/sraps.php'; // SRAPS helper functions (sraps_assign_device, sraps_release_device, sraps_fetch_profiles, sraps_test_connection)

if (empty($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$uid = (int)$_SESSION['user_id'];

try { $pdo = db(); } catch (Throwable $e) { provision_log('db() error: '.$e->getMessage()); die("DB error"); }

function ensure_system_wiz_table(PDO $pdo) {
    try { $pdo->exec("CREATE TABLE IF NOT EXISTS system_wiz (system_id INTEGER, user_id INTEGER, data TEXT NOT NULL, updated_at TEXT, PRIMARY KEY (system_id, user_id))"); }
    catch (Throwable $e) { provision_log('ensure_system_wiz_table error: '.$e->getMessage()); }
}
function load_wiz_from_db(PDO $pdo, int $sysId, int $uid): ?array {
    try {
        $st = $pdo->prepare('SELECT data FROM system_wiz WHERE system_id = ? AND user_id = ? LIMIT 1');
        $st->execute([$sysId, $uid]);
        $row = $st->fetchColumn();
        if ($row) { $arr = json_decode($row, true); if (is_array($arr)) return $arr; }
    } catch (Throwable $e) { provision_log('load_wiz_from_db error: '.$e->getMessage()); }
    return null;
}
function save_wiz_to_db(PDO $pdo, int $sysId, int $uid, array $wiz): bool {
    $json = json_encode($wiz, JSON_UNESCAPED_UNICODE);
    if ($json === false) { provision_log('save_wiz_to_db json_encode failed'); return false; }
    $ts = date('c');
    try {
        $st = $pdo->prepare('UPDATE system_wiz SET data = ?, updated_at = ? WHERE system_id = ? AND user_id = ?');
        $st->execute([$json, $ts, $sysId, $uid]);
        if ($st->rowCount() === 0) {
            $st2 = $pdo->prepare('INSERT INTO system_wiz (system_id, user_id, data, updated_at) VALUES (?,?,?,?)');
            $st2->execute([$sysId, $uid, $json, $ts]);
        }
        return true;
    } catch (Throwable $e) { provision_log('save_wiz_to_db error: '.$e->getMessage()); return false; }
}
ensure_system_wiz_table($pdo);

/* Load system */
$sysId = isset($_REQUEST['system_id']) ? (int)$_REQUEST['system_id'] : 0;
$st = $pdo->prepare('SELECT * FROM systems WHERE id=? AND user_id=?');
$st->execute([$sysId, $uid]);
$sys = $st->fetch(PDO::FETCH_ASSOC);
if (!$sys) { http_response_code(404); die('<pre>Invalid or unauthorized system ID.</pre>'); }
$sys['label'] = isset($sys['label']) ? sanitize_for_ui((string)$sys['label']) : 'Provisioning';

/* All sites (Switch Site) */
$sites = [];
try {
    $stSites = $pdo->prepare('SELECT id, label, host FROM systems WHERE user_id = ? ORDER BY label ASC, id ASC');
    $stSites->execute([$uid]);
    while ($r = $stSites->fetch(PDO::FETCH_ASSOC)) {
        $sites[] = [
            'id'    => (int)$r['id'],
            'label' => sanitize_for_ui((string)($r['label'] ?? 'Site '.$r['id'])),
            'host'  => sanitize_for_ui((string)($r['host'] ?? ''))
        ];
    }
} catch (Throwable $e) { provision_log('Switch Site load error: '.$e->getMessage()); }

/* Assets/paths */
$local_logo_path = 'assets/logos/snom_logo_gray_60.svg';
$logo_src = file_exists(__DIR__.'/'.$local_logo_path)
    ? $local_logo_path
    : 'data:image/svg+xml;utf8,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" width="120" height="88"><rect rx="8" width="120" height="88" fill="#eef6ff"/><text x="50%" y="50%" font-size="20" fill="#0b2548" text-anchor="middle" dominant-baseline="central">snom</text></svg>');

$PROVISION_DIR = rtrim(__DIR__, '/').'/provisioning_files';
if (!is_dir($PROVISION_DIR)) { @mkdir($PROVISION_DIR, 0777, true); @chmod($PROVISION_DIR, 0777); }
$PUBLIC_PROVISION_PATH = '/' . trim(str_replace(rtrim($_SERVER['DOCUMENT_ROOT'],'/'), '', $PROVISION_DIR), '/');
if ($PUBLIC_PROVISION_PATH === '') $PUBLIC_PROVISION_PATH = '/provisioning_files';

/* Session wizard state */
if (!isset($_SESSION['wiz'])) $_SESSION['wiz'] = [];
if (!isset($_SESSION['wiz'][$sysId])) {
    $_SESSION['wiz'][$sysId] = [
        'exts'=>[],'assign'=>[],'settings'=>[],'generated'=>[],'global'=>[],'flash'=>null,
        'sraps'=>[
            'baseUrl'=>'https://api.sraps.snom.com/api/v1/',
            'orgId'=>'','accessKey'=>'','secretKey'=>'',
            'statusOK'=>false,'statusAt'=>'',
            'profilesCat'=>['D'=>'','M'=>'','M500'=>'','HOTEL'=>'']
        ]
    ];
}
$wiz = &$_SESSION['wiz'][$sysId];
// Load order: site-wide (user_id=0) first, then per-user overrides
if ($site_wiz = load_wiz_from_db($pdo, $sysId, 0)) {
    $_SESSION['wiz'][$sysId] = array_replace_recursive($wiz, $site_wiz);
    $wiz = &$_SESSION['wiz'][$sysId];
}
if ($user_wiz = load_wiz_from_db($pdo, $sysId, $uid)) {
    $_SESSION['wiz'][$sysId] = array_replace_recursive($wiz, $user_wiz);
    $wiz = &$_SESSION['wiz'][$sysId];
}

// Ensure sraps structure
if (!isset($wiz['sraps']) || !is_array($wiz['sraps'])) {
    $wiz['sraps'] = [
        'baseUrl'=>'https://api.sraps.snom.com/api/v1/',
        'orgId'=>'','accessKey'=>'','secretKey'=>'',
        'statusOK'=>false,'statusAt'=>'',
        'profilesCat'=>['D'=>'','M'=>'','M500'=>'','HOTEL'=>'']
    ];
} else {
    $wiz['sraps'] = array_merge([
        'baseUrl'=>'https://api.sraps.snom.com/api/v1/',
        'orgId'=>'','accessKey'=>'','secretKey'=>'',
        'statusOK'=>false,'statusAt'=>'',
        'profilesCat'=>['D'=>'','M'=>'','M500'=>'','HOTEL'=>'']
    ], $wiz['sraps']);
}

/* --- SRAPS AJAX endpoint --- */
if (isset($_GET['sraps_action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $act = (string)$_GET['sraps_action'];
    $out = null; $code = 200;
    try {
        if ($act === 'status') {
            $out = [
                'configured' => ($wiz['sraps']['baseUrl'] ?? '') !== '' && ($wiz['sraps']['orgId'] ?? '') !== '' && ($wiz['sraps']['accessKey'] ?? '') !== '' && ($wiz['sraps']['secretKey'] ?? '') !== '',
                'statusOK'   => (bool)($wiz['sraps']['statusOK'] ?? false),
                'statusAt'   => (string)($wiz['sraps']['statusAt'] ?? ''),
                'baseUrl'    => (string)($wiz['sraps']['baseUrl'] ?? 'https://api.sraps.snom.com/api/v1/'),
                'profilesCat'=> (array)($wiz['sraps']['profilesCat'] ?? ['D'=>'','M'=>'','M500'=>'','HOTEL'=>'']),
            ];
        } elseif ($act === 'save_creds' && $_SERVER['REQUEST_METHOD']==='POST') {
            $raw = file_get_contents('php://input') ?: '';
            $in = json_decode($raw, true) ?: [];
            $base = rtrim((string)($in['baseUrl'] ?? 'https://api.sraps.snom.com/api/v1/'), '/') . '/';
            $org  = trim((string)($in['orgId'] ?? ''));
            $id   = trim((string)($in['accessKey'] ?? ''));
            $secret = isset($in['secretKey']) ? (string)$in['secretKey'] : null;

            if ($secret === '********' || $secret === null) {
                $secretToStore = $wiz['sraps']['secretKey'] ?? '';
            } else {
                $secretToStore = $secret;
            }

            $wiz['sraps']['baseUrl'] = $base;
            $wiz['sraps']['orgId'] = $org;
            $wiz['sraps']['accessKey'] = $id;
            $wiz['sraps']['secretKey'] = $secretToStore;
            $wiz['sraps']['statusOK'] = false;
            $wiz['sraps']['statusAt'] = '';
            save_wiz_to_db($pdo,$sysId,$uid,$wiz);
            // Also save site-wide (user_id=0)
            $system_store = load_wiz_from_db($pdo,$sysId,0) ?: [];
            if (!isset($system_store['sraps'])) $system_store['sraps'] = [];
            $system_store['sraps'] = $wiz['sraps'];
            save_wiz_to_db($pdo,$sysId,0,$system_store);
            $out = ['ok'=>true];
        } elseif ($act === 'test') {
            $conf = $wiz['sraps'];
            if (($conf['baseUrl'] ?? '') === '' || ($conf['orgId'] ?? '') === '' || ($conf['accessKey'] ?? '') === '' || ($conf['secretKey'] ?? '') === '') {
                throw new RuntimeException('Missing SRAPS credentials');
            }
            try {
                $resp = sraps_test_connection($wiz['sraps']);
                $wiz['sraps']['statusOK'] = true;
                $wiz['sraps']['statusAt'] = date('c');
                save_wiz_to_db($pdo,$sysId,$uid,$wiz);
                // Also save site-wide (user_id=0)
                $system_store = load_wiz_from_db($pdo,$sysId,0) ?: [];
                if (!isset($system_store['sraps'])) $system_store['sraps'] = [];
                $system_store['sraps'] = $wiz['sraps'];
                save_wiz_to_db($pdo,$sysId,0,$system_store);
                $out = ['ok'=>true,'company'=>$resp['data'] ?? $resp];
            } catch (Throwable $e) {
                $wiz['sraps']['statusOK'] = false; $wiz['sraps']['statusAt'] = date('c');
                save_wiz_to_db($pdo,$sysId,$uid,$wiz);
                // Also save site-wide (user_id=0)
                $system_store = load_wiz_from_db($pdo,$sysId,0) ?: [];
                if (!isset($system_store['sraps'])) $system_store['sraps'] = [];
                $system_store['sraps'] = $wiz['sraps'];
                save_wiz_to_db($pdo,$sysId,0,$system_store);
                throw $e;
            }
        } elseif ($act === 'get_profiles') {
            $profiles = sraps_fetch_profiles($wiz['sraps']);
            $out = ['profiles'=>$profiles];
        } elseif ($act === 'get_category_profiles') {
            $out = ['ok'=>true, 'profilesCat'=>(array)($wiz['sraps']['profilesCat'] ?? ['D'=>'','M'=>'','M500'=>'','HOTEL'=>''])];
        } elseif ($act === 'save_category_profiles' && $_SERVER['REQUEST_METHOD']==='POST') {
            $raw = file_get_contents('php://input') ?: '';
            $in = json_decode($raw, true) ?: [];
            $wiz['sraps']['profilesCat'] = [
                'D'     => (string)($in['profile_D'] ?? ''),
                'M'     => (string)($in['profile_M'] ?? ''),
                'M500'  => (string)($in['profile_M500'] ?? ''),
                'HOTEL' => (string)($in['profile_HOTEL'] ?? ''),
            ];
            save_wiz_to_db($pdo,$sysId,$uid,$wiz);
            // Also save site-wide (user_id=0)
            $system_store = load_wiz_from_db($pdo,$sysId,0) ?: [];
            if (!isset($system_store['sraps'])) $system_store['sraps'] = [];
            if (!isset($system_store['sraps']['profilesCat'])) $system_store['sraps']['profilesCat'] = [];
            $system_store['sraps']['profilesCat'] = $wiz['sraps']['profilesCat'];
            save_wiz_to_db($pdo,$sysId,0,$system_store);
            $out = ['ok'=>true,'saved'=>$wiz['sraps']['profilesCat']];
        } elseif ($act === 'assign' && $_SERVER['REQUEST_METHOD']==='POST') {
            $raw = file_get_contents('php://input') ?: '';
            $in = json_decode($raw, true) ?: [];
            $mac = strtoupper(preg_replace('/[^A-Fa-f0-9]/','', (string)($in['mac'] ?? '')));
            $model = (string)($in['model'] ?? '');
            $name  = (string)($in['name'] ?? '');
            $prof  = isset($in['profileOverride']) ? (string)$in['profileOverride'] : null;
            if ($mac === '' || strlen($mac)!==12) throw new RuntimeException('mac must be 12 hex characters');
            $resp = sraps_assign_device($wiz['sraps'], $mac, $model, $name, $prof);
            $out = ['ok'=>true,'endpoint'=>$resp['data'] ?? $resp];
        } elseif ($act === 'release' && $_SERVER['REQUEST_METHOD']==='POST') {
            $raw = file_get_contents('php://input') ?: '';
            $in = json_decode($raw, true) ?: [];
            $mac = strtoupper(preg_replace('/[^A-Fa-f0-9]/','', (string)($in['mac'] ?? '')));
            if ($mac === '' || strlen($mac)!==12) throw new RuntimeException('mac must be 12 hex characters');
            $resp = sraps_release_device($wiz['sraps'], $mac);
            $out = ['ok'=>true,'endpoint'=>$resp['data'] ?? $resp];
        } else {
            $code = 400; $out = ['error'=>'Unknown action'];
        }
    } catch (Throwable $e) {
        $code = 500; $out = ['error'=>$e->getMessage()];
        provision_log("[SRAPS/AJAX] action={$act} error: " . $e->getMessage());
    }
    http_response_code($code);
    echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/* CSV parsing/upload */
function parse_mac_csv($tmpfile){
    $out=[]; $fh=@fopen($tmpfile,'r'); if(!$fh) return [false,'Cannot open file'];
    $first=fgetcsv($fh); if($first===false){ fclose($fh); return [false,'Empty CSV']; }
    $hdr=array_map('trim',$first); $hasHeader=false; $h0=strtolower($hdr[0]??'');
    if(strpos($h0,'mac')!==false||strpos($h0,'model')!==false) $hasHeader=true;
    if($hasHeader){
        while(($row=fgetcsv($fh))!==false){
            if(!isset($row[0])) continue;
            $mac=strtoupper(preg_replace('/[^A-Fa-f0-9]/','',(string)$row[0])); if($mac==='') continue;
            $model=trim($row[1]??''); $label=trim($row[2]??'');
            $out[]=['mac'=>$mac,'model'=>$model,'label'=>$label];
        }
    } else {
        $row=$hdr;
        if(isset($row[0])){ $mac=strtoupper(preg_replace('/[^A-Fa-f0-9]/','',(string)$row[0])); if($mac!=='') $out[]=['mac'=>$mac,'model'=>trim($row[1]??''),'label'=>trim($row[2]??'')]; }
        while(($row=fgetcsv($fh))!==false){
            if(!isset($row[0])) continue;
            $mac=strtoupper(preg_replace('/[^A-Fa-f0-9]/','',(string)$row[0])); if($mac==='') continue;
            $out[]=['mac'=>$mac,'model'=>trim($row[1]??''),'label'=>trim($row[2]??'')];
        }
    }
    fclose($fh);
    return [true,$out];
}
$csv_msg = '';
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_FILES['mac_csv']) && is_uploaded_file($_FILES['mac_csv']['tmp_name'])) {
    [$ok,$res]=parse_mac_csv($_FILES['mac_csv']['tmp_name']);
    if(!$ok){ $csv_msg = $res; }
    else {
        $_SESSION['mac_list'] = [];
        foreach ($res as $r) {
            $k = strtoupper(preg_replace('/[^A-Fa-f0-9]/','', (string)($r['mac'] ?? '')));
            if ($k === '') continue;
            $_SESSION['mac_list'][$k] = ['mac'=>$k,'model'=>$r['model'] ?? '','label'=>$r['label'] ?? ''];
        }
        $_SESSION['mac_mode'] = 'csv_only';
        $_SESSION['mac_prompt_shown'] = true;
        $wiz['flash'] = ['msg' => 'CSV upload completed.', 'type' => 'success'];
        save_wiz_to_db($pdo, $sysId, $uid, $wiz);
        // redirect back so JS/CLIENT reads session-updated MAC_LIST
        header('Location: extensions.php?system_id='.(int)$sysId); exit;
    }
}
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['clear_mac_list'])) { unset($_SESSION['mac_list']); $_SESSION['mac_mode']='allow_manual'; $csv_msg="MAC list cleared."; save_wiz_to_db($pdo,$sysId,$uid,$wiz); }

/* UCM helpers & load */
function api_post_json($url,$json,$cookie=null){
    $ch=curl_init($url);
    $hdr=['Content-Type: application/json;charset=UTF-8']; if($cookie)$hdr[]='Cookie: '.$cookie;
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $json,
        CURLOPT_HTTPHEADER => $hdr,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_TIMEOUT => 25,
        CURLOPT_CONNECTTIMEOUT => 8,
    ]);
    $resp=curl_exec($ch); if($resp===false){ $err=curl_error($ch); curl_close($ch); return ['error'=>$err]; }
    $code=curl_getinfo($ch,CURLINFO_RESPONSE_CODE); curl_close($ch);
    return ['http_code'=>$code,'json'=>@json_decode($resp,true),'raw'=>$resp];
}
function do_challenge($base,$user){ return api_post_json($base,json_encode(['request'=>['action'=>'challenge','user'=>$user,'version'=>'1.0']])); }
function do_login($base,$user,$token){ return api_post_json($base,json_encode(['request'=>['action'=>'login','user'=>$user,'token'=>$token]])); }
function do_listAccount($base,$cookie){ return api_post_json($base,json_encode(['request'=>['action'=>'listAccount','cookie'=>$cookie,'item_num'=>'2000','page'=>'1']])); }
function do_getSIPAccount($base,$cookie,$ext){ return api_post_json($base,json_encode(['request'=>['action'=>'getSIPAccount','cookie'=>$cookie,'extension'=>(string)$ext]])); }

$msg=''; $exts = $wiz['exts'] ?? [];
if ((isset($_POST['fetch_ucm']) && $_POST['fetch_ucm']) || empty($exts)) {
    $host=$sys['host']; $port=(int)$sys['port']; $user=$sys['username']; $pass=base64_decode($sys['password_encrypted'] ?? '');
    $base="https://{$host}:{$port}/api";
    $ch=do_challenge($base,$user);
    if(!isset($ch['json']['response']['challenge'])){ $msg="Challenge failed."; $exts=[]; }
    else {
        $token=md5($ch['json']['response']['challenge'] . $pass);
        $lo=do_login($base,$user,$token);
        if(!isset($lo['json']['response']['cookie'])){ $msg="Login failed"; $exts=[]; }
        else {
            $cookie=$lo['json']['response']['cookie'];
            $list=do_listAccount($base,$cookie);
            $result=[];
            if(isset($list['json']['response']['account']) && is_array($list['json']['response']['account'])){
                foreach($list['json']['response']['account'] as $acct){
                    $extension=$acct['extension'] ?? null; if(!$extension) continue;
                    $sip = do_getSIPAccount($base,$cookie,$extension);
                    if(isset($sip['json']['response']['extension'])) {
                        $e=$sip['json']['response']['extension'];
                        $result[]=[
                            'extension'=>$e['extension'] ?? $extension,
                            'fullname'=>sanitize_for_ui($e['fullname'] ?? ''),
                            'authid'=>$e['authid'] ?? ($e['authenticate_id'] ?? $extension),
                            'secret'=>$e['secret'] ?? ''
                        ];
                    }
                }
            }
            $exts = $wiz['exts'] = $result;
            save_wiz_to_db($pdo,$sysId,$uid,$wiz);
            $msg = $msg ?: ("Loaded ".count($exts)." extensions.");
        }
    }
}

/* Fullname map for labels */
$fullname_by_ext = [];
foreach ($exts as $ee) {
    $fullname_by_ext[(string)($ee['extension'] ?? '')] = sanitize_for_ui($ee['fullname'] ?? '');
}

/* Write profile (XML)
   Important changes:
   - keep per-device admin/http password (generated if missing)
   - include new security tags: user_srtp, user_savp, filter_registrar
   - include custom XML fragments in priority order: per-device custom (highest), family-specific (D8xx/D7xx/D1xx), then global general (lowest)
   - auto-normalize global custom XML so adjacent tags are printed line-by-line even if user pasted single-line XML
*/
function write_profile($dir, $ucm_host, $extInfo, $mac, $overrides = [], $all_exts = []) {
    $mac = strtoupper(preg_replace('/[^A-Fa-f0-9]/','', (string)$mac));
    if ($mac === '') return [false, 'Invalid MAC'];
    if (empty($dir)) $dir = rtrim(__DIR__,'/').'/provisioning_files';
    if (!is_dir($dir)) { if (!@mkdir($dir, 0777, true)) return [false, "Cannot create provisioning directory: {$dir}"]; @chmod($dir, 0777); }
    if (!is_writable($dir)) return [false, "Provisioning directory not writable: {$dir}"];

    $ext = (string)($extInfo['extension'] ?? '');
    $fullname = sanitize_for_ui((string)($extInfo['fullname'] ?? ''));
    $password = $extInfo['secret'] ?? ($overrides['auth_password'] ?? '');

    $prov_path = (string)($overrides['setting_server'] ?? '');
    $sip_server = (string)$ucm_host;

    $model = $overrides['__model'] ?? '';
    $cap = fkey_cap_for_model((string)$model);

    $blf_rows_in = is_array($overrides['__blf'] ?? []) ? $overrides['__blf'] : [];
    $blf_rows_in = array_slice($blf_rows_in, 0, max(0, (int)$cap));

    $fullname_map = [];
    foreach ($all_exts as $ae) { $fullname_map[(string)$ae['extension']] = sanitize_for_ui($ae['fullname'] ?? ''); }

    // Admin password: per-device; keep ability to set via per-device overrides (http_pass) or generate
    $admin_pass = isset($overrides['http_pass']) && $overrides['http_pass'] !== '' ? (string)$overrides['http_pass'] : random_password_no_symbols(16);
    $user_pass  = isset($overrides['user_http_pass']) && $overrides['user_http_pass'] !== '' ? (string)$overrides['user_http_pass'] : random_password(16);

    $custom_xml_global = (string)($overrides['custom_xml_general'] ?? $overrides['custom_xml_global'] ?? '');
    $custom_xml_d8 = (string)($overrides['custom_xml_d8xx'] ?? '');
    $custom_xml_d7 = (string)($overrides['custom_xml_d7xx'] ?? '');
    $custom_xml_d1 = (string)($overrides['custom_xml_d1xx'] ?? '');
    $custom_xml_ext    = (string)($overrides['custom_xml'] ?? '');

    $sip_tos = dscp_to_tos($overrides['net_dscp_sip'] ?? null);
    $rtp_tos = dscp_to_tos($overrides['net_dscp_rtp'] ?? null);
    if ($sip_tos === null) $sip_tos = 184;
    if ($rtp_tos === null) $rtp_tos = 184;

    $lan_vlan = (string)($overrides['net_vlan_lan'] ?? ($overrides['net_vlan_voice'] ?? ''));
    $pc_vlan  = (string)($overrides['net_vlan_pc'] ?? '');

    // VLAN priority 0..7
    $vlan_pc_pri = isset($overrides['vlan_pc_priority']) ? (int)$overrides['vlan_pc_priority'] : null;
    if ($vlan_pc_pri !== null) { if ($vlan_pc_pri < 0) $vlan_pc_pri = 0; if ($vlan_pc_pri > 7) $vlan_pc_pri = 7; }
    $vlan_qos = isset($overrides['vlan_qos']) ? (int)$overrides['vlan_qos'] : null;
    if ($vlan_qos !== null) { if ($vlan_qos < 0) $vlan_qos = 0; if ($vlan_qos > 7) $vlan_qos = 7; }

    $transport = strtolower((string)($overrides['sec_sip_transport'] ?? 'udp'));
    $user_host_value = $sip_server;
    if (in_array($transport, ['tcp','tls'], true)) {
        $user_host_value = $sip_server . ';transport=' . $transport;
    } elseif ($transport === 'udp') {
        $user_host_value = $sip_server;
    }

    $vm_key = (string)($overrides['vm_key'] ?? '');
    $call_waiting = (string)($overrides['call_waiting'] ?? 'on');
    $transfer_on_hangup = (string)($overrides['transfer_on_hangup'] ?? 'off');
    $transfer_on_hangup_non_pots = (string)($overrides['transfer_on_hangup_non_pots'] ?? 'off');
    $quick_transfer = (string)($overrides['quick_transfer'] ?? 'attended');
    $transfer_dialing_on = (string)($overrides['transfer_dialing_on'] ?? 'attended');
    $mute_is_dnd_in_idle = (string)($overrides['mute_is_dnd_in_idle'] ?? 'on');

    $tbook_url = (string)($overrides['contacts_tbook_url'] ?? '');

    // Security-related globals (defaults if absent)
    $user_srtp = (string)($overrides['user_srtp'] ?? ($overrides['global_user_srtp'] ?? 'off')); // on/off
    $user_savp = (string)($overrides['user_savp'] ?? ($overrides['global_user_savp'] ?? 'off')); // off/optional/mandatory
    $filter_registrar = (string)($overrides['filter_registrar'] ?? ($overrides['global_filter_registrar'] ?? 'off')); // on/off

    // Normalize values
    $user_srtp = ($user_srtp === 'on') ? 'on' : 'off';
    $allowed_savp = ['off','optional','mandatory'];
    if (!in_array($user_savp, $allowed_savp, true)) $user_savp = 'off';
    $filter_registrar = ($filter_registrar === 'on') ? 'on' : 'off';

    $xml  = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    $xml .= "<settings>\n";

    $xml .= "  <phone-settings e=\"2\">\n";

    $xml .= "    <user_active idx=\"1\" perm=\"RW\">on</user_active>\n";
    $xml .= "    <user_idle_text idx=\"1\" perm=\"RW\">".htmlspecialchars(clean_utf8($fullname), ENT_QUOTES, 'UTF-8')."</user_idle_text>\n";
    $xml .= "    <user_idle_number idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_idle_number>\n";
    $xml .= "    <user_name idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_name>\n";
    $xml .= "    <user_pname idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_pname>\n";
    if ($password !== '') $xml .= "    <user_pass idx=\"1\" perm=\"RW\">".htmlspecialchars($password, ENT_QUOTES, 'UTF-8')."</user_pass>\n";
    $xml .= "    <user_realname idx=\"1\" perm=\"RW\">".htmlspecialchars(clean_utf8($fullname), ENT_QUOTES, 'UTF-8')."</user_realname>\n";

    if ($user_host_value !== '') {
        $xml .= "    <user_host idx=\"1\" perm=\"RW\">".htmlspecialchars($user_host_value, ENT_QUOTES, 'UTF-8')."</user_host>\n";
        $xml .= "    <user_outbound idx=\"1\" perm=\"RW\">".htmlspecialchars($user_host_value, ENT_QUOTES, 'UTF-8')."</user_outbound>\n";
    }

    if ($prov_path !== '') {
        $xml .= "    <setting_server perm=\"RW\">".htmlspecialchars($prov_path, ENT_QUOTES, 'UTF-8')."</setting_server>\n";
    }

    if (!empty($overrides['codec_priority_list'])) {
        $xml .= "    <codec_priority_list idx=\"1\" perm=\"RW\">".htmlspecialchars($overrides['codec_priority_list'], ENT_QUOTES, 'UTF-8')."</codec_priority_list>\n";
    }
    if (!empty($overrides['rtp_port_start'])) {
        $xml .= "    <rtp_port_start perm=\"RW\">".htmlspecialchars($overrides['rtp_port_start'], ENT_QUOTES, 'UTF-8')."</rtp_port_start>\n";
    }
    if (!empty($overrides['rtp_port_end'])) {
        $xml .= "    <rtp_port_end perm=\"RW\">".htmlspecialchars($overrides['rtp_port_end'], ENT_QUOTES, 'UTF-8')."</rtp_port_end>\n";
    }

    $xml .= "    <codec_tos perm=\"RW\">".$rtp_tos."</codec_tos>\n";
    $xml .= "    <signaling_tos perm=\"RW\">".$sip_tos."</signaling_tos>\n";

    if ($lan_vlan !== '') {
        $xml .= "    <vlan_id perm=\"RW\">".htmlspecialchars(preg_replace('/\D/','',(string)$lan_vlan), ENT_QUOTES, 'UTF-8')."</vlan_id>\n";
        $xml .= "    <vlan_port_tagging perm=\"RW\">on</vlan_port_tagging>\n";
    }
    if ($pc_vlan !== '') {
        $xml .= "    <pc_port_vlan_id perm=\"RW\">".htmlspecialchars(preg_replace('/\D/','',(string)$pc_vlan), ENT_QUOTES, 'UTF-8')."</pc_port_vlan_id>\n";
        $xml .= "    <pc_port_tagging perm=\"RW\">on</pc_port_tagging>\n";
    }
    // VLAN priority tags as requested
    if ($vlan_pc_pri !== null) {
        $xml .= "    <vlan_pc_priority perm=\"RW\">".$vlan_pc_pri."</vlan_pc_priority>\n";
    }
    if ($vlan_qos !== null) {
        $xml .= "    <vlan_qos perm=\"RW\">".$vlan_qos."</vlan_qos>\n";
    }

    if (!empty($overrides['loc_lcd_language'])) {
        $xml .= "    <language perm=\"RW\">".htmlspecialchars($overrides['loc_lcd_language'], ENT_QUOTES, 'UTF-8')."</language>\n";
    } elseif (!empty($overrides['loc_language'])) {
        $xml .= "    <language perm=\"RW\">".htmlspecialchars($overrides['loc_language'], ENT_QUOTES, 'UTF-8')."</language>\n";
    }
    if (!empty($overrides['loc_web_language'])) {
        $xml .= "    <web_language perm=\"RW\">".htmlspecialchars($overrides['loc_web_language'], ENT_QUOTES, 'UTF-8')."</web_language>\n";
    }
    if (!empty($overrides['loc_timezone'])) {
        $xml .= "    <timezone perm=\"RW\">".htmlspecialchars($overrides['loc_timezone'], ENT_QUOTES, 'UTF-8')."</timezone>\n";
    }
    if (!empty($overrides['loc_locale'])) {
        $xml .= "    <locale perm=\"RW\">".htmlspecialchars($overrides['loc_locale'], ENT_QUOTES, 'UTF-8')."</locale>\n";
    }
    if (!empty($overrides['ntp_server'])) {
        $xml .= "    <ntp_server perm=\"RW\">".htmlspecialchars($overrides['ntp_server'], ENT_QUOTES, 'UTF-8')."</ntp_server>\n";
    }
    if (isset($overrides['ntp_refresh_timer']) && $overrides['ntp_refresh_timer'] !== '') {
        $ntpInt = (int)$overrides['ntp_refresh_timer']; if ($ntpInt < 0) $ntpInt = 0;
        $xml .= "    <ntp_refresh_timer perm=\"RW\">".$ntpInt."</ntp_refresh_timer>\n";
    }

    if (isset($overrides['contacts_ldap_enable'])) {
        $xml .= "    <ldap_enable perm=\"RW\">".($overrides['contacts_ldap_enable']==='on' ? 'on' : 'off')."</ldap_enable>\n";
    }
    $xml .= "    <dkey_directory perm=\"RW\">".htmlspecialchars($tbook_url, ENT_QUOTES, 'UTF-8')."</dkey_directory>\n";

    if (!empty($model)) {
        $modelKey = 'maint_fw_' . strtoupper($model);
        if (!empty($overrides[$modelKey])) {
            $xml .= "    <firmware perm=\"RW\">".htmlspecialchars($overrides[$modelKey], ENT_QUOTES, 'UTF-8')."</firmware>\n";
        }
    }
    if (!empty($overrides['syslog_server'])) {
        $xml .= "    <syslog_server perm=\"RW\">".htmlspecialchars($overrides['syslog_server'], ENT_QUOTES, 'UTF-8')."</syslog_server>\n";
    }

    if (isset($overrides['prov_polling_period'])) {
        $period = (int)$overrides['prov_polling_period'];
        if ($period < 0) $period = 0;
               if ($period > 3600) $period = 3600;
        if ($period > 0) {
            $xml .= "    <prov_polling_enabled perm=\"RW\">on</prov_polling_enabled>\n";
            $xml .= "    <prov_polling_mode perm=\"RW\">rel</prov_polling_mode>\n";
            $xml .= "    <prov_polling_period perm=\"RW\">".$period."</prov_polling_period>\n";
        } else {
            $xml .= "    <prov_polling_enabled perm=\"RW\">off</prov_polling_enabled>\n";
        }
    }

    if ($transport !== '' && in_array($transport, ['udp','tcp','tls'], true)) {
        $xml .= "    <user_media_transport_offer idx=\"1\" perm=\"RW\">".$transport."</user_media_transport_offer>\n";
    }
    if ($vm_key !== '') {
        $xml .= "    <user_mailbox idx=\"1\" perm=\"RW\">".htmlspecialchars($vm_key, ENT_QUOTES, 'UTF-8')."</user_mailbox>\n";
    } else {
        $xml .= "    <user_mailbox idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_mailbox>\n";
    }
    $xml .= "    <call_waiting perm=\"RW\">".htmlspecialchars($call_waiting, ENT_QUOTES, 'UTF-8')."</call_waiting>\n";
    $xml .= "    <transfer_on_hangup perm=\"RW\">".htmlspecialchars($transfer_on_hangup, ENT_QUOTES, 'UTF-8')."</transfer_on_hangup>\n";
    $xml .= "    <transfer_on_hangup_non_pots perm=\"RW\">".htmlspecialchars($transfer_on_hangup_non_pots, ENT_QUOTES, 'UTF-8')."</transfer_on_hangup_non_pots>\n";
    $xml .= "    <quick_transfer perm=\"RW\">".htmlspecialchars($quick_transfer, ENT_QUOTES, 'UTF-8')."</quick_transfer>\n";
    $xml .= "    <transfer_dialing_on perm=\"RW\">".htmlspecialchars($transfer_dialing_on, ENT_QUOTES, 'UTF-8')."</transfer_dialing_on>\n";
    $xml .= "    <mute_is_dnd_in_idle perm=\"RW\">".htmlspecialchars($mute_is_dnd_in_idle, ENT_QUOTES, 'UTF-8')."</mute_is_dnd_in_idle>\n";

    // Security options (new)
    $xml .= "    <user_srtp perm=\"RW\">".htmlspecialchars($user_srtp, ENT_QUOTES, 'UTF-8')."</user_srtp>\n";
    $xml .= "    <user_savp perm=\"RW\">".htmlspecialchars($user_savp, ENT_QUOTES, 'UTF-8')."</user_savp>\n";
    $xml .= "    <filter_registrar perm=\"RW\">".htmlspecialchars($filter_registrar, ENT_QUOTES, 'UTF-8')."</filter_registrar>\n";

    $xml .= "    <webserver_user_name perm=\"RW\">user</webserver_user_name>\n";
    $xml .= "    <webserver_user_password perm=\"RW\">".htmlspecialchars($user_pass, ENT_QUOTES, 'UTF-8')."</webserver_user_password>\n";
    $xml .= "    <http_user perm=\"RW\">admin</http_user>\n";
    $xml .= "    <webserver_admin_name perm=\"RW\">admin</webserver_admin_name>\n";
    $xml .= "    <http_pass perm=\"RW\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</http_pass>\n";
    $xml .= "    <admin_mode_password perm=\"RW\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</admin_mode_password>\n";
    $xml .= "    <webserver_admin_password perm=\"RW\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</webserver_admin_password>\n";

    // Insert custom XML in priority order:
    // 1) per-device custom XML (highest priority)
    if (trim($custom_xml_ext) !== '') {
        foreach (explode("\n", $custom_xml_ext) as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
    }
    // 2) family-specific custom XML (model-specific)
    $model_up = strtoupper(trim($model));
    if ($model_up !== '') {
        if (strpos($model_up, 'D8') === 0 && trim($custom_xml_d8) !== '') {
            foreach (explode("\n", $custom_xml_d8) as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
        } elseif (strpos($model_up, 'D7') === 0 && trim($custom_xml_d7) !== '') {
            foreach (explode("\n", $custom_xml_d7) as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
        } elseif (strpos($model_up, 'D1') === 0 && trim($custom_xml_d1) !== '') {
            foreach (explode("\n", $custom_xml_d1) as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
        }
    }
    // 3) global general custom XML (lowest priority)
    if (trim($custom_xml_global) !== '') {
        // Normalize CRLF to LF for consistent splitting
        $custom_xml_global = preg_replace("/\r\n?/", "\n", $custom_xml_global);
        // If user pasted everything on a single line (e.g. >< adjacent tags),
        // insert a newline between adjacent tags so each tag appears on its own line.
        $custom_xml_global = preg_replace('/>\s*</', ">\n<", $custom_xml_global);
        // Ensure there's a trailing newline so explode() yields last line correctly
        $custom_xml_global = rtrim($custom_xml_global) . "\n";
        foreach (explode("\n", $custom_xml_global) as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
    }

    $xml .= "  </phone-settings>\n";

    $xml .= "  <functionKeys e=\"2\">\n";
    $i = 0;
    foreach ($blf_rows_in as $row) {
        $value = (string)($row['value'] ?? '');
        if ($value === '') continue;

        if (isset($fullname_map[$value]) && $fullname_map[$value] !== '') {
            $name = $fullname_map[$value];
        } elseif (!empty($row['label'])) {
            $name = $row['label'];
        } else {
            $name = $value;
        }

        $nameEsc = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        $valEsc  = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

        $xml .= '    <fkey idx="'.(int)$i.'" context="active" short_label_mode="icon_text" short_label="'.
                $nameEsc.'" short_default_text="!!$(::)!!$(generate_via_conditional_label_short)" label_mode="icon_text" icon_type="" reg_label_mode="icon_text" ringer="Silent" park_retrieve="" label="'.
                $nameEsc.'" lp="on" default_text="!!$(::)!!$(generate_via_conditional_label_full)" perm="RW">blf '.$valEsc."</fkey>\n";

        $i++;
        if ($i >= $cap) break;
    }
    $xml .= "  </functionKeys>\n";

    $xml .= "</settings>\n";

    $file = rtrim($dir, '/')."/{$mac}.xml";
    $res = @file_put_contents($file, $xml);
    if ($res === false) {
        return [false, "Write failed for {$file}"];
    }
    @chmod($file, 0666);
    return [true, $mac];
}

/* Merge assign helper */
function merge_assign_into_session(array $postedAssign, array &$wiz, string &$errMsg): bool {
    $errors=[]; $existing=[];
    foreach ($wiz['assign'] as $aext=>$adata){ $am=normalize_mac((string)($adata['mac'] ?? '')); if($am!=='') $existing[$am]=$aext; }
    foreach ($postedAssign as $ext=>$row) {
        $raw = trim((string)($row['mac'] ?? ''));
        $macnorm = normalize_mac($raw);
        $model = trim((string)($row['model'] ?? ''));
        if ($macnorm !== '' && strlen($macnorm) !== 12) $errors[] = "Invalid MAC for {$ext}. Expect 12 hex characters.";
        else if ($macnorm !== '' && isset($existing[$macnorm]) && $existing[$macnorm] !== $ext) $errors[] = "MAC {$macnorm} already assigned to {$existing[$macnorm]}";
    }
    if (!empty($errors)) { $errMsg = implode('; ', $errors); return false; }
    foreach ($postedAssign as $ext=>$row) {
        $raw = trim((string)($row['mac'] ?? ''));
        $macnorm = normalize_mac($raw);
        $model = trim((string)($row['model'] ?? ''));
        if (!isset($wiz['assign'][$ext])) $wiz['assign'][$ext]=['mac'=>'','model'=>''];
        $wiz['assign'][$ext]['mac'] = $macnorm ?: '';
        $wiz['assign'][$ext]['model'] = $model ?: '';
    }
    return true;
}

/* POST handlers */
if (isset($wiz['edit_ext'])) unset($wiz['edit_ext']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['open_global'])) {
    header('Location: extensions.php?system_id=' . (int)$sysId . '&global=1'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['assign']) && is_array($_POST['assign']) && !isset($_POST['generate_one']) && !isset($_POST['generate_selected']) && !isset($_POST['delete_generated']) && !isset($_POST['regenerate_all_existing'])) {
    $err = '';
    if (!merge_assign_into_session($_POST['assign'], $wiz, $err)) {
        $wiz['flash']=['msg'=>$err,'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz);
        header('Location: extensions.php?system_id=' . (int)$sysId); exit;
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    $wiz['flash']=['msg'=>'Assignments saved.','type'=>'success']; save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id=' . (int)$sysId); exit;
}

/* Global Settings save (SRAPS toggles + new security options + custom xml parts) */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_global'])) {
    $incoming = (array)($_POST['global'] ?? []);
    $wiz['global'] = array_replace($wiz['global'], $incoming);

    // Booleans/toggles
    if (!isset($incoming['use_sraps'])) {
        $wiz['global']['use_sraps'] = 'off';
    } else {
        $wiz['global']['use_sraps'] = 'on';
    }
    // Respect unchecked state for the push toggle
    if (!isset($incoming['sraps_push_on_generate'])) {
        $wiz['global']['sraps_push_on_generate'] = 'off';
    } else {
        $wiz['global']['sraps_push_on_generate'] = 'on';
    }

    // Remove global force_admin_password entirely (do not persist)
    if (isset($wiz['global']['force_admin_password'])) unset($wiz['global']['force_admin_password']);
    if (isset($wiz['global']['forced_admin_password'])) unset($wiz['global']['forced_admin_password']);

    // New security options: user_srtp (on/off), user_savp (off/optional/mandatory), filter_registrar (on/off)
    $wiz['global']['user_srtp'] = (isset($incoming['user_srtp']) && $incoming['user_srtp']==='on') ? 'on' : 'off';
    $allowed_savp = ['off','optional','mandatory'];
    $savp_raw = strtolower(trim((string)($incoming['user_savp'] ?? 'off')));
    $wiz['global']['user_savp'] = in_array($savp_raw, $allowed_savp, true) ? $savp_raw : 'off';
    $wiz['global']['filter_registrar'] = (isset($incoming['filter_registrar']) && $incoming['filter_registrar']==='on') ? 'on' : 'off';

    // Custom XML per-family and general
    // IMPORTANT: store raw string (preserve newlines). Do not sanitize to single-line here.
    $wiz['global']['custom_xml_general'] = (string)($incoming['custom_xml_general'] ?? $wiz['global']['custom_xml_general'] ?? '');
    $wiz['global']['custom_xml_d8xx']   = (string)($incoming['custom_xml_d8xx'] ?? $wiz['global']['custom_xml_d8xx'] ?? '');
    $wiz['global']['custom_xml_d7xx']   = (string)($incoming['custom_xml_d7xx'] ?? $wiz['global']['custom_xml_d7xx'] ?? '');
    $wiz['global']['custom_xml_d1xx']   = (string)($incoming['custom_xml_d1xx'] ?? $wiz['global']['custom_xml_d1xx'] ?? '');

    // Defaults and clamps
    if (empty($wiz['global']['setting_server'])) {
        $wiz['global']['setting_server'] = 'v2.6.1c/provisioning_files';
    }
    if (isset($wiz['global']['prov_polling_period'])) {
        $pp = (int)$wiz['global']['prov_polling_period'];
        if ($pp < 0) $pp = 0;
        if ($pp > 3600) $pp = 3600;
        $wiz['global']['prov_polling_period'] = (string)$pp;
    }
    if (!isset($wiz['global']['codec_priority_list'])) $wiz['global']['codec_priority_list'] = 'g722,pcmu,pcma,g729,telephone-event';
    if (!isset($wiz['global']['rtp_port_start'])) $wiz['global']['rtp_port_start'] = '49152';
    if (!isset($wiz['global']['rtp_port_end'])) $wiz['global']['rtp_port_end'] = '65534';

    $wiz['flash'] = ['msg'=>'Global settings saved.','type'=>'success'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id=' . (int)$sysId . '&global=1'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit'])) {
    $ext = (string)$_POST['edit'];
    header('Location: extensions.php?system_id=' . (int)$sysId . '&edit=' . urlencode($ext)); exit;
}

/* Save per-extension settings */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_settings']) && isset($_POST['ext'])) {
    $ext = (string)$_POST['ext'];
    $settings = $wiz['settings'][$ext] ?? [];

    if (isset($_POST['cfg_http_pass_real']) && trim((string)$_POST['cfg_http_pass_real']) !== '') {
        $settings['http_pass'] = trim((string)$_POST['cfg_http_pass_real']);
    } elseif (empty($settings['http_pass'])) {
        $settings['http_pass'] = random_password_no_symbols(16);
    }

    if (isset($_POST['cfg_user_http_pass']) && trim((string)$_POST['cfg_user_http_pass']) !== '') {
        $settings['user_http_pass'] = trim((string)$_POST['cfg_user_http_pass']);
    }

    $blf=[]; $types=$_POST['cfg_blf_type']??[]; $exts_b=$_POST['cfg_blf_ext']??[]; $vals=$_POST['cfg_blf_value']??[]; $labs=$_POST['cfg_blf_label']??[];
    $max=max(count($types),count($exts_b),count($vals),count($labs));
    global $fullname_by_ext;
    for($i=1;$i<=$max;$i++){
        $t=trim((string)($types[$i]??'blf'));
        $ev=trim((string)($exts_b[$i]??'')); $vv=trim((string)($vals[$i]??'')); $ll=sanitize_for_ui((string)($labs[$i]??''));
        if($t==='none') continue;
        $val = ($ev !== '' ? $ev : $vv);
        if($val==='') continue;
        if ($ll === '') { $nm = $fullname_by_ext[$val] ?? ''; $ll = $nm !== '' ? $nm : $val; }
        $blf[]=['type'=>'blf','value'=>$val,'label'=>$ll];
    }

    $model_for_ext = $wiz['assign'][$ext]['model'] ?? '';
    $cap = fkey_cap_for_model((string)$model_for_ext);
    if (count($blf) > $cap) {
        $blf = array_slice($blf, 0, $cap);
        $wiz['flash'] = ['msg' => "F-keys limited to {$cap} for model ".(($model_for_ext?:'Unknown')).". Excess removed.", 'type' => 'warn'];
    }
    $settings['__blf'] = $blf;

    // Store per-device custom XML raw (preserve newlines)
    $settings['custom_xml'] = (string)($_POST['cfg']['custom_xml'] ?? ($settings['custom_xml'] ?? ''));

    $wiz['settings'][$ext] = $settings;
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    if (empty($wiz['flash'])) $wiz['flash']=['msg'=>"Settings saved for {$ext}.",'type'=>'success'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId.'&edit='.urlencode($ext)); exit;
}

/* Generate one */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_one']) && $_POST['generate_one']!=='') {
    if (isset($_POST['assign']) && is_array($_POST['assign'])) { $err=''; if (!merge_assign_into_session($_POST['assign'], $wiz, $err)) { $wiz['flash']=['msg'=>$err,'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; } save_wiz_to_db($pdo,$sysId,$uid,$wiz); }
    $ext=(string)$_POST['generate_one']; $found=null; foreach($exts as $e) if((string)$e['extension']===$ext){ $found=$e; break; }
    if(!$found){ $wiz['flash']=['msg'=>"Extension {$ext} not found.",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    $mac = $wiz['assign'][$ext]['mac'] ?? '';
    if ($mac===''){ $wiz['flash']=['msg'=>"No MAC assigned for {$ext}.",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    if (!is_valid_mac($mac)) { $wiz['flash']=['msg'=>"Invalid MAC for {$ext}. Expect 12 hex characters (0-9,A-F).",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    $over = $wiz['settings'][$ext] ?? [];
    if (empty($over['http_pass'])) { $over['http_pass'] = random_password_no_symbols(16); $wiz['settings'][$ext]['http_pass'] = $over['http_pass']; }
    if (empty($over['user_http_pass'])) { $over['user_http_pass'] = random_password(16); $wiz['settings'][$ext]['user_http_pass'] = $over['user_http_pass']; }
    $over['__model'] = $wiz['assign'][$ext]['model'] ?? '';
    $global = $wiz['global'] ?? [];
    $merged = array_merge($global, $over);

    // Ensure security options propagate to merged overrides (per-device override possible)
    $merged['user_srtp'] = $merged['user_srtp'] ?? ($wiz['global']['user_srtp'] ?? 'off');
    $merged['user_savp'] = $merged['user_savp'] ?? ($wiz['global']['user_savp'] ?? 'off');
    $merged['filter_registrar'] = $merged['filter_registrar'] ?? ($wiz['global']['filter_registrar'] ?? 'off');

    // propagate family custom xml into merged so write_profile can include them
    $merged['custom_xml_general'] = $merged['custom_xml_general'] ?? ($wiz['global']['custom_xml_general'] ?? '');
    $merged['custom_xml_d8xx']   = $merged['custom_xml_d8xx'] ?? ($wiz['global']['custom_xml_d8xx'] ?? '');
    $merged['custom_xml_d7xx']   = $merged['custom_xml_d7xx'] ?? ($wiz['global']['custom_xml_d7xx'] ?? '');
    $merged['custom_xml_d1xx']   = $merged['custom_xml_d1xx'] ?? ($wiz['global']['custom_xml_d1xx'] ?? '');

    if (empty($merged['setting_server'])) $merged['setting_server'] = 'v2.6.1c/provisioning_files';
    $oldfile = rtrim($PROVISION_DIR,'/')."/{$mac}.xml"; if (file_exists($oldfile)) @unlink($oldfile);
    [$ok,$res] = write_profile($PROVISION_DIR, $sys['host'], $found, $mac, $merged, $exts);
    if ($ok) {
        $wiz['generated'][$ext]=['mac'=>$res,'url'=>$PUBLIC_PROVISION_PATH.'/'.$res.'.xml','created'=>date('c')];
        $flashMsg = "Generated profile for {$ext}.";
        // Push to SRAPS if enabled & configured AND push toggle is enabled
        if ((($wiz['global']['use_sraps'] ?? 'off') === 'on') && (($wiz['global']['sraps_push_on_generate'] ?? 'off') === 'on')) {
            try {
                sraps_assign_device($wiz['sraps'], $res, $merged['__model'] ?? '', $found['fullname'] ?? '', null);
                $wiz['generated'][$ext]['sraps_assigned'] = true;
                $flashMsg .= " SRAPS assign OK.";
            } catch (Throwable $e) {
                provision_log("SRAPS assign failed for {$res}: ".$e->getMessage());
                $flashMsg .= " SRAPS assign failed: " . $e->getMessage();
            }
        } else {
            // explicitly indicate not pushed when SRAPS push toggle disabled
            if (($wiz['global']['use_sraps'] ?? 'off') === 'on') {
                $flashMsg .= " SRAPS push disabled by global setting.";
            }
        }
        $wiz['flash']=['msg'=>$flashMsg,'type'=>'success'];
    } else {
        $wiz['flash']=['msg'=>"Failed generating {$ext}: {$res}",'type'=>'warn'];
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

/* Generate selected */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_selected']) && is_array($_POST['generate_selected'])) {
    if (isset($_POST['assign']) && is_array($_POST['assign'])) { $err=''; if (!merge_assign_into_session($_POST['assign'], $wiz, $err)) { $wiz['flash']=['msg'=>$err,'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; } save_wiz_to_db($pdo,$sysId,$uid,$wiz); }
    $selected = $_POST['generate_selected']; $count=0; $errors=[]; $global = $wiz['global'] ?? [];
    foreach($selected as $ext) {
        $ext=(string)$ext; $found=null; foreach($exts as $e) if((string)$e['extension']===$ext){ $found=$e; break; }
        if(!$found){ $errors[]="Not found {$ext}"; continue; }
        $mac = $wiz['assign'][$ext]['mac'] ?? '';
        if ($mac===''){ $errors[]="No MAC for {$ext}"; continue; }
        if (!is_valid_mac($mac)) { $errors[]="Invalid MAC for {$ext}: must be 12 hex chars (0-9,A-F)"; continue; }
        $over = $wiz['settings'][$ext] ?? [];
        if (empty($over['http_pass'])) { $over['http_pass'] = random_password_no_symbols(16); $wiz['settings'][$ext]['http_pass'] = $over['http_pass']; }
        if (empty($over['user_http_pass'])) { $over['user_http_pass'] = random_password(16); $wiz['settings'][$ext]['user_http_pass'] = $over['user_http_pass']; }
        $over['__model'] = $wiz['assign'][$ext]['model'] ?? '';
        $merged = array_merge($global, $over);

        $merged['user_srtp'] = $merged['user_srtp'] ?? ($wiz['global']['user_srtp'] ?? 'off');
        $merged['user_savp'] = $merged['user_savp'] ?? ($wiz['global']['user_savp'] ?? 'off');
        $merged['filter_registrar'] = $merged['filter_registrar'] ?? ($wiz['global']['filter_registrar'] ?? 'off');

        $merged['custom_xml_general'] = $merged['custom_xml_general'] ?? ($wiz['global']['custom_xml_general'] ?? '');
        $merged['custom_xml_d8xx']   = $merged['custom_xml_d8xx'] ?? ($wiz['global']['custom_xml_d8xx'] ?? '');
        $merged['custom_xml_d7xx']   = $merged['custom_xml_d7xx'] ?? ($wiz['global']['custom_xml_d7xx'] ?? '');
        $merged['custom_xml_d1xx']   = $merged['custom_xml_d1xx'] ?? ($wiz['global']['custom_xml_d1xx'] ?? '');

        if (empty($merged['setting_server'])) $merged['setting_server'] = 'v2.6.1c/provisioning_files';
        $oldfile = rtrim($PROVISION_DIR,'/')."/{$mac}.xml"; if (file_exists($oldfile)) @unlink($oldfile);
        [$ok,$res] = write_profile($PROVISION_DIR, $sys['host'], $found, $mac, $merged, $exts);
        if ($ok) {
            $wiz['generated'][$ext]=['mac'=>$res,'url'=>$PUBLIC_PROVISION_PATH.'/'.$res.'.xml','created'=>date('c')];
            $count++;
            if ((($wiz['global']['use_sraps'] ?? 'off') === 'on') && (($wiz['global']['sraps_push_on_generate'] ?? 'off') === 'on')) {
                try {
                    sraps_assign_device($wiz['sraps'], $res, $merged['__model'] ?? '', $found['fullname'] ?? '', null);
                    $wiz['generated'][$ext]['sraps_assigned'] = true;
                } catch (Throwable $e) {
                    $errors[] = "SRAPS assign failed for {$ext}: ".$e->getMessage();
                    provision_log("SRAPS assign failed for {$res}: ".$e->getMessage());
                }
            } else {
                if (($wiz['global']['use_sraps'] ?? 'off') === 'on') {
                    // note: server-managed; record as not pushed
                    $wiz['generated'][$ext]['sraps_assigned'] = false;
                }
            }
        } else $errors[]="Failed {$ext}: {$res}";
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    $msg = "Generated {$count} profiles."; if (!empty($errors)) $msg .= ' Errors: '.implode('; ',$errors);
    $wiz['flash']=['msg'=>$msg,'type'=>$count ? 'success' : 'warn'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

/* Regenerate all existing (already have a generated file) */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['regenerate_all_existing'])) {
    $existing = array_keys($wiz['generated'] ?? []);
    if (empty($existing)) { $wiz['flash']=['msg'=>'No existing generated files to regenerate.','type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    $count=0; $errors=[]; $global = $wiz['global'] ?? [];
    foreach($existing as $ext) {
        $ext=(string)$ext; $found=null; foreach($exts as $e) if((string)$e['extension']===$ext){ $found=$e; break; }
        if(!$found){ $errors[]="Not found {$ext}"; continue; }
        $mac = $wiz['assign'][$ext]['mac'] ?? ($wiz['generated'][$ext]['mac'] ?? '');
        if ($mac===''){ $errors[]="No MAC for {$ext}"; continue; }
        if (!is_valid_mac($mac)) { $errors[]="Invalid MAC for {$ext}"; continue; }
        $over = $wiz['settings'][$ext] ?? [];
        if (empty($over['http_pass'])) { $over['http_pass'] = random_password_no_symbols(16); $wiz['settings'][$ext]['http_pass'] = $over['http_pass']; }
        if (empty($over['user_http_pass'])) { $over['user_http_pass'] = random_password(16); $wiz['settings'][$ext]['user_http_pass'] = $over['user_http_pass']; }
        $over['__model'] = $wiz['assign'][$ext]['model'] ?? '';
        $merged = array_merge($global, $over);

        $merged['user_srtp'] = $merged['user_srtp'] ?? ($wiz['global']['user_srtp'] ?? 'off');
        $merged['user_savp'] = $merged['user_savp'] ?? ($wiz['global']['user_savp'] ?? 'off');
        $merged['filter_registrar'] = $merged['filter_registrar'] ?? ($wiz['global']['filter_registrar'] ?? 'off');

        $merged['custom_xml_general'] = $merged['custom_xml_general'] ?? ($wiz['global']['custom_xml_general'] ?? '');
        $merged['custom_xml_d8xx']   = $merged['custom_xml_d8xx'] ?? ($wiz['global']['custom_xml_d8xx'] ?? '');
        $merged['custom_xml_d7xx']   = $merged['custom_xml_d7xx'] ?? ($wiz['global']['custom_xml_d7xx'] ?? '');
        $merged['custom_xml_d1xx']   = $merged['custom_xml_d1xx'] ?? ($wiz['global']['custom_xml_d1xx'] ?? '');

        if (empty($merged['setting_server'])) $merged['setting_server'] = 'v2.6.1c/provisioning_files';
        $oldfile = rtrim($PROVISION_DIR,'/')."/{$mac}.xml"; if (file_exists($oldfile)) @unlink($oldfile);
        [$ok,$res] = write_profile($PROVISION_DIR, $sys['host'], $found, $mac, $merged, $exts);
        if ($ok) {
            $wiz['generated'][$ext]=['mac'=>$res,'url'=>$PUBLIC_PROVISION_PATH.'/'.$res.'.xml','created'=>date('c')];
            $count++;
            if ((($wiz['global']['use_sraps'] ?? 'off') === 'on') && (($wiz['global']['sraps_push_on_generate'] ?? 'off') === 'on')) {
                try {
                    sraps_assign_device($wiz['sraps'], $res, $merged['__model'] ?? '', $found['fullname'] ?? '', null);
                    $wiz['generated'][$ext]['sraps_assigned'] = true;
                } catch (Throwable $e) {
                    $errors[] = "SRAPS assign failed for {$ext}: ".$e->getMessage();
                    provision_log("SRAPS assign failed for {$res}: ".$e->getMessage());
                }
            } else {
                if (($wiz['global']['use_sraps'] ?? 'off') === 'on') {
                    $wiz['generated'][$ext]['sraps_assigned'] = false;
                }
            }
        } else $errors[]="Failed {$ext}: {$res}";
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    $msg = "Regenerated {$count} profiles."; if (!empty($errors)) $msg .= ' Errors: '.implode('; ',$errors);
    $wiz['flash']=['msg'=>$msg,'type'=>$count ? 'success' : 'warn'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

/* Delete generated file */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_generated']) && $_POST['delete_generated']!=='') {
    $ext = (string)$_POST['delete_generated'];
    $gen = $wiz['generated'][$ext] ?? null;
    if (!$gen) {
        $wiz['flash']=['msg'=>"No generated file found for {$ext}.",'type'=>'warn'];
    } else {
        $mac = $gen['mac'] ?? '';
        $srapsMsg = '';
        $srapsFailed = false;
        if ($mac) {
            // If client already indicated it released the device, skip server-side release
            if (($wiz['global']['use_sraps'] ?? 'off') === 'on' && !empty($_POST['sraps_released_client'])) {
                $srapsMsg = ' SRAPS: device released by client.';
                provision_log("SRAPS release skipped server-side for {$mac} (client already released).");
            } else {
                // Try release from SRAPS if configured (server-side fallback) and report result
                if (($wiz['global']['use_sraps'] ?? 'off') === 'on') {
                    try {
                        $resp = sraps_release_device($wiz['sraps'], $mac);
                        $srapsMsg = ' SRAPS: device released.';
                        provision_log("SRAPS release OK for {$mac}");
                    } catch (Throwable $e) {
                        $srapsMsg = ' SRAPS release failed: ' . $e->getMessage();
                        $srapsFailed = true;
                        provision_log("SRAPS release failed for {$mac}: " . $e->getMessage());
                    }
                }
            }
            $file = rtrim($PROVISION_DIR,'/')."/{$mac}.xml";
            if (file_exists($file)) { @unlink($file); }
        }
        unset($wiz['generated'][$ext]);
        $flashType = $srapsFailed ? 'warn' : 'success';
        $wiz['flash']=['msg'=>"Deleted provisioning file for {$ext}." . $srapsMsg,'type'=>$flashType];
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

/* Client-side data */
$mac_list_for_js = [];
if (!empty($_SESSION['mac_list']) && is_array($_SESSION['mac_list'])) foreach($_SESSION['mac_list'] as $mac=>$info) $mac_list_for_js[]=$info;
$mac_list_json = json_encode($mac_list_for_js, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);
$assigned_macs = []; foreach ($wiz['assign'] as $aext=>$adata) { $am = normalize_mac((string)$adata['mac']); if ($am!=='') $assigned_macs[$am] = $aext; }
$assigned_macs_json = json_encode($assigned_macs, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);

/* flash -> toast */
$toast_msg = ''; $toast_type = 'success';
if (!empty($wiz['flash']) && is_array($wiz['flash'])) {
    $toast_msg = sanitize_for_ui($wiz['flash']['msg'] ?? '');
    $toast_msg = preg_replace('/\?+\s*$/', '', $toast_msg);
    $toast_type = $wiz['flash']['type'] ?? 'success';
    $wiz['flash'] = null;
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
}

/* open modals via GET */
$show_edit_ext = null;
if (isset($_GET['edit']) && trim((string)$_GET['edit']) !== '') $show_edit_ext = sanitize_for_ui((string)$_GET['edit']);
$show_global = (isset($_GET['global']) && (string)$_GET['global'] === '1');

/* Ensure passwords exist on Edit open */
if (!empty($show_edit_ext)) {
    $ext = $show_edit_ext;
    if (!isset($wiz['settings'][$ext])) $wiz['settings'][$ext] = [];
    if (empty($wiz['settings'][$ext]['http_pass'])) {
        $wiz['settings'][$ext]['http_pass'] = random_password_no_symbols(16);
    }
    if (empty($wiz['settings'][$ext]['user_http_pass'])) {
        $wiz['settings'][$ext]['user_http_pass'] = random_password(16);
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
}

/* Extension -> fullname map for JS */
$ext_to_fullname = [];
foreach ($exts as $row) {
    $ee = (string)($row['extension'] ?? '');
    $nm = sanitize_for_ui((string)($row['fullname'] ?? ''));
    if ($ee !== '') $ext_to_fullname[$ee] = $nm;
}
$ext_to_fullname_json = json_encode($ext_to_fullname, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);

/* Locale list (unique, order preserved) */
$localeCodes = array_unique([
"om_ET","om_KE","aa_ET","af_ZA","af_NA","sq_AL","sq_MK","sq_XK","am_ET","ar_EG","ar_DZ","ar_BH","ar_TD","ar_KM","ar_DJ","ar_ER","ar_IQ","ar_IL","ar_JO","ar_KW","ar_LB","ar_LY","ar_MR","ar_MA","ar_OM","ar_PS","ar_QA","ar_SA","ar_SO","ar_SD","ar_SY","ar_TN","ar_AE","ar_EH","ar_YE","ar_SS","ar_001","hy_AM","as_IN","az_AZ","az_IR","ba_RU","eu_ES","bn_BD","bn_IN","dz_BT","br_FR","bg_BG","my_MM","be_BY","km_KH","ca_ES","ca_AD","ca_FR","ca_IT","zh_CN","zh_HK","zh_MO","zh_SG","zh_TW","co_FR","hr_HR","hr_BA","cs_CZ","da_DK","da_GL","nl_NL","nl_AW","nl_BE","nl_CW","nl_SR","nl_BQ","nl_SX","en_US","en_AS","en_AI","en_AG","en_AU","en_AT","en_BS","en_BB","en_BE","en_BZ","en_BM","en_BW","en_IO","en_BI","en_CM","en_CA","en_KY","en_CX","en_CC","en_CK","en_CY","en_DK","en_DM","en_ER","en_FK","en_FJ","en_FI","en_GG","en_GM","en_DE","en_GH","en_GI","en_GD","en_GU","en_GY","en_HK","en_IN","en_IE","en_IL","en_JM","en_KE","en_KI","en_LS","en_LR","en_MO","en_MG","en_MW","en_MY","en_MT","en_MH","en_MU","en_FM","en_MS","en_NA","en_NR","en_NL","en_NZ","en_NG","en_NU","en_NF","en_MP","en_PK","en_PW","en_PG","en_PH","en_PN","en_PR","en_RW","en_KN","en_LC","en_VC","en_WS","en_SC","en_SL","en_SG","en_SI","en_SB","en_ZA","en_SH","en_SD","en_SZ","en_SE","en_CH","en_TZ","en_TK","en_TO","en_TT","en_TC","en_TV","en_UG","en_AE","en_GB","en_UM","en_VU","en_VG","en_VI","en_ZM","en_ZW","en_DG","en_IM","en_JE","en_SS","en_SX","en_001","en_150","eo_001","et_EE","fo_FO","fo_DK","fi_FI","fr_FR","fr_DZ","fr_BE","fr_BJ","fr_BF","fr_BI","fr_CM","fr_CA","fr_CF","fr_TD","fr_KM","fr_CD","fr_CG","fr_CI","fr_DJ","fr_GQ","fr_GF","fr_PF","fr_GA","fr_GP","fr_GN","fr_HT","fr_LU","fr_MG","fr_ML","fr_MQ","fr_MR","fr_MU","fr_YT","fr_MC","fr_MA","fr_NC","fr_NE","fr_RE","fr_RW","fr_SN","fr_SC","fr_PM","fr_CH","fr_SY","fr_TG","fr_TN","fr_VU","fr_WF","fr_BL","fr_MF","fy_NL","gd_GB","gl_ES","ka_GE","de_DE","de_AT","de_BE","de_IT","de_LI","de_LU","de_CH","el_GR","el_CY","kl_GL","gn_PY","gu_IN","ha_NG","ha_GH","ha_NE","he_IL","hi_IN","hu_HU","is_IS","id_ID","ia_001","iu_CA","ga_IE","ga_GB","it_IT","it_SM","it_CH","it_VA","ja_JP","jv_ID","kn_IN","ks_IN","kk_KZ","rw_RW","ky_KG","ko_KR","ko_KP","ku_TR","rn_BI","lo_LA","la_VA","lv_LV","ln_CD","ln_AO","ln_CF","ln_CG","lt_LT","mk_MK","mg_MG","ms_MY","ms_BN","ms_ID","ms_SG","ml_IN","mt_MT","mi_NZ","mr_IN","mn_MN","mn_CN","ne_NP","ne_IN","nb_NO","nb_SJ","oc_FR","or_IN","ps_AF","ps_PK","fa_IR","fa_AF","pl_PL","pt_BR","pt_AO","pt_CV","pt_TL","pt_GQ","pt_GW","pt_LU","pt_MO","pt_MZ","pt_PT","pt_ST","pt_CH","pa_IN","pa_PK","qu_PE","qu_BO","qu_EC","rm_CH","ro_RO","ro_MD","ru_RU","ru_BY","ru_KZ","ru_KG","ru_MD","ru_UA","sg_CF","sa_IN","sr_RS","sr_BA","sr_ME","sr_XK","os_GE","os_RU","st_ZA","tn_ZA","sn_ZW","sd_PK","sd_IN","si_LK","ss_ZA","sk_SK","sl_SI","so_SO","so_DJ","so_ET","so_KE","es_ES","es_AR","es_BZ","es_BO","es_BR","es_CL","es_CO","es_CR","es_CU","es_DO","es_EC","es_SV","es_GQ","es_GT","es_HN","es_MX","es_NI","es_PA","es_PY","es_PE","es_PH","es_PR","es_US","es_UY","es_VE","es_IC","es_419","es_EA","su_ID","sw_TZ","sw_CD","sw_KE","sw_UG","sv_SE","sv_FI","sv_AX","sc_IT","tg_TJ","ta_IN","ta_MY","ta_SG","ta_LK","tt_RU","te_IN","th_TH","bo_CN","bo_IN","ti_ET","ti_ER","to_TO","ts_ZA","tr_TR","tr_CY","tk_TM","ug_CN","uk_UA","ur_PK","ur_IN","uz_UZ","uz_AF","vi_VN","vo_001","cy_GB","wo_SN","xh_ZA","yi_001","yo_NG","yo_BJ","zu_ZA","nn_NO","bs_BA","dv_MV","gv_IM","kw_GB","ak_GH","kok_IN","gaa_GH","ig_NG","kam_KE","syr_IQ","byn_ER","gez_ET","sid_ET","cch_NG","tig_ER","kaj_NG","fur_IT","ve_ZA","ee_GH","ee_TG","wal_ET","haw_US","kcg_NG","ny_MW","fil_PH","gsw_CH","gsw_FR","gsw_LI","ii_CN","kpe_LR","nds_DE","nds_NL","nr_ZA","nso_ZA","se_NO","se_FI","se_SE","trv_TW","guz_KE","dav_KE","ff_SN","ff_BF","ff_CM","ff_GM","ff_GH","ff_GN","ff_GW","ff_LR","ff_MR","ff_NE","ff_NG","ff_SL","ki_KE","saq_KE","seh_MZ","nd_ZW","rof_TZ","shi_MA","kab_DZ","nyn_UG","bez_TZ","vun_TZ","bm_ML","ebu_KE","chr_US","mfe_MU","kde_TZ","lag_TZ","lg_UG","bem_ZM","kea_CV","mer_KE","kln_KE","naq_NA","jmc_TZ","ksh_DE","mas_KE","mas_TZ","xog_UG","luy_KE","asa_TZ","teo_UG","teo_KE","ssy_ER","khq_ML","rwk_TZ","luo_KE","cgg_UG","tzm_MA","ses_ML","ksb_TZ","brx_IN","ce_RU","cu_RU","cv_RU","lu_CD","lb_LU","nv_US","wa_BE","agq_CM","bas_CM","dje_NE","dua_CM","dyo_SN","ewo_CM","ksf_CM","mgh_MZ","mua_CM","nmg_CM","nus_SS","sah_RU","sbp_TZ","twq_NE","vai_LR","wae_CH","yav_CM","ast_ES","jgo_CM","kkj_CM","mgo_CM","nnh_CM","an_ES","doi_IN","mni_IN","sat_IN","blt_VN","bss_CM","lkt_US","zgh_MA","arn_CL","ckb_IQ","ckb_IR","dsb_DE","hsb_DE","ken_CM","moh_CA","nqo_GN","prg_001","quc_GT","sma_SE","smj_SE","smn_FI","sms_FI","wbp_AU","mai_IN","mzn_IR","lrc_IR","lrc_IQ","yue_HK","yue_CN","osa_US","io_001","jbo_001","scn_IT","sdh_IR","bgn_PK","ceb_PH","myv_RU","cic_US","mus_US","szl_PL","pcm_NG"
]);

/* Render */
$title_safe = sanitize_for_ui((string)($sys['label'] ?? 'Provisioning'));
$sraps_ok = isset($wiz['sraps']) && !empty($wiz['sraps']['statusOK']);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?= e($title_safe) ?> - Extensions</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f5f7fb;--card:#fff;--muted:#5b6472;--ink:#0d1321;--accent:#2f3bd6;--accent-2:#0ea5e9;--danger:#dc2626;
  --border:#e6eaf2;--tab:#eef2ff;--radius:12px;--shadow:0 10px 30px rgba(2,6,23,0.08)
}
*{box-sizing:border-box}
body{background:var(--bg);margin:18px;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial;color:var(--ink)}
.container{max-width:1220px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.logo{height:48px;width:auto;border-radius:10px;padding:6px;background:#fff;object-fit:contain;border:1px solid var(--border)}
.small{font-size:13px;color:var(--muted)}
.btn{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:8px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;font-weight:600;font-size:12px}
.btn.secondary{background:#334155}
.btn.warn{background:var(--danger)}
.btn.ghost{background:#eef2ff;color:#0b2548}
.btn.inline{padding:6px 9px}
.header-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.table{margin-top:14px;border-radius:14px;overflow:hidden;box-shadow:var(--shadow);border:1px solid var(--border);background:var(--card)}
.table table{width:100%;border-collapse:collapse}
.table th, .table td{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:middle}
.table thead th{background:#fafcff; text-align:left}
.macs-input, select[name$="[model]"], .small-input, select.small-input{height:30px;padding:6px 8px;border-radius:10px;border:1px solid var(--border);font-size:12px;background:#fff;width:100%}
.mac-combo-input{width:220px;text-transform:uppercase}
.row-actions{display:flex;gap:8px;align-items:center;white-space:nowrap}
.sel-chk{width:18px;height:18px;margin:0}
.modal-card{width:920px;max-width:100%;max-height:92vh;overflow:auto;background:var(--card);border-radius:16px;padding:18px;box-shadow:0 40px 90px rgba(2,6,23,0.18);border:1px solid var(--border)}
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--border);margin-bottom:12px;flex-wrap:nowrap;white-space:nowrap;overflow:visible}
.tab{padding:6px 9px;border-radius:10px 10px 0 0;background:var(--tab);cursor:pointer;color:#0b2548;font-weight:600;flex:0 0 auto;font-size:12px}
.tab.active{background:#fff;border:1px solid var(--border);border-bottom-color:#fff}
.tabpanel{display:none}
.tabpanel.active{display:block}
.form-grid{display:grid;grid-template-columns:200px 1fr;gap:8px 12px;align-items:center}
.form-grid .label{color:#475569;font-size:12px}
.form-grid .value{width:100%}
.area{width:100%;min-height:120px;padding:8px;border:1px solid var(--border);border-radius:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.section-card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:12px;margin-bottom:12px}
.group-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:10px}
.mac-combo{position:relative;display:inline-block}
.mac-combo-list{position:absolute;left:0;right:0;top:calc(100% + 6px);background:#fff;border:1px solid var(--border);border-radius:10px;max-height:220px;overflow:auto;z-index:120;box-shadow:var(--shadow);display:none}
.mac-combo-item{padding:8px 10px;border-bottom:1px solid var(--border);cursor:pointer;font-family:monospace}
.mac-combo-item:hover,.mac-combo-item.active{background:#f1f7ff}
.mac-combo-empty{padding:8px 10px;color:#64748b}

/* Actions bar and search */
.actions-bar{display:flex;align-items:center;gap:8px;flex-wrap:nowrap;white-space:nowrap;overflow-x:auto;padding-bottom:2px}
.search-input{height:30px;padding:6px 8px;border:1px solid var(--border);border-radius:10px;font-size:12px;width:240px;min-width:180px}

/* Toasts */
/* success -> green; warn/error -> red */
.center-toast-overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.05);z-index:99999}
.center-toast{display:flex;align-items:center;gap:12px;background:#16a34a;color:#fff;border-radius:10px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.25);max-width:80vw}
.center-toast.warn{background:#dc2626} /* error/warn: red */
.close-btn{appearance:none;border:0;background:transparent;color:#fff;font-size:20px;cursor:pointer}

/* SRAPS dot */
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;background:#dc2626}
.dot.ok{background:#16a34a}
.dot.bad{background:#dc2626}
</style>
<?php
$themeRel = 'assets/css/theme-snom.css';
$themeAbs = __DIR__ . '/' . $themeRel;
$baseDir = isset($_SERVER['SCRIPT_NAME']) ? rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') : '';
$themeHref = ($baseDir === '' ? '' : $baseDir . '/') . $themeRel;
if (!file_exists($themeAbs) && isset($_SERVER['DOCUMENT_ROOT']) && is_file($_SERVER['DOCUMENT_ROOT'] . '/assets/css/theme-snom.css')) {
    $themeHref = '/assets/css/theme-snom.css';
    $themeAbs = $_SERVER['DOCUMENT_ROOT'] . '/assets/css/theme-snom.css';
}
$themeVer = file_exists($themeAbs) ? (int)filemtime($themeAbs) : time();
?>
<link rel="stylesheet" href="<?= e($themeHref) ?>?v=<?= $themeVer ?>">
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <img id="site-logo" src="<?= e($logo_src) ?>" class="logo" alt="logo" onerror="this.onerror=null;this.src='<?= e($local_logo_path) ?>';">
      <div>
        <div style="font-weight:700"><?= e($title_safe) ?></div>
        <div class="small">Host: <?= e((string)$sys['host'] ?? '') ?></div>
      </div>
    </div>

    <div class="header-actions">
      <button id="open-sraps" class="btn inline" type="button" title="SRAPS">
        <span id="sraps-dot" class="dot <?= $sraps_ok ? 'ok' : 'bad' ?>"></span>
        SRAPS
      </button>
      <button class="btn secondary inline" type="button" onclick="document.getElementById('switch-site-modal').style.display='flex'">Switch Site</button>
      <a href="logout.php" class="btn warn inline" style="text-decoration:none">Logout</a>
      <form method="post" style="margin:0"><input type="hidden" name="fetch_ucm" value="1"><button class="btn secondary inline" type="submit">Refresh Extensions</button></form>
      <form method="post" style="margin:0"><input type="hidden" name="regenerate_all_existing" value="1"><button class="btn inline" type="submit">Regenerate All Existing</button></form>
      <form method="post" enctype="multipart/form-data" style="margin:0;display:inline-flex;align-items:center;gap:6px">
        <input type="file" name="mac_csv" id="mac_csv_input" accept=".csv">
        <button class="btn inline" type="submit">Upload CSV</button>
      </form>
    </div>
  </div>

  <?php if (!empty($csv_msg)): ?><div style="margin-top:6px" class="small"><?= e($csv_msg) ?></div><?php endif; ?>

  <div style="margin-top:12px;">
    <div class="actions-bar">
      <form method="post" style="margin:0;display:inline">
        <button class="btn inline" type="submit" name="open_global" value="1">Global Settings</button>
      </form>
      <button class="btn inline" id="save-assignments-btn" type="button" onclick="document.getElementById('assign-form').submit()">Save Assignments</button>
      <!-- D7xx top-level button removed per request -->
      <button class="btn inline" type="button" onclick="location.href='dect.php?system_id=<?= (int)$sysId ?>'">DECT</button>
      <button class="btn inline" type="button" onclick="location.href='m500.php?system_id=<?= (int)$sysId ?>'">M500</button>
      <button class="btn inline" type="button" onclick="location.href='hotel.php?system_id=<?= (int)$sysId ?>'">Hotel Phones</button>

      <!-- Inline dynamic search (no server calls) -->
      <input id="search-all" class="search-input" type="text" placeholder="Search name, ext, MAC, model" aria-label="Search">
      <button id="search-btn" class="btn inline" type="button">Search</button>
    </div>
  </div>

  <div class="table" style="margin-top:12px">
    <form method="post" id="assign-form">
      <table id="ext-table">
        <thead><tr><th></th><th style="width:120px">Extension</th><th>Fullname</th><th style="width:260px">MAC</th><th style="width:180px">Model</th><th style="width:320px">Actions</th></tr></thead>
        <tbody>
        <?php if (!empty($exts)): foreach ($exts as $r):
          $ext = sanitize_for_ui((string)$r['extension']);
          $full = sanitize_for_ui((string)$r['fullname']);
          $macVal = $wiz['assign'][$ext]['mac'] ?? ''; $modelVal = $wiz['assign'][$ext]['model'] ?? ''; $isGen = isset($wiz['generated'][$ext]);
          $comboId = 'mac_combo_'.preg_replace('/[^A-Za-z0-9_-]/','_',$ext);
        ?>
          <tr>
            <td><input type="checkbox" class="sel-chk" value="<?= e($ext) ?>"></td>
            <td class="col-ext"><?= e($ext) ?></td>
            <td class="col-full"><?= e($full) ?></td>
            <td class="col-mac">
              <div class="mac-combo" data-ext="<?= e($ext) ?>">
                <input type="text" name="assign[<?= e($ext) ?>][mac]" value="<?= e($macVal) ?>" class="mac-combo-input macs-input" data-combo-id="<?= e($comboId) ?>" placeholder="AABBCCDDEEFF" maxlength="17" autocomplete="off" aria-label="MAC for <?= e($ext) ?>">
                <div class="mac-combo-list" id="<?= e($comboId) ?>" role="listbox" aria-label="MAC suggestions"></div>
              </div>
            </td>
            <td class="col-model">
              <select name="assign[<?= e($ext) ?>][model]" class="small-input">
                <option value="">Select</option>
                <?php
                $models = ['D862','D865','D895','D892','D815','D812','D785','D735','D717','D713','D150','D140','D120'];
                foreach ($models as $m) { $sel = ($modelVal === $m) ? 'selected' : ''; echo "<option value=\"".e($m)."\" $sel>".e($m)."</option>"; }
                ?>
              </select>
            </td>
            <td>
              <div class="row-actions" role="group">
                <button class="btn inline" type="button" onclick="postGenerate('<?= e($ext) ?>')"><?= $isGen ? 'Regenerate' : 'Generate' ?></button>
                <button class="btn secondary inline" type="button" onclick="postEdit('<?= e($ext) ?>')">Edit</button>
                <?php if ($isGen): $url = $wiz['generated'][$ext]['url'] ?? ''; if ($url): ?>
                  <a class="btn secondary inline" href="<?= e($url) ?>" target="_blank" rel="noopener noreferrer">Download</a>
                <?php endif; ?>
                  <button type="button" class="btn warn inline" onclick="confirmDelete('<?= e($ext) ?>')">Delete File</button>
                <?php endif; ?>
              </div>
            </td>
          </tr>
        <?php endforeach; else: ?>
          <tr><td colspan="6" class="small">No extensions found. Use Refresh Extensions to fetch from UCM.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </form>
  </div>
</div>

<!-- Switch Site modal -->
<div id="switch-site-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);align-items:center;justify-content:center;z-index:9998">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="switch-site-title" style="max-width:520px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 id="switch-site-title" style="margin:0">Switch Site</h3>
      <div><button type="button" class="btn secondary inline" onclick="document.getElementById('switch-site-modal').style.display='none'">Close</button></div>
    </div>
    <div style="display:flex;flex-direction:column;gap:12px">
      <label>Choose a site
        <select id="switch-site-select" class="small-input" style="width:100%">
          <?php if (!empty($sites)): foreach ($sites as $s): ?>
            <option value="<?= (int)$s['id'] ?>" <?= ((int)$s['id'] === (int)$sysId) ? 'selected' : '' ?>>
              <?= e($s['label']) ?> <?= $s['host'] ? '(' . e($s['host']) . ')' : '' ?>
            </option>
          <?php endforeach; else: ?>
            <option value="">No sites found</option>
          <?php endif; ?>
        </select>
      </label>
      <div style="text-align:right">
        <button type="button" class="btn secondary inline" onclick="document.getElementById('switch-site-modal').style.display='none'">Cancel</button>
        <button type="button" class="btn inline" onclick="switchSiteGo()">Go</button>
      </div>
    </div>
  </div>
</div>

<!-- Global Settings modal -->
<?php if ($show_global): ?>
<div id="global-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9998">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="global-modal-title" style="max-width:920px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h3 id="global-modal-title" style="margin:0;font-size:16px">Global Settings</h3>
      <div><a class="btn secondary inline" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Close</a></div>
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="tab-loc">Localization</div>
      <div class="tab" data-tab="tab-contacts">Contact List</div>
      <div class="tab" data-tab="tab-maint">Maintenance</div>
      <div class="tab" data-tab="tab-net">Network</div>
      <div class="tab" data-tab="tab-sec">Security</div>
      <div class="tab" data-tab="tab-prov">Provisioning</div>
      <div class="tab" data-tab="tab-call">Call Features</div>
      <div class="tab" data-tab="tab-custom">Custom XML</div>
      <div class="tab" data-tab="tab-sraps">SRAPS</div>
    </div>

    <form method="post" style="display:block">
      <!-- Localization -->
      <div id="tab-loc" class="tabpanel active">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">Web UI Language</div>
            <div class="value">
              <select class="small-input" name="global[loc_web_language]">
                <?php
                $webLang = $wiz['global']['loc_web_language'] ?? 'English';
                $webOpts = ["English","Dansk","Deutsch","Español","Français","Italiano","Polski","Svenska","Українська"];
                foreach ($webOpts as $opt) { $sel = ($webLang === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
                ?>
              </select>
            </div>

            <div class="label">Phone LCD Language</div>
            <div class="value">
              <select class="small-input" name="global[loc_lcd_language]">
                <?php
                $lcdLang = $wiz['global']['loc_lcd_language'] ?? ($wiz['global']['loc_language'] ?? 'English');
                $lcdOpts = ["English","Dansk","Deutsch","Español","Français","Italiano","Magyar","Nederlands","Polski","Svenska","Tiếng Việt","Українська"];
                foreach ($lcdOpts as $opt) { $sel = ($lcdLang === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
                ?>
              </select>
            </div>

            <div class="label">Time Zone</div>
            <div class="value">
              <select class="small-input" name="global[loc_timezone]">
                <?php
                $tz = $wiz['global']['loc_timezone'] ?? '';
                $tzOpts = [
                  'USA-10','USA-9','CAN-8','MEX-8','USA-8','CAN-7','MEX-7','USA2-7','USA-7','CAM-6','CAN-6','CAN2-6','CHL-6','MEX-6','USA-6',
                  'BHS-5','CAN-5','CUB-5','USA-5','VEN-4.5','CAN-4','CHL-4','PRY-4','BMU-4','FLK-4','TTB-4','CAN-3.5','GRL-3','ARG-3','BRA2-3','BRA1-3',
                  'BRA-2','PRT-1','FRO-0','IRL-0','PRT-0','ESP-0','GBR-0','ALB+1','AUT+1','BEL+1','CAI+1','CHA+1','HRV+1','CZE+1','DNK+1','FRA+1','GER+1',
                  'HUN+1','ITA+1','LUX+1','MAK+1','NLD+1','NAM+1','NOR+1','POL+1','SVK+1','ESP+1','SWE+1','CHE+1','GIB+1','YUG+1','WAT+1','BLR+2','BGR+2',
                  'CYP+2','CAT+2','EGY+2','EST+2','FIN+2','GAZ+2','GRC+2','ISR+2','JOR+2','LVA+2','LBN+2','MDA+2','RUS+2','ROU+2','SYR+2','TUR+2','UKR+2',
                  'EAT+3','IRQ+3','RUS+3','IRN+3.5','ARM+4','AZE+4','GEO+4','KAZ+4','RUS+4','KAZ+5','KGZ+5','PAK+5','RUS+5','IND+5.5','KAZ+6','RUS+6',
                  'RUS+7','THA+7','CHN+7','SGP+8','KOR+8','AUS+8','JPN+9','AUS+9.5','AUS2+9.5','AUS+10','AUS2+10','AUS3+10','RUS+10','AUS+10.5',
                  'NCL+11','NZL+12','RUS+12','NZL+12.75','TON+13'
                ];
                echo '<option value=""></option>';
                foreach ($tzOpts as $opt) { $sel = ($tz === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
                ?>
              </select>
            </div>

            <div class="label">Locale (date/time)</div>
            <div class="value">
              <select class="small-input" name="global[loc_locale]">
                <?php
                  $loc = $wiz['global']['loc_locale'] ?? 'en_US';
                  foreach ($localeCodes as $code) {
                      $sel = ($loc === $code) ? 'selected' : '';
                      echo '<option value="'.e($code).'" '.$sel.'>'.e($code).'</option>';
                  }
                ?>
              </select>
            </div>

            <div class="label">NTP Server</div>
            <div class="value">
              <input class="small-input" name="global[ntp_server]" value="<?= e($wiz['global']['ntp_server'] ?? 'pool.ntp.org') ?>" placeholder="pool.ntp.org">
            </div>

            <div class="label">NTP Update Interval (sec)</div>
            <div class="value">
              <input class="small-input" name="global[ntp_refresh_timer]" value="<?= e($wiz['global']['ntp_refresh_timer'] ?? '3600') ?>" placeholder="3600">
            </div>
          </div>
        </div>
      </div>

      <!-- Contact List -->
      <div id="tab-contacts" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">Enable LDAP</div>
            <div class="value">
              <select class="small-input" name="global[contacts_ldap_enable]">
                <?php $en = $wiz['global']['contacts_ldap_enable'] ?? 'off';
                foreach (['on'=>'On','off'=>'Off'] as $k=>$v){ $sel=($en===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
              </select>
            </div>

            <div class="label">Tbook URL</div>
            <div class="value">
              <input class="small-input" name="global[contacts_tbook_url]" value="<?= e($wiz['global']['contacts_tbook_url'] ?? '') ?>" placeholder="http(s)://.../tbook.xml">
            </div>
          </div>
        </div>
      </div>

      <!-- Maintenance -->
      <div id="tab-maint" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <?php
              $models = ['D895','D892','D865','D862','D815','D812','D785','D735','D717','D713','D150','D140','D120','D810WB'];
              foreach ($models as $m) {
                $key = 'maint_fw_'.strtoupper($m);
                $val = $wiz['global'][$key] ?? '';
                echo '<div class="label">Firmware URL - '.e($m).'</div><div class="value"><input class="small-input" name="global['.e($key).']" value="'.e($val).'" placeholder="http(s)://.../'.e($m).'/firmware.bin"></div>';
              }
            ?>
            <div class="label">Syslog Server</div>
            <div class="value"><input class="small-input" name="global[syslog_server]" value="<?= e($wiz['global']['syslog_server'] ?? '') ?>" placeholder="host or IP"></div>
          </div>
        </div>
      </div>

      <!-- Network -->
      <div id="tab-net" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">VLAN (LAN)</div>
            <div class="value"><input class="small-input" name="global[net_vlan_lan]" value="<?= e($wiz['global']['net_vlan_lan'] ?? ($wiz['global']['net_vlan_voice'] ?? '')) ?>" placeholder="e.g. 20"></div>

            <div class="label">VLAN (PC)</div>
            <div class="value"><input class="small-input" name="global[net_vlan_pc]" value="<?= e($wiz['global']['net_vlan_pc'] ?? '') ?>" placeholder="e.g. 10"></div>

            <div class="label">VLAN Priority (0-7) PC</div>
            <div class="value">
              <input class="small-input" name="global[vlan_pc_priority]" value="<?= e($wiz['global']['vlan_pc_priority'] ?? '') ?>" placeholder="0-7">
            </div>

            <div class="label">VLAN Priority (0-7)</div>
            <div class="value">
              <input class="small-input" name="global[vlan_qos]" value="<?= e($wiz['global']['vlan_qos'] ?? '') ?>" placeholder="0-7">
            </div>

            <div class="label">DSCP (SIP)</div>
            <div class="value"><input class="small-input" name="global[net_dscp_sip]" value="<?= e($wiz['global']['net_dscp_sip'] ?? '46') ?>" placeholder="0-63"></div>

            <div class="label">DSCP (RTP)</div>
            <div class="value"><input class="small-input" name="global[net_dscp_rtp]" value="<?= e($wiz['global']['net_dscp_rtp'] ?? '46') ?>" placeholder="0-63"></div>

            <div class="label">Codecs</div>
            <div class="value"><input class="small-input" name="global[codec_priority_list]" value="<?= e($wiz['global']['codec_priority_list'] ?? 'g722,pcmu,pcma,g729,telephone-event') ?>"></div>

            <div class="label">RTP Start</div>
            <div class="value"><input class="small-input" name="global[rtp_port_start]" value="<?= e($wiz['global']['rtp_port_start'] ?? '49152') ?>" placeholder="49152"></div>

            <div class="label">RTP End</div>
            <div class="value"><input class="small-input" name="global[rtp_port_end]" value="<?= e($wiz['global']['rtp_port_end'] ?? '65534') ?>" placeholder="65534"></div>
          </div>
        </div>
      </div>

      <!-- Security -->
      <div id="tab-sec" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">TLS min</div>
            <div class="value">
              <select class="small-input" name="global[sec_tls_min]">
                <?php $tls = $wiz['global']['sec_tls_min'] ?? '1.2';
                  foreach (['1.0','1.1','1.2','1.3'] as $ver){ $sel=($tls===$ver)?'selected':''; echo "<option $sel>".e($ver)."</option>"; } ?>
              </select>
            </div>

            <!-- Lock LCD removed per request -->

            <div class="label">User SRTP</div>
            <div class="value">
              <select class="small-input" name="global[user_srtp]">
                <?php $usr_srtp = ($wiz['global']['user_srtp'] ?? 'off'); ?>
                <option value="off" <?= $usr_srtp==='off'?'selected':''; ?>>Off</option>
                <option value="on" <?= $usr_srtp==='on'?'selected':''; ?>>On</option>
              </select>
            </div>

            <div class="label">User SAVP</div>
            <div class="value">
              <?php $usr_savp = ($wiz['global']['user_savp'] ?? 'off'); ?>
              <select class="small-input" name="global[user_savp]">
                <option value="off" <?= $usr_savp==='off'?'selected':''; ?>>off</option>
                <option value="optional" <?= $usr_savp==='optional'?'selected':''; ?>>optional</option>
                <option value="mandatory" <?= $usr_savp==='mandatory'?'selected':''; ?>>mandatory</option>
              </select>
            </div>

            <div class="label">Filter Registrar</div>
            <div class="value">
              <input type="checkbox" name="global[filter_registrar]" value="on" <?= (($wiz['global']['filter_registrar'] ?? 'off') === 'on') ? 'checked' : '' ?>>
            </div>

          </div>
        </div>
      </div>

      <!-- Provisioning -->
      <div id="tab-prov" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">setting_server</div>
            <div class="value"><input class="small-input" name="global[setting_server]" value="<?= e($wiz['global']['setting_server'] ?? 'v2.6.1c/provisioning_files') ?>" placeholder="http(s)://host/path OR relative path"></div>

            <div class="label">Polling (sec)</div>
            <div class="value"><input class="small-input" name="global[prov_polling_period]" value="<?= e($wiz['global']['prov_polling_period'] ?? '3600') ?>" placeholder="0..3600"></div>
          </div>
        </div>
      </div>

      <!-- Call Features -->
      <div id="tab-call" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">Voicemail Number</div>
            <div class="value">
              <input class="small-input" name="global[vm_key]" value="<?= e($wiz['global']['vm_key'] ?? '') ?>" placeholder="e.g. *97 or 5000">
            </div>

            <div class="label">Call Waiting</div>
            <div class="value">
              <?php $cw = $wiz['global']['call_waiting'] ?? 'on'; ?>
              <select class="small-input" name="global[call_waiting]">
                <option value="on" <?= $cw==='on'?'selected':''; ?>>On</option>
                <option value="off" <?= $cw==='off'?'selected':''; ?>>Off</option>
              </select>
            </div>

            <div class="label">Transfer on Hangup</div>
            <div class="value">
              <?php $toh = $wiz['global']['transfer_on_hangup'] ?? 'off'; ?>
              <select class="small-input" name="global[transfer_on_hangup]">
                <option value="on" <?= $toh==='on'?'selected':''; ?>>On</option>
                <option value="off" <?= $toh==='off'?'selected':''; ?>>Off</option>
              </select>
            </div>

            <div class="label">Transfer on Hangup (Non-POTS)</div>
            <div class="value">
              <?php $tohnp = $wiz['global']['transfer_on_hangup_non_pots'] ?? 'off'; ?>
              <select class="small-input" name="global[transfer_on_hangup_non_pots]">
                <option value="on" <?= $tohnp==='on'?'selected':''; ?>>On</option>
                <option value="off" <?= $tohnp==='off'?'selected':''; ?>>Off</option>
              </select>
            </div>

            <div class="label">Default Transfer Type</div>
            <div class="value">
              <?php $qt = $wiz['global']['quick_transfer'] ?? 'attended'; ?>
              <select class="small-input" name="global[quick_transfer]">
                <option value="attended" <?= $qt==='attended'?'selected':''; ?>>Attended</option>
                <option value="blind" <?= $qt==='blind'?'selected':''; ?>>Blind</option>
              </select>
            </div>

            <div class="label">Transfer While Dialing</div>
            <div class="value">
              <?php $td = $wiz['global']['transfer_dialing_on'] ?? 'attended'; ?>
              <select class="small-input" name="global[transfer_dialing_on]">
                <option value="attended" <?= $td==='attended'?'selected':''; ?>>Attended</option>
                <option value="blind" <?= $td==='blind'?'selected':''; ?>>Blind</option>
              </select>
            </div>

            <div class="label">Mute Button is DND in Idle</div>
            <div class="value">
              <?php $md = $wiz['global']['mute_is_dnd_in_idle'] ?? 'on'; ?>
              <select class="small-input" name="global[mute_is_dnd_in_idle]">
                <option value="on" <?= $md==='on'?'selected':''; ?>>On</option>
                <option value="off" <?= $md==='off'?'selected':''; ?>>Off</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <!-- Global Custom XML with sub-tabs: General / D8xx / D7xx / D1xx -->
      <div id="tab-custom" class="tabpanel">
        <div class="section-card">
          <div class="tabs" style="margin-bottom:8px">
            <div class="tab active" data-tab="custom-general">General</div>
            <div class="tab" data-tab="custom-d8">D8xx</div>
            <div class="tab" data-tab="custom-d7">D7xx</div>
            <div class="tab" data-tab="custom-d1">D1xx</div>
          </div>

          <div id="custom-general" class="tabpanel active">
            <div style="margin-bottom:8px"><small>Applied to all phones</small></div>
            <textarea class="area" name="global[custom_xml_general]" placeholder="Custom XML for all phones"><?php
              // Preserve newlines for user-entered XML: use clean_utf8, NOT sanitize_for_ui (which collapses whitespace)
              echo htmlspecialchars(clean_utf8($wiz['global']['custom_xml_general'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            ?></textarea>
          </div>

          <div id="custom-d8" class="tabpanel" style="display:none">
            <div style="margin-bottom:8px"><small>Applied to D8xx family (models starting with D8)</small></div>
            <textarea class="area" name="global[custom_xml_d8xx]" placeholder="Custom XML for D8xx"><?php
              echo htmlspecialchars(clean_utf8($wiz['global']['custom_xml_d8xx'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            ?></textarea>
          </div>

          <div id="custom-d7" class="tabpanel" style="display:none">
            <div style="margin-bottom:8px"><small>Applied to D7xx family (models starting with D7)</small></div>
            <textarea class="area" name="global[custom_xml_d7xx]" placeholder="Custom XML for D7xx"><?php
              echo htmlspecialchars(clean_utf8($wiz['global']['custom_xml_d7xx'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            ?></textarea>
          </div>

          <div id="custom-d1" class="tabpanel" style="display:none">
            <div style="margin-bottom:8px"><small>Applied to D1xx family (models starting with D1)</small></div>
            <textarea class="area" name="global[custom_xml_d1xx]" placeholder="Custom XML for D1xx"><?php
              echo htmlspecialchars(clean_utf8($wiz['global']['custom_xml_d1xx'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            ?></textarea>
          </div>

        </div>
      </div>

      <!-- SRAPS -->
      <div id="tab-sraps" class="tabpanel">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">Use SRAPS</div>
            <div class="value">
              <input type="checkbox" name="global[use_sraps]" value="on" <?= (($wiz['global']['use_sraps'] ?? 'off') === 'on') ? 'checked' : '' ?>>
            </div>

            <div class="label">Push to SRAPS on Generate</div>
            <div class="value">
              <input type="checkbox" name="global[sraps_push_on_generate]" value="on" <?= (($wiz['global']['sraps_push_on_generate'] ?? 'off') === 'on') ? 'checked' : '' ?>>
            </div>
          </div>
        </div>
      </div>

      <div class="group-actions">
        <a class="btn secondary inline" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Cancel</a>
        <button class="btn inline" type="submit" name="save_global" value="1">Save Global</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<!-- Edit modal -->
<?php if (!empty($show_edit_ext)): $edit_ext = $show_edit_ext; $over = $wiz['settings'][$edit_ext] ?? []; $edit_model = $wiz['assign'][$edit_ext]['model'] ?? ''; $edit_cap = fkey_cap_for_model($edit_model); ?>
<div id="edit-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9999">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div>
        <h3 style="margin:0;font-size:16px">Edit Device - Ext <?= e($edit_ext) ?></h3>
        <div class="small" style="margin-top:3px;color:#64748b">Model: <?= e($edit_model ?: 'Unknown') ?> - Max F-keys: <?= (int)$edit_cap ?></div>
      </div>
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="tab-pass">Admin Password</div>
      <div class="tab" data-tab="tab-blf">BLF Keys</div>
      <div class="tab" data-tab="tab-custom-ext">Custom XML</div>
    </div>

    <form method="post">
      <input type="hidden" name="ext" value="<?= e($edit_ext) ?>">

      <div id="tab-pass" class="tabpanel active">
        <div class="section-card">
          <div class="form-grid">
            <div class="label">Admin password</div>
            <div class="value">
              <div style="display:flex;gap:8px;align-items:center">
                <?php $masked = !empty($over['http_pass']) ? '*********' : ''; ?>
                <input class="small-input" id="http_pass_mask" type="password" value="<?= e($masked) ?>" readonly placeholder="*********">
                <button type="button" class="btn secondary inline" onclick="toggleHttpPass()">Show/Hide</button>
                <button type="button" class="btn inline" onclick="copyHttpPass()">Copy</button>
                <input type="text" name="cfg_http_pass_real" id="cfg_http_pass_real" value="<?= e($over['http_pass'] ?? '') ?>" style="display:none">
                <button type="button" class="btn" onclick="editHttpPass()">Edit</button>
              </div>
              <div style="margin-top:8px;color:#64748b;font-size:12px">You may edit the admin password for this device. If left empty, a random password is generated.</div>
            </div>
          </div>
        </div>
      </div>

      <div id="tab-blf" class="tabpanel">
        <div class="section-card">
          <div id="blf-list" style="display:flex;flex-direction:column;gap:8px">
            <?php
              $display_blf = $over['__blf'] ?? [];
              if (empty($display_blf)) $display_blf = [['type'=>'blf','value'=>'','label'=>'']];
              $idx=1;
              foreach($display_blf as $r):
                $val = sanitize_for_ui((string)($r['value'] ?? ''));
                $lab = sanitize_for_ui((string)($r['label'] ?? ''));
            ?>
              <div style="display:flex;gap:8px;align-items:center">
                <strong style="width:28px">#<?= (int)$idx ?></strong>
                <select name="cfg_blf_type[<?= (int)$idx ?>]" class="small-input" style="width:120px">
                  <option value="blf" selected>BLF</option>
                  <option value="none">None</option>
                </select>
                <select name="cfg_blf_ext[<?= (int)$idx ?>]" class="small-input blf-ext" style="width:220px">
                  <option value="">-- Select Extension --</option>
                  <?php foreach ($exts as $e2) {
                      $valOpt=sanitize_for_ui((string)$e2['extension']);
                      $labOpt=sanitize_for_ui((string)$e2['extension'].' - '.$e2['fullname']);
                      $selOpt = ((string)$val === (string)$valOpt) ? 'selected' : '';
                      echo '<option value="'.e($valOpt).'" '.$selOpt.'>'.e($labOpt).'</option>';
                  } ?>
                </select>
                <input class="small-input" name="cfg_blf_value[<?= (int)$idx ?>]" value="<?= e($val) ?>" placeholder="Manual value (e.g. 1001)" style="flex:1">
                <input class="small-input blf-label" name="cfg_blf_label[<?= (int)$idx ?>]" value="<?= e($lab) ?>" placeholder="Label (auto-filled)">
                <button type="button" class="btn ghost inline" onclick="this.closest('div').remove()">Remove</button>
              </div>
            <?php $idx++; endforeach; ?>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
            <div class="small" style="color:#64748b">Up to <?= (int)$edit_cap ?> keys</div>
            <button type="button" class="btn secondary inline" onclick="addBLF()">+ Add BLF</button>
          </div>
        </div>
      </div>

      <div id="tab-custom-ext" class="tabpanel">
        <div class="section-card">
          <textarea class="area" name="cfg[custom_xml]" placeholder="Custom XML under <phone-settings> (per device)"><?php
            // Preserve newlines for per-device custom xml
            $cx = (string)($over['custom_xml'] ?? '');
            echo htmlspecialchars(clean_utf8($cx), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
          ?></textarea>
        </div>
      </div>

      <div class="group-actions">
        <a class="btn secondary inline" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Close</a>
        <button class="btn inline" name="save_settings" value="1" type="submit">Save</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<!-- SRAPS Modal -->
<div id="sraps-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);align-items:center;justify-content:center;z-index:9999">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="sraps-title" style="max-width:760px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <strong id="sraps-title">SRAPS Settings</strong>
      <button type="button" class="btn secondary inline" onclick="closeSrapsModal()">Close</button>
    </div>
    <div class="tabs">
      <div class="tab active" data-tab="s-cred">Credentials</div>
      <div class="tab" data-tab="s-prof">Profiles</div>
    </div>
    <div id="s-cred" class="tabpanel active">
      <div class="section-card">
        <div class="form-grid">
          <div class="label">API URL</div>
          <div class="value"><input id="sraps-api-url" class="small-input" value="<?= e($wiz['sraps']['baseUrl'] ?? 'https://api.sraps.snom.com/api/v1/') ?>"></div>
          <div class="label">Organization ID</div>
          <div class="value"><input id="sraps-org-id" class="small-input" value="<?= e($wiz['sraps']['orgId'] ?? '') ?>"></div>
          <div class="label">Access Key ID</div>
          <div class="value"><input id="sraps-key-id" class="small-input" value="<?= e($wiz['sraps']['accessKey'] ?? '') ?>"></div>
          <div class="label">Access Key Secret</div>
          <div class="value"><input id="sraps-key-secret" class="small-input" type="password" value="<?= !empty($wiz['sraps']['secretKey']) ? '********' : '' ?>"></div>
        </div>
        <div class="group-actions" style="justify-content:flex-start">
          <button type="button" class="btn inline" onclick="saveSrapsCreds()">Save</button>
          <button type="button" class="btn secondary inline" onclick="testSrapsCreds()">Test Connection</button>
          <span id="sraps-status" class="small"></span>
        </div>
      </div>
    </div>
    <div id="s-prof" class="tabpanel">
      <div class="section-card">
        <div style="margin-bottom:10px">
          <button type="button" class="btn secondary inline" onclick="loadSrapsProfiles()">Load Profiles</button>
          <span id="sraps-profile-count" class="hint"></span>
        </div>
        <div class="form-grid">
          <div class="label">D Series</div>
          <div class="value"><select id="sraps-profile-D" class="small-input"><option value="">--select--</option></select></div>
          <div class="label">M Series</div>
          <div class="value"><select id="sraps-profile-M" class="small-input"><option value="">--select--</option></select></div>
          <div class="label">M500</div>
          <div class="value"><select id="sraps-profile-M500" class="small-input"><option value="">--select--</option></select></div>
          <div class="label">Hotel Phones</div>
          <div class="value"><select id="sraps-profile-HOTEL" class="small-input"><option value="">--select--</option></select></div>
        </div>
        <div class="group-actions" style="justify-content:flex-start">
          <button type="button" class="btn inline" onclick="saveSrapsProfileMap()">Save Profile Mapping</button>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const MAC_LIST = <?= $mac_list_json ?: '[]' ?>;
const ASSIGNED_MACS = <?= $assigned_macs_json ?: '{}' ?>;
const FLASH_MSG = <?= json_encode($toast_msg) ?: '""' ?>;
const FLASH_TYPE = <?= json_encode($toast_type) ?: '"success"' ?>;
const SYSTEM_ID = <?= json_encode($sysId) ?>;
const EXT_TO_NAME = <?= $ext_to_fullname_json ?: '{}' ?>;
<?php if (!empty($show_edit_ext)): ?>const BLF_CAP = <?= (int)$edit_cap ?>;<?php else: ?>const BLF_CAP = null;<?php endif; ?>
const SRAPS_STATUS_OK = <?= $sraps_ok ? 'true' : 'false' ?>;

// showToast default duration now 5000ms (5s)
function showToast(message, type='success', duration=5000) {
  message = String(message || '').replace(/\s+/g,' ').replace(/\?+\s*$/,'').trim();
  if (!message) return;
  document.querySelectorAll('.center-toast-overlay').forEach(el => el.remove());
  const overlay = document.createElement('div'); overlay.className = 'center-toast-overlay'; overlay.setAttribute('role','status');
  const box = document.createElement('div'); box.className = 'center-toast ' + (type==='warn' ? 'warn' : 'success');
  const txt = document.createElement('div'); txt.style.flex = '1'; txt.style.textAlign = 'center'; txt.textContent = message;
  const close = document.createElement('button'); close.className = 'close-btn'; close.innerHTML = '&times;'; close.title='Close';
  close.addEventListener('click', () => overlay.remove());
  box.appendChild(txt); box.appendChild(close); overlay.appendChild(box); document.body.appendChild(overlay);
  setTimeout(()=>{ overlay.remove(); }, Math.min(duration, Math.max(500, duration || 5000)));
}

function setSrapsConnected(ok){
  const dot = document.getElementById('sraps-dot');
  if (!dot) return;
  dot.classList.toggle('ok', !!ok);
  dot.classList.toggle('bad', !ok);
}

document.addEventListener('DOMContentLoaded', function(){
  try { if (FLASH_MSG) showToast(FLASH_MSG, FLASH_TYPE, 5000); } catch(e){}

  // Initial SRAPS dot
  try { setSrapsConnected(SRAPS_STATUS_OK); } catch(e){}

  // Ensure SRAPS button opens modal
  const srapsBtn = document.getElementById('open-sraps');
  if (srapsBtn) {
    srapsBtn.removeEventListener('click', ()=>{}); // defensive
    srapsBtn.addEventListener('click', () => {
      openSrapsModal();
    });
  }

  document.querySelectorAll('.tabpanel').forEach(p=>{
    p.style.display = p.classList.contains('active') ? 'block' : 'none';
  });

  document.querySelectorAll('.tabs').forEach(tabsEl=>{
    tabsEl.querySelectorAll('.tab').forEach(tab=>{
      tab.addEventListener('click', ()=>{
        const tgt = tab.getAttribute('data-tab');
        const panel = document.getElementById(tgt);

        tabsEl.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        tab.classList.add('active');

        let groupPanels = [];
        if (panel && panel.parentElement) {
          groupPanels = Array.from(panel.parentElement.querySelectorAll('.tabpanel'));
        } else {
          groupPanels = Array.from(document.querySelectorAll('.tabpanel'));
        }
        groupPanels.forEach(p=>{
          p.classList.remove('active');
          p.style.display = 'none';
        });
        if (panel) {
          panel.classList.add('active');
          panel.style.display = 'block';
        }
      });
    });
  });

  // If Global modal is open, auto-select tab from URL (?tab=tab-sraps or #tab-sraps)
  const globalModal = document.getElementById('global-modal');
  if (globalModal) {
    const params = new URLSearchParams(location.search);
    const targetTabId = params.get('tab') || (location.hash ? location.hash.replace('#','') : '');
    if (targetTabId) {
      const tabBtn = globalModal.querySelector('.tabs .tab[data-tab="'+targetTabId+'"]');
      const panel = document.getElementById(targetTabId);
      if (tabBtn && panel) {
        const tabsEl = tabBtn.parentElement;
        tabsEl.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tabBtn.classList.add('active');
        const panels = Array.from(panel.parentElement.querySelectorAll('.tabpanel'));
        panels.forEach(p => { p.classList.remove('active'); p.style.display = 'none'; });
        panel.classList.add('active'); panel.style.display = 'block';
      }
    }
  }

  // Toggle force admin password field (removed in newer UI, but keep defensive code)
  const chk = document.getElementById('force_admin_password');
  const pwd = document.getElementById('forced_admin_password');
  if (chk && pwd) {
    chk.addEventListener('change', ()=> {
      if (chk.checked) { pwd.removeAttribute('disabled'); pwd.focus(); }
      else { pwd.setAttribute('disabled','disabled'); }
    });
  }

  // Tab handling for nested custom XML tabs inside Global -> Custom XML
  document.querySelectorAll('#tab-custom .tabs').forEach(tabsEl => {
    tabsEl.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const tgt = tab.getAttribute('data-tab');
        if (!tgt) return;
        tabsEl.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const panels = tabsEl.parentElement.querySelectorAll('.tabpanel');
        panels.forEach(p => {
          if (p.id === tgt) { p.classList.add('active'); p.style.display = 'block'; }
          else { p.classList.remove('active'); p.style.display = 'none'; }
        });
      });
    });
  });

  // Dynamic search (client-side only)
  const searchInput = document.getElementById('search-all');
  const searchBtn = document.getElementById('search-btn');
  function applySearchFilter() {
    const q = (searchInput.value || '').toLowerCase().trim();
    const rows = document.querySelectorAll('#assign-form tbody tr');
    rows.forEach(tr => {
      const ext = (tr.querySelector('.col-ext')?.textContent || '').toLowerCase();
      const full = (tr.querySelector('.col-full')?.textContent || '').toLowerCase();
      const mac = (tr.querySelector('.col-mac input')?.value || '').toLowerCase();
      const model = (tr.querySelector('.col-model select')?.value || '').toLowerCase();
      const hay = ext + ' ' + full + ' ' + mac + ' ' + model;
      tr.style.display = (q === '' || hay.indexOf(q) !== -1) ? '' : 'none';
    });
  }
  if (searchInput) {
    searchInput.addEventListener('input', applySearchFilter);
    searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); applySearchFilter(); } });
  }
  if (searchBtn) searchBtn.addEventListener('click', applySearchFilter);

  // Attach MAC combos (suggestions + model autofill)
  attachMacCombos();

  // Clear file input value so selecting same file again works in browsers
  const macCsvInput = document.getElementById('mac_csv_input');
  if (macCsvInput) {
    try { macCsvInput.value = ''; } catch (e) {}
  }

  // finalize: if server rendered modal open, leave it visible (server sets show_global)
  if (globalModal && <?= ($show_global ? 'true' : 'false') ?>) {
    globalModal.style.display = 'flex';
  }

}); // end DOMContentLoaded

/* Utility functions and actions */

function switchSiteGo(){
  const sel = document.getElementById('switch-site-select');
  const modal = document.getElementById('switch-site-modal');
  if (!sel || !sel.value) { if (modal) modal.style.display='none'; return; }
  window.location.href = 'extensions.php?system_id=' + encodeURIComponent(sel.value);
}

function toggleHttpPass() {
  const mask = document.getElementById('http_pass_mask');
  const real = document.getElementById('cfg_http_pass_real');
  if (!mask || !real) return;
  const visible = (mask.type === 'text');
  if (visible) {
    mask.type = 'password';
    mask.readOnly = true;
    mask.value = real.value ? '*********' : '';
  } else {
    mask.type = 'text';
    mask.readOnly = true;
    mask.value = (real.value || '');
  }
}

function copyHttpPass() {
  const real = document.getElementById('cfg_http_pass_real');
  const mask = document.getElementById('http_pass_mask');
  let secret = (real && real.value) ? real.value : '';
  if (!secret && mask && mask.type === 'text' && mask.value && mask.value !== '*********') {
    secret = mask.value;
  }
  if (!secret) { showToast('No password available to copy','warn',5000); return; }
  if (navigator && navigator.clipboard && navigator.clipboard.writeText && (window.isSecureContext || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    navigator.clipboard.writeText(secret).then(()=>showToast('Password copied','success',5000)).catch(()=>fallbackCopy(secret));
  } else {
    fallbackCopy(secret);
  }
  function fallbackCopy(text) {
    try {
      const ta=document.createElement('textarea'); ta.value=text; ta.setAttribute('readonly',''); ta.style.position='fixed'; ta.style.left='-9999px'; ta.style.opacity='0'; document.body.appendChild(ta);
      ta.focus(); ta.select(); ta.setSelectionRange(0, ta.value.length);
      const ok=document.execCommand('copy'); document.body.removeChild(ta);
      showToast(ok?'Password copied':'Copy failed', ok?'success':'warn',5000);
    } catch(e){ showToast('Copy failed','warn',5000); }
  }
}

function editHttpPass(){
  const real = document.getElementById('cfg_http_pass_real');
  const mask = document.getElementById('http_pass_mask');
  if (!real || !mask) return;
  const newVal = prompt('Enter admin password for this device (leave empty to generate a random one):', real.value || '');
  if (newVal === null) return; // cancelled
  real.value = newVal;
  mask.type = 'password';
  mask.value = newVal ? '*********' : '';
}

/* BLF helpers */
function currentBLFRowCount(){
  const list=document.getElementById('blf-list'); if (!list) return 0;
  return Array.from(list.querySelectorAll('select[name^="cfg_blf_type"]')).filter(s=> (s.value||'blf') !== 'none').length;
}
function addBLF(){
  const list=document.getElementById('blf-list'); if(!list) return;
  if (typeof BLF_CAP === 'number' && currentBLFRowCount() >= BLF_CAP) { showToast('Reached maximum F-keys.','warn',5000); return; }
  const nextIdx = (list.querySelectorAll('select[name^="cfg_blf_type"]').length + 1);
  let extHtml = document.querySelector('#blf-list select[name^="cfg_blf_ext"]')?.innerHTML || '<option value="">-- Select Extension --</option>';
  const div=document.createElement('div'); div.style.display='flex'; div.style.gap='8px'; div.style.alignItems='center';
  div.innerHTML = `<strong style="width:28px">#${nextIdx}</strong>
    <select name="cfg_blf_type[${nextIdx}]" class="small-input" style="width:120px">
      <option value="blf" selected>BLF</option><option value="none">None</option>
    </select>
    <select name="cfg_blf_ext[${nextIdx}]" class="small-input blf-ext" style="width:220px">${extHtml}</select>
    <input class="small-input" name="cfg_blf_value[${nextIdx}]" placeholder="Manual value (e.g. 1001)" style="flex:1">
    <input class="small-input blf-label" name="cfg_blf_label[${nextIdx}]" placeholder="Label" style="width:200px">
    <button type="button" class="btn ghost inline" onclick="this.closest('div').remove()">Remove</button>`;
  list.appendChild(div);
}

/* Form helpers used by action buttons */
function postEdit(ext){
  if(!ext) return;
  const f=document.createElement('form'); f.method='post'; f.style.display='none'; f.action='extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID);
  const i=document.createElement('input'); i.type='hidden'; i.name='edit'; i.value=ext; f.appendChild(i);
  document.body.appendChild(f); f.submit();
}
function postGenerate(ext){
  if(!ext) return;
  const f=document.createElement('form'); f.method='post'; f.style.display='none'; f.action='extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID);
  const macInput = document.querySelector('input[name="assign['+ext+'][mac]"]');
  if (macInput) { const h=document.createElement('input'); h.type='hidden'; h.name='assign['+ext+'][mac]'; h.value=(macInput.value||''); f.appendChild(h); }
  const modelSel = document.querySelector('select[name="assign['+ext+'][model]"]');
  if (modelSel) { const h=document.createElement('input'); h.type='hidden'; h.name='assign['+ext+'][model]'; h.value=(modelSel.value||''); f.appendChild(h); }
  const i=document.createElement('input'); i.type='hidden'; i.name='generate_one'; i.value=ext; f.appendChild(i);
  document.body.appendChild(f); f.submit();
}

/* Improved confirmDelete: attempt SRAPS release via AJAX first (shows toast), then submit server-side delete POST */
function confirmDelete(ext){
  if (!ext) return;
  if (!confirm('Delete generated provisioning file for extension ' + ext + ' ?')) return;

  (async function(){
    let releasedByClient = false;
    try {
      const statusResp = await fetch('extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID) + '&sraps_action=status', {cache:'no-store'});
      const statusJson = await statusResp.json().catch(()=>({configured:false}));
      const useSraps = (statusJson && statusJson.configured) ? true : false;
      if (useSraps) {
        // find mac on client
        let mac = '';
        const macInput = document.querySelector('input[name="assign['+ext+'][mac]"]');
        if (macInput && macInput.value) mac = macInput.value.trim().replace(/[^A-Fa-f0-9]/g,'').toUpperCase();
        if (!mac && window.MAC_LIST) {
          for (let i=0;i<MAC_LIST.length;i++){
            const e = MAC_LIST[i] || {};
            if ((e.extension && String(e.extension) === ext) || (e.label && String(e.label).indexOf(ext) === 0)) { mac = (e.mac||'').replace(/[^A-Fa-f0-9]/g,'').toUpperCase(); break; }
          }
        }
        if (mac && mac.length===12) {
          try {
            const relResp = await fetch('extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID) + '&sraps_action=release', {
              method: 'POST',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify({ mac: mac })
            });
            const relJson = await relResp.json().catch(()=>null);
            if (relResp.ok && relJson && relJson.ok) {
              releasedByClient = true;
              showToast('SRAPS: device released (' + mac + ')','success',5000);
            } else {
              const msg = (relJson && relJson.error) ? relJson.error : ('HTTP ' + (relResp.status || 'err'));
              showToast('SRAPS release: ' + msg,'warn',5000);
            }
          } catch (e) {
            console.error('SRAPS release ajax error', e);
            showToast('SRAPS release AJAX error','warn',5000);
          }
        } else {
          showToast('SRAPS: MAC not found client-side — server will attempt release','warn',5000);
        }
      }
    } catch (e) {
      console.error('SRAPS status check failed', e);
    } finally {
      const f = document.createElement('form'); f.method='post'; f.style.display='none'; f.action='extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID);
      const i = document.createElement('input'); i.type='hidden'; i.name='delete_generated'; i.value=ext; f.appendChild(i);
      if (releasedByClient) { const s=document.createElement('input'); s.type='hidden'; s.name='sraps_released_client'; s.value='1'; f.appendChild(s); }
      document.body.appendChild(f); f.submit();
    }
  })();
}

/* MAC combo implementation */
function attachMacCombos() {
  const macList = Array.isArray(MAC_LIST) ? MAC_LIST : [];
  document.querySelectorAll('.mac-combo').forEach(combo => {
    const input = combo.querySelector('.mac-combo-input');
    const listEl = combo.querySelector('.mac-combo-list');
    if (!input || !listEl) return;
    const ext = combo.getAttribute('data-ext') || '';
    function normalizeDisplayMac(s){ return String(s||'').replace(/[^A-Fa-f0-9]/g,'').toUpperCase(); }
    function findModelForMac(mac) {
      if (!mac) return '';
      for (let i=0;i<macList.length;i++){
        const entry = macList[i] || {};
        const m = (entry.mac || entry.MAC || '').toString().replace(/[^A-Fa-f0-9]/g,'').toUpperCase();
        if (m === mac) return (entry.model || entry.Model || '').toString();
      }
      return '';
    }
    function setModelForExt(extLocal, model) {
      if (!extLocal) return;
      const sel = document.querySelector('select[name="assign['+extLocal+'][model]"]');
      if (sel && model) {
        let found=false;
        for (let i=0;i<sel.options.length;i++){
          if (sel.options[i].value === model) { sel.selectedIndex = i; found=true; break; }
        }
        if (!found) { const opt = document.createElement('option'); opt.value = model; opt.text = model; opt.selected = true; sel.appendChild(opt); }
      }
    }
    function buildList(filterQ='') {
      listEl.innerHTML = '';
      const q = normalizeDisplayMac(filterQ);
      let any = 0;
      macList.forEach(it => {
        const mac = normalizeDisplayMac(it.mac || it.MAC || '');
        if (!mac) return;
        const assignedTo = (ASSIGNED_MACS && ASSIGNED_MACS[mac]) ? ASSIGNED_MACS[mac] : null;
        if (assignedTo && assignedTo !== ext) return;
        if (q === '' || mac.indexOf(q) !== -1) {
          const item = document.createElement('div'); item.className = 'mac-combo-item'; item.tabIndex = -1;
          item.dataset.value = mac; item.dataset.model = (it.model || it.Model || '').toString();
          item.textContent = mac + (it.model ? ' ' + it.model : '');
          listEl.appendChild(item); any++;
        }
      });
      if (any === 0) { const empty = document.createElement('div'); empty.className = 'mac-combo-empty'; empty.textContent = 'No suggestions'; listEl.appendChild(empty); }
      const first = listEl.querySelector('.mac-combo-item'); if (first) first.classList.add('active');
      listEl.style.display = 'block';
    }
    function showList() { buildList(input.value || ''); }
    function hideListSoon() { setTimeout(()=>listEl.style.display='none', 150); }
    function hideList() { listEl.style.display = 'none'; }

    input.addEventListener('focus', showList);
    input.addEventListener('input', function(){ showList(); });
    input.addEventListener('blur', function(){
      input.value = normalizeDisplayMac(input.value || '');
      const model = findModelForMac(input.value || '');
      if (model) setModelForExt(ext, model);
      hideListSoon();
    });
    input.addEventListener('keydown', function(ev){
      const visible = Array.from(listEl.querySelectorAll('.mac-combo-item')).filter(it => it.offsetParent !== null);
      const active = listEl.querySelector('.mac-combo-item.active');
      if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        if (listEl.style.display !== 'block') { showList(); return; }
        if (!visible.length) return;
        if (!active) { visible[0].classList.add('active'); visible[0].scrollIntoView({block:'nearest'}); return; }
        const idx = visible.indexOf(active); const next = visible[idx+1] || visible[0];
        active.classList.remove('active'); next.classList.add('active'); next.scrollIntoView({block:'nearest'});
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        if (listEl.style.display !== 'block') { showList(); return; }
        if (!visible.length) return;
        if (!active) { visible[visible.length-1].classList.add('active'); visible[visible.length-1].scrollIntoView({block:'nearest'}); return; }
        const idx = visible.indexOf(active); const prev = visible[idx-1] || visible[visible.length-1];
        active.classList.remove('active'); prev.classList.add('active'); prev.scrollIntoView({block:'nearest'});
      } else if (ev.key === 'Enter') {
        if (listEl.style.display === 'block') {
          const pick = listEl.querySelector('.mac-combo-item.active');
          if (pick && pick.dataset && pick.dataset.value) {
            ev.preventDefault();
            input.value = pick.dataset.value;
            if (pick.dataset.model) setModelForExt(ext, pick.dataset.model);
            input.dispatchEvent(new Event('input',{bubbles:true}));
            hideList();
          }
        }
      } else if (ev.key === 'Escape') { hideList(); }
    });
    listEl.addEventListener('mousedown', function(ev){
      const it = ev.target.closest('.mac-combo-item'); if (!it || !it.dataset) return;
      ev.preventDefault();
      input.value = it.dataset.value || '';
      if (it.dataset.model) setModelForExt(ext, it.dataset.model);
      input.dispatchEvent(new Event('input',{bubbles:true}));
      hideList(); input.focus();
    });
    document.addEventListener('click', function(ev){ if (!combo.contains(ev.target)) hideList(); });
  });
}

/* SRAPS modal JS functions */
function openSrapsModal(){
  const modal = document.getElementById('sraps-modal');
  if (!modal) return;
  modal.style.display = 'flex';
  // ensure credentials tab shown by default
  document.querySelectorAll('#sraps-modal .tab').forEach(t => t.classList.remove('active'));
  const credTab = document.querySelector('#sraps-modal .tab[data-tab="s-cred"]');
  if (credTab) credTab.classList.add('active');
  document.querySelectorAll('#sraps-modal .tabpanel').forEach(p => { p.style.display = 'none'; p.classList.remove('active'); });
  const panel = document.getElementById('s-cred');
  if (panel) { panel.style.display = 'block'; panel.classList.add('active'); }
}
function closeSrapsModal(){ const m = document.getElementById('sraps-modal'); if (m) m.style.display='none'; }

function saveSrapsCreds(){
  const apiUrl = (document.getElementById('sraps-api-url')?.value || '').trim();
  const orgId = (document.getElementById('sraps-org-id')?.value || '').trim();
  const keyId = (document.getElementById('sraps-key-id')?.value || '').trim();
  const secret = (document.getElementById('sraps-key-secret')?.value || '');
  fetch('extensions.php?system_id='+encodeURIComponent(SYSTEM_ID)+'&sraps_action=save_creds', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ baseUrl: apiUrl, orgId: orgId, accessKey: keyId, secretKey: secret })
  })
  .then(r=>r.json())
  .then(res=>{
    if (res && res.ok) {
      showToast('SRAPS credentials saved','success',5000);
      testSrapsCreds();
    } else {
      showToast('Save failed','warn',5000);
    }
  })
  .catch(()=>showToast('Save failed','warn',5000));
}

function testSrapsCreds(){
  const statusEl = document.getElementById('sraps-status');
  if (statusEl) statusEl.textContent = 'Testing...';
  fetch('extensions.php?system_id='+encodeURIComponent(SYSTEM_ID)+'&sraps_action=test')
    .then(r=>r.json())
    .then(res=>{
      if (res && res.ok) {
        if (statusEl) statusEl.textContent = 'Connected';
        setSrapsConnected(true);
        showToast('SRAPS connection OK','success',5000);
      } else {
        if (statusEl) statusEl.textContent = 'Failed';
        setSrapsConnected(false);
        showToast('SRAPS test failed','warn',5000);
      }
    })
    .catch(()=>{ if (statusEl) statusEl.textContent = 'Failed'; setSrapsConnected(false); showToast('SRAPS test failed','warn',5000); });
}

function loadSrapsProfiles(){
  const countEl = document.getElementById('sraps-profile-count');
  if (countEl) countEl.textContent = 'Loading...';
  Promise.all([
    fetch('extensions.php?system_id='+encodeURIComponent(SYSTEM_ID)+'&sraps_action=get_profiles').then(r=>r.json()),
    fetch('extensions.php?system_id='+encodeURIComponent(SYSTEM_ID)+'&sraps_action=get_category_profiles').then(r=>r.json())
  ])
  .then(([profilesRes, mappingRes]) => {
    const profiles = Array.isArray(profilesRes.profiles) ? profilesRes.profiles : [];
    const savedMapping = (mappingRes && mappingRes.profilesCat) ? mappingRes.profilesCat : {};
    if (countEl) countEl.textContent = profiles.length + ' profiles';
    fillProfileSelect('sraps-profile-D', profiles, savedMapping.D || '');
    fillProfileSelect('sraps-profile-M', profiles, savedMapping.M || '');
    fillProfileSelect('sraps-profile-M500', profiles, savedMapping.M500 || '');
    fillProfileSelect('sraps-profile-HOTEL', profiles, savedMapping.HOTEL || '');
  })
  .catch(()=>{ if (countEl) countEl.textContent=''; showToast('Failed to load profiles','warn',5000); });
}

function fillProfileSelect(selId, profiles, selected){
  const sel = document.getElementById(selId);
  if (!sel) return;
  sel.innerHTML = '<option value="">--select--</option>';
  const selStr = String(selected || '');
  profiles.forEach(p => {
    try {
      const id = (p['uuid'] || p['uuid_v4'] || p['id'] || '').toString();
      const name = (p['name'] || p['display_name'] || id || '').toString();
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = name;
      if (id === selStr) opt.selected = true;
      sel.appendChild(opt);
    } catch (e) {
      // ignore malformed profile
    }
  });
}

function saveSrapsProfileMap(){
  const d = document.getElementById('sraps-profile-D')?.value || '';
  const m = document.getElementById('sraps-profile-M')?.value || '';
  const m500 = document.getElementById('sraps-profile-M500')?.value || '';
  const h = document.getElementById('sraps-profile-HOTEL')?.value || '';
  fetch('extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID) + '&sraps_action=save_category_profiles', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ profile_D: d, profile_M: m, profile_M500: m500, profile_HOTEL: h })
  })
  .then(r=>r.json())
  .then(res=>{
    if (res && res.ok) { showToast('SRAPS profile mapping saved','success',5000); setTimeout(()=>location.reload(),600); } else showToast('Failed to save profile mapping','warn',5000);
  })
  .catch(()=>showToast('Save failed','warn',5000));
}
</script>

</body>
</html>
