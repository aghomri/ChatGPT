<?php
// --- UTF-8 Fix ---
// Ensures multilingual characters (Ti?ng Vi?t, ??????????, etc.) display correctly
if (!headers_sent()) header('Content-Type: text/html; charset=UTF-8');
ini_set('default_charset', 'UTF-8');

ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();

/* Force UTF-8 everywhere to display Vietnamese/Cyrillic correctly */
ini_set('default_charset', 'UTF-8');
if (function_exists('mb_internal_encoding')) mb_internal_encoding('UTF-8');
if (function_exists('mb_http_output')) mb_http_output('UTF-8');
header('Content-Type: text/html; charset=UTF-8');

function provision_log($line){
    @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' '.$line.PHP_EOL, FILE_APPEND);
}

/* ========================= Helpers ========================= */
function clean_utf8($s) {
    if ($s === null) return '';
    if (!is_string($s)) $s = (string)$s;

    // Convert to UTF-8 only if not already UTF-8
    if (function_exists('mb_detect_encoding') && function_exists('mb_convert_encoding')) {
        $enc = @mb_detect_encoding($s, ['UTF-8','UTF-16','Windows-1252','ISO-8859-1'], true);
        if ($enc && $enc !== 'UTF-8') {
            $s = @mb_convert_encoding($s, 'UTF-8', $enc);
        }
    }
    return $s;
}
// Keep printable Unicode; only remove control chars and collapse whitespace
function sanitize_for_ui(string $s): string {
    $s = clean_utf8($s);
    // Remove C0 controls except common whitespace (leave \t \n \r)
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $s);
    // Collapse excessive whitespace
    $s = preg_replace('/\s+/u', ' ', $s);
    return trim($s);
}
// Always sanitize before escaping for HTML
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
// Per-model F-key capacity
function fkey_cap_for_model(string $model): int {
    $m = strtoupper(trim($model));
    if ($m === 'D895') return 236;
    if (in_array($m, ['D815','D892','D865'], true)) return 220;
    if (in_array($m, ['D862','D812'], true)) return 212;
    return 212; // conservative default
}
// Map DSCP (0-63) to TOS byte (DSCP << 2)
function dscp_to_tos(?string $dscp): ?int {
    if ($dscp === null) return null;
    $dscp = trim((string)$dscp);
    if ($dscp === '' || !preg_match('/^\d+$/', $dscp)) return null;
    $v = (int)$dscp;
    if ($v < 0) $v = 0;
    if ($v > 63) $v = 63;
    return $v * 4;
}
// Map log level string to Snom numeric level
function snom_log_level_from_string(?string $s): ?int {
    if ($s === null) return null;
    $m = [
        'emerg'=>0,'emergency'=>0,
        'alert'=>1,
        'crit'=>2,'critical'=>2,
        'err'=>3,'error'=>3,
        'warning'=>4,'warn'=>4,
        'notice'=>5,
        'info'=>6,
        'debug'=>7
    ];
    $k = strtolower(trim($s));
    return $m[$k] ?? null;
}

/* ========================= DB/auth ========================= */
if (!file_exists(__DIR__ . '/db.php')) { provision_log('db.php missing'); die("Missing db.php - cannot continue"); }
require_once __DIR__ . '/db.php';
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

/* ========================= Load system ========================= */
$sysId = isset($_REQUEST['system_id']) ? (int)$_REQUEST['system_id'] : 0;
$st = $pdo->prepare('SELECT * FROM systems WHERE id=? AND user_id=?');
$st->execute([$sysId, $uid]);
$sys = $st->fetch(PDO::FETCH_ASSOC);
if (!$sys) { http_response_code(404); die('<pre>Invalid or unauthorized system ID.</pre>'); }
$sys['label'] = isset($sys['label']) ? sanitize_for_ui((string)$sys['label']) : 'Provisioning';

// All sites (Switch Site)
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

/* ========================= Assets/paths ========================= */
$local_logo_path = 'assets/logos/snom_logo_gray_60.svg';
$logo_src = file_exists(__DIR__.'/'.$local_logo_path)
    ? $local_logo_path
    : 'data:image/svg+xml;utf8,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" width="120" height="88"><rect rx="8" width="120" height="88" fill="#eef6ff"/><text x="50%" y="50%" font-size="20" fill="#0b2548" text-anchor="middle" dominant-baseline="central">snom</text></svg>');

$PROVISION_DIR = rtrim(__DIR__, '/').'/provisioning_files';
if (!is_dir($PROVISION_DIR)) { @mkdir($PROVISION_DIR, 0777, true); @chmod($PROVISION_DIR, 0777); }
$PUBLIC_PROVISION_PATH = '/' . trim(str_replace(rtrim($_SERVER['DOCUMENT_ROOT'],'/'), '', $PROVISION_DIR), '/');
if ($PUBLIC_PROVISION_PATH === '') $PUBLIC_PROVISION_PATH = '/provisioning_files';

/* ========================= Session wizard state ========================= */
if (!isset($_SESSION['wiz'])) $_SESSION['wiz'] = [];
if (!isset($_SESSION['wiz'][$sysId])) $_SESSION['wiz'][$sysId] = ['exts'=>[],'assign'=>[],'settings'=>[],'generated'=>[],'global'=>[],'flash'=>null];
$wiz = &$_SESSION['wiz'][$sysId];
if ($db_wiz = load_wiz_from_db($pdo, $sysId, $uid)) { $_SESSION['wiz'][$sysId] = array_replace_recursive($wiz, $db_wiz); $wiz = &$_SESSION['wiz'][$sysId]; }

/* ========================= CSV parsing/upload ========================= */
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
        header('Location: extensions.php?system_id='.(int)$sysId); exit;
    }
}
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['clear_mac_list'])) { unset($_SESSION['mac_list']); $_SESSION['mac_mode']='allow_manual'; $csv_msg="MAC list cleared."; save_wiz_to_db($pdo,$sysId,$uid,$wiz); }

/* ========================= UCM helpers & load ========================= */
function api_post_json($url,$json,$cookie=null){
    $ch=curl_init($url);
    $hdr=['Content-Type: application/json;charset=UTF-8']; if($cookie)$hdr[]='Cookie: '.$cookie;
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$json,CURLOPT_HTTPHEADER=>$hdr,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0,CURLOPT_TIMEOUT=>25,CURLOPT_CONNECTTIMEOUT=>8]);
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

// Fullname map for labels (sanitized)
$fullname_by_ext = [];
foreach ($exts as $ee) {
    $fullname_by_ext[(string)($ee['extension'] ?? '')] = sanitize_for_ui($ee['fullname'] ?? '');
}

/* ========================= Write profile (XML) ========================= */
function write_profile($dir, $ucm_host, $extInfo, $mac, $overrides = [], $all_exts = []) {
    $mac = strtoupper(preg_replace('/[^A-Fa-f0-9]/','', (string)$mac));
    if ($mac === '') return [false, 'Invalid MAC'];
    if (empty($dir)) $dir = rtrim(__DIR__,'/').'/provisioning_files';
    if (!is_dir($dir)) { if (!@mkdir($dir, 0777, true)) return [false, "Cannot create provisioning directory: {$dir}"]; @chmod($dir, 0777); }
    if (!is_writable($dir)) return [false, "Provisioning directory not writable: {$dir}"];

    $ext = (string)($extInfo['extension'] ?? '');
    $fullname = sanitize_for_ui((string)($extInfo['fullname'] ?? ''));
    $password = $extInfo['secret'] ?? ($overrides['auth_password'] ?? '');

    // Prefer explicit prov_server, fallback to legacy setting_server, then UCM host
    $server = $overrides['prov_server'] ?? $overrides['setting_server'] ?? $ucm_host ?? '';

    $model = $overrides['__model'] ?? '';
    $cap = fkey_cap_for_model((string)$model);

    $blf_rows_in = is_array($overrides['__blf'] ?? []) ? $overrides['__blf'] : [];
    $blf_rows_in = array_slice($blf_rows_in, 0, max(0, (int)$cap));

    // Map ext -> fullname (sanitized)
    $fullname_map = [];
    foreach ($all_exts as $ae) { $fullname_map[(string)$ae['extension']] = sanitize_for_ui($ae['fullname'] ?? ''); }

    // Admin/user Web UI credentials
    $admin_pass = isset($overrides['http_pass']) && $overrides['http_pass'] !== '' ? (string)$overrides['http_pass'] : random_password(16);
    $user_pass  = isset($overrides['user_http_pass']) && $overrides['user_http_pass'] !== '' ? (string)$overrides['user_http_pass'] : random_password(16);

    // Custom per-device XML (raw insert)
    $custom_xml = (string)($overrides['custom_xml'] ?? '');

    // Resolve DSCP -> TOS (byte) for SIP and RTP if provided
    $sip_tos = dscp_to_tos($overrides['net_dscp_sip'] ?? null);
    $rtp_tos = dscp_to_tos($overrides['net_dscp_rtp'] ?? null);

    // Logging level (string -> numeric)
    $log_level_num = snom_log_level_from_string($overrides['log_level'] ?? null);

    $xml  = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    $xml .= "<settings>\n";

    // Phone settings block
    $xml .= "  <phone-settings e=\"2\">\n";

    // Basic identity (Account 1)
    $xml .= "    <user_active idx=\"1\" perm=\"RW\">on</user_active>\n";
    $xml .= "    <user_idle_text idx=\"1\" perm=\"RW\">".htmlspecialchars(clean_utf8($fullname), ENT_QUOTES, 'UTF-8')."</user_idle_text>\n";
    $xml .= "    <user_idle_number idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_idle_number>\n";
    $xml .= "    <user_name idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_name>\n";
    $xml .= "    <user_pname idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_pname>\n";
    if ($password !== '') $xml .= "    <user_pass idx=\"1\" perm=\"RW\">".htmlspecialchars($password, ENT_QUOTES, 'UTF-8')."</user_pass>\n";
    $xml .= "    <user_realname idx=\"1\" perm=\"RW\">".htmlspecialchars(clean_utf8($fullname), ENT_QUOTES, 'UTF-8')."</user_realname>\n";
    if ($server !== '') {
        $xml .= "    <user_host idx=\"1\" perm=\"RW\">".htmlspecialchars($server, ENT_QUOTES, 'UTF-8')."</user_host>\n";
        $xml .= "    <user_outbound idx=\"1\" perm=\"RW\">".htmlspecialchars($server, ENT_QUOTES, 'UTF-8')."</user_outbound>\n";
    }
    $xml .= "    <user_mailbox idx=\"1\" perm=\"RW\">".htmlspecialchars($ext, ENT_QUOTES, 'UTF-8')."</user_mailbox>\n";

    // Codec priority (global)
    if (!empty($overrides['codec_priority_list'])) {
        $xml .= "    <codec_priority_list idx=\"1\" perm=\"RW\">".htmlspecialchars($overrides['codec_priority_list'], ENT_QUOTES, 'UTF-8')."</codec_priority_list>\n";
    }

    // RTP Port range (global)
    if (!empty($overrides['rtp_port_start'])) {
        $xml .= "    <rtp_port_start perm=\"RW\">".htmlspecialchars($overrides['rtp_port_start'], ENT_QUOTES, 'UTF-8')."</rtp_port_start>\n";
    }
    if (!empty($overrides['rtp_port_end'])) {
        $xml .= "    <rtp_port_end perm=\"RW\">".htmlspecialchars($overrides['rtp_port_end'], ENT_QUOTES, 'UTF-8')."</rtp_port_end>\n";
    }

    // Webserver login tags
    $xml .= "    <webserver_user_name perm=\"R\">user</webserver_user_name>\n";
    $xml .= "    <webserver_user_password perm=\"R\">".htmlspecialchars($user_pass, ENT_QUOTES, 'UTF-8')."</webserver_user_password>\n";
    $xml .= "    <http_user perm=\"R\">admin</http_user>\n";
    $xml .= "    <webserver_admin_name perm=\"R\">admin</webserver_admin_name>\n";
    $xml .= "    <http_pass perm=\"R\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</http_pass>\n";
    $xml .= "    <admin_mode_password perm=\"R\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</admin_mode_password>\n";
    $xml .= "    <webserver_admin_password perm=\"R\">".htmlspecialchars($admin_pass, ENT_QUOTES, 'UTF-8')."</webserver_admin_password>\n";

    // ========== Global Settings Mappings (Localization updated; LDAP removed) ==========

    // Provisioning
    if (!empty($server)) {
        $xml .= "    <setting_server perm=\"RW\">".htmlspecialchars($server, ENT_QUOTES, 'UTF-8')."</setting_server>\n";
    }
    if (isset($overrides['prov_interval'])) {
        $interval = (int)$overrides['prov_interval'];
        if ($interval > 0) {
            $xml .= "    <prov_polling_enabled perm=\"RW\">on</prov_polling_enabled>\n";
            $xml .= "    <prov_polling_mode perm=\"RW\">rel</prov_polling_mode>\n";
            $xml .= "    <prov_polling_period perm=\"RW\">".$interval."</prov_polling_period>\n";
        } else {
            $xml .= "    <prov_polling_enabled perm=\"RW\">off</prov_polling_enabled>\n";
        }
    }
    if (isset($overrides['prov_resync_boot'])) {
        $xml .= "    <keep_provisioning_url_after_reboot perm=\"RW\">".($overrides['prov_resync_boot']==='on' ? 'on' : 'off')."</keep_provisioning_url_after_reboot>\n";
    }

    // Localization (UPDATED)
    // Phone LCD Language (tag: <language>) - uses provided labels directly
    if (!empty($overrides['loc_lcd_language'])) {
        $xml .= "    <language perm=\"RW\">".htmlspecialchars($overrides['loc_lcd_language'], ENT_QUOTES, 'UTF-8')."</language>\n";
    } elseif (!empty($overrides['loc_language'])) { // legacy fallback
        $xml .= "    <language perm=\"RW\">".htmlspecialchars($overrides['loc_language'], ENT_QUOTES, 'UTF-8')."</language>\n";
    }
    // Web UI Language (tag: <web_language>)
    if (!empty($overrides['loc_web_language'])) {
        $xml .= "    <web_language perm=\"RW\">".htmlspecialchars($overrides['loc_web_language'], ENT_QUOTES, 'UTF-8')."</web_language>\n";
    }
    // Timezone (tag: <timezone>)
    if (!empty($overrides['loc_timezone'])) {
        $xml .= "    <timezone perm=\"RW\">".htmlspecialchars($overrides['loc_timezone'], ENT_QUOTES, 'UTF-8')."</timezone>\n";
    }
    // Locale (tag: <locale>) replaces time_24_format
    if (!empty($overrides['loc_locale'])) {
        $xml .= "    <locale perm=\"RW\">".htmlspecialchars($overrides['loc_locale'], ENT_QUOTES, 'UTF-8')."</locale>\n";
    }
    // Date format (optional toggle)
    if (!empty($overrides['loc_date_fmt'])) {
        $xml .= "    <date_us_format perm=\"RW\">".($overrides['loc_date_fmt']==='MM-DD-YYYY' ? 'on' : 'off')."</date_us_format>\n";
    }
    // Removed: <time_24_format>

    // Contact List (only Local Directory URL; LDAP removed)
    if (!empty($overrides['contacts_local_dir_url'])) {
        $xml .= "    <extdir_url idx=\"1\" perm=\"RW\">".htmlspecialchars($overrides['contacts_local_dir_url'], ENT_QUOTES, 'UTF-8')."</extdir_url>\n";
    }

    // Maintenance
    if (!empty($overrides['maint_fw_url'])) {
        $xml .= "    <firmware perm=\"RW\">".htmlspecialchars($overrides['maint_fw_url'], ENT_QUOTES, 'UTF-8')."</firmware>\n";
    }

    // Network
    if (!empty($overrides['net_vlan_voice'])) {
        $xml .= "    <vlan_id perm=\"RW\">".htmlspecialchars(preg_replace('/\D/','',(string)$overrides['net_vlan_voice']), ENT_QUOTES, 'UTF-8')."</vlan_id>\n";
        $xml .= "    <vlan_port_tagging perm=\"RW\">on</vlan_port_tagging>\n";
    }
    if (isset($overrides['net_lldp_med'])) {
        $xml .= "    <lldp_enable perm=\"RW\">".($overrides['net_lldp_med']==='on' ? 'on' : 'off')."</lldp_enable>\n";
    }
    if ($sip_tos !== null) {
        $xml .= "    <signaling_tos perm=\"RW\">".$sip_tos."</signaling_tos>\n";
    }
    if ($rtp_tos !== null) {
        $xml .= "    <codec_tos perm=\"RW\">".$rtp_tos."</codec_tos>\n";
    }

    // Security
    if (!empty($overrides['sec_sip_transport'])) {
        $tr = strtolower((string)$overrides['sec_sip_transport']);
        if (in_array($tr, ['udp','tcp','tls'], true)) {
            $xml .= "    <user_media_transport_offer idx=\"1\" perm=\"RW\">".$tr."</user_media_transport_offer>\n";
        }
    }
    if (!empty($overrides['sec_srtp'])) {
        $mode = strtolower((string)$overrides['sec_srtp']); // off | optional | mandatory
        if ($mode === 'off') {
            $xml .= "    <user_srtp idx=\"1\" perm=\"RW\">off</user_srtp>\n";
            $xml .= "    <user_srtcp idx=\"1\" perm=\"RW\">off</user_srtcp>\n";
            $xml .= "    <user_savp idx=\"1\" perm=\"RW\">off</user_savp>\n";
        } elseif ($mode === 'mandatory') {
            $xml .= "    <user_srtp idx=\"1\" perm=\"RW\">on</user_srtp>\n";
            $xml .= "    <user_srtcp idx=\"1\" perm=\"RW\">on</user_srtcp>\n";
            $xml .= "    <user_savp idx=\"1\" perm=\"RW\">on</user_savp>\n";
        } else { // optional
            $xml .= "    <user_srtp idx=\"1\" perm=\"RW\">on</user_srtp>\n";
            $xml .= "    <user_srtcp idx=\"1\" perm=\"RW\">on</user_srtcp>\n";
            $xml .= "    <user_savp idx=\"1\" perm=\"RW\">off</user_savp>\n";
        }
    }

    // Call Features
    if (isset($overrides['call_dnd'])) {
        $xml .= "    <dnd_mode idx=\"1\" perm=\"RW\">".($overrides['call_dnd']==='on' ? 'on' : 'off')."</dnd_mode>\n";
    }
    if (isset($overrides['call_waiting'])) {
        $xml .= "    <call_waiting idx=\"1\" perm=\"RW\">".($overrides['call_waiting']==='off' ? 'off' : 'on')."</call_waiting>\n";
    }
    if (!empty($overrides['call_pickup'])) {
        $xml .= "    <blf_directed_call_pickup idx=\"1\" perm=\"RW\">".htmlspecialchars($overrides['call_pickup'], ENT_QUOTES, 'UTF-8')."</blf_directed_call_pickup>\n";
    }
    if (!empty($overrides['call_park'])) {
        $xml .= "    <blf_park_pick_up idx=\"1\" perm=\"RW\">".htmlspecialchars($overrides['call_park'], ENT_QUOTES, 'UTF-8')."</blf_park_pick_up>\n";
    }

    // Logging
    if (!empty($overrides['log_server'])) {
        $xml .= "    <syslog_server perm=\"RW\">".htmlspecialchars($overrides['log_server'], ENT_QUOTES, 'UTF-8')."</syslog_server>\n";
    }
    if ($log_level_num !== null) {
        $xml .= "    <log_level perm=\"RW\">".$log_level_num."</log_level>\n";
    }

    // Custom per-device tags (raw)
    if (trim($custom_xml) !== '') {
        $xml .= "\n    <!-- Custom per-device tags -->\n";
        $lines = explode("\n", $custom_xml);
        foreach ($lines as $L) { $xml .= '    ' . rtrim($L) . "\n"; }
    }
    $xml .= "  </phone-settings>\n";

    // Function keys block: indices MUST start at 0
    $xml .= "  <functionKeys e=\"2\">\n";
    $i = 0; // start at 0
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

/* ========================= Merge assign helper ========================= */
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

/* ========================= POST handlers (PRG) ========================= */
if (isset($wiz['edit_ext'])) unset($wiz['edit_ext']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['open_global'])) {
    header('Location: extensions.php?system_id=' . (int)$sysId . '&global=1'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['assign']) && is_array($_POST['assign']) && !isset($_POST['generate_one']) && !isset($_POST['generate_selected']) && !isset($_POST['delete_generated'])) {
    $err = '';
    if (!merge_assign_into_session($_POST['assign'], $wiz, $err)) {
        $wiz['flash']=['msg'=>$err,'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz);
        header('Location: extensions.php?system_id=' . (int)$sysId); exit;
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    $wiz['flash']=['msg'=>'Assignments saved.','type'=>'success']; save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id=' . (int)$sysId); exit;
}

/* Global Settings save */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_global'])) {
    // Merge all grouped keys
    $wiz['global'] = array_replace($wiz['global'], (array)($_POST['global'] ?? []));

    // Back-compat legacy keys and defaults
    $wiz['global']['setting_server'] = trim((string)($wiz['global']['prov_server'] ?? ($wiz['global']['setting_server'] ?? '')));
    if (!isset($wiz['global']['codec_priority_list'])) {
        $wiz['global']['codec_priority_list'] = 'g722,pcmu,pcma,g729,telephone-event';
    }
    if (!isset($wiz['global']['rtp_port_start'])) {
        $wiz['global']['rtp_port_start'] = '49152';
    }
    if (!isset($wiz['global']['rtp_port_end'])) {
        $wiz['global']['rtp_port_end'] = '65534';
    }

    $wiz['flash'] = ['msg'=>'Global settings saved.','type'=>'success'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id=' . (int)$sysId . '&global=1'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit'])) {
    $ext = (string)$_POST['edit'];
    header('Location: extensions.php?system_id=' . (int)$sysId . '&edit=' . urlencode($ext)); exit;
}

// Save settings (per-extension): Admin password (view/copy only), BLF, Custom tags
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_settings']) && isset($_POST['ext'])) {
    $ext = (string)$_POST['ext'];
    $settings = $wiz['settings'][$ext] ?? [];

    // Admin web UI password (persist)
    if (isset($_POST['cfg_http_pass_real']) && trim((string)$_POST['cfg_http_pass_real']) !== '') {
        $settings['http_pass'] = trim((string)$_POST['cfg_http_pass_real']);
    } elseif (empty($settings['http_pass'])) {
        $settings['http_pass'] = random_password(16);
    }

    // Optional user password
    if (isset($_POST['cfg_user_http_pass']) && trim((string)$_POST['cfg_user_http_pass']) !== '') {
        $settings['user_http_pass'] = trim((string)$_POST['cfg_user_http_pass']);
    }

    // BLF rows
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
    // Enforce cap
    $model_for_ext = $wiz['assign'][$ext]['model'] ?? '';
    $cap = fkey_cap_for_model((string)$model_for_ext);
    if (count($blf) > $cap) {
        $blf = array_slice($blf, 0, $cap);
        $wiz['flash'] = ['msg' => "F-keys limited to {$cap} for model ".(($model_for_ext?:'Unknown')).". Excess removed.", 'type' => 'warn'];
    }
    $settings['__blf'] = $blf;

    // Custom per-device XML
    $settings['custom_xml'] = (string)($_POST['cfg']['custom_xml'] ?? ($settings['custom_xml'] ?? ''));

    $wiz['settings'][$ext] = $settings;
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    if (empty($wiz['flash'])) $wiz['flash']=['msg'=>"Settings saved for {$ext}.",'type'=>'success'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId.'&edit='.urlencode($ext)); exit;
}

/* ===== Generate (merge current assign first) ===== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_one']) && $_POST['generate_one']!=='') {
    if (isset($_POST['assign']) && is_array($_POST['assign'])) { $err=''; if (!merge_assign_into_session($_POST['assign'], $wiz, $err)) { $wiz['flash']=['msg'=>$err,'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; } save_wiz_to_db($pdo,$sysId,$uid,$wiz); }
    $ext=(string)$_POST['generate_one']; $found=null; foreach($exts as $e) if((string)$e['extension']===$ext){ $found=$e; break; }
    if(!$found){ $wiz['flash']=['msg'=>"Extension {$ext} not found.",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    $mac = $wiz['assign'][$ext]['mac'] ?? '';
    if ($mac===''){ $wiz['flash']=['msg'=>"No MAC assigned for {$ext}.",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    if (!is_valid_mac($mac)) { $wiz['flash']=['msg'=>"Invalid MAC for {$ext}. Expect 12 hex characters (0-9,A-F).",'type'=>'warn']; save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit; }
    $over = $wiz['settings'][$ext] ?? [];
    if (empty($over['http_pass'])) { $over['http_pass'] = random_password(16); $wiz['settings'][$ext]['http_pass'] = $over['http_pass']; }
    if (empty($over['user_http_pass'])) { $over['user_http_pass'] = random_password(16); $wiz['settings'][$ext]['user_http_pass'] = $over['user_http_pass']; }
    $over['__model'] = $wiz['assign'][$ext]['model'] ?? '';
    $global = $wiz['global'] ?? [];
    $merged = array_merge($global, $over);
    if (empty($merged['setting_server']) && !empty($sys['host'])) $merged['setting_server'] = $sys['host'];
    $oldfile = rtrim($PROVISION_DIR,'/')."/{$mac}.xml"; if (file_exists($oldfile)) @unlink($oldfile);
    [$ok,$res] = write_profile($PROVISION_DIR, $sys['host'], $found, $mac, $merged, $exts);
    if ($ok) { $wiz['generated'][$ext]=['mac'=>$res,'url'=>$PUBLIC_PROVISION_PATH.'/'.$res.'.xml','created'=>date('c')]; $wiz['flash']=['msg'=>"Generated 1 profile for {$ext}.",'type'=>'success']; }
    else { $wiz['flash']=['msg'=>"Failed generating {$ext}: {$res}",'type'=>'warn']; }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

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
        if (empty($over['http_pass'])) { $over['http_pass'] = random_password(16); $wiz['settings'][$ext]['http_pass'] = $over['http_pass']; }
        if (empty($over['user_http_pass'])) { $over['user_http_pass'] = random_password(16); $wiz['settings'][$ext]['user_http_pass'] = $over['user_http_pass']; }
        $over['__model'] = $wiz['assign'][$ext]['model'] ?? '';
        $merged = array_merge($global, $over);
        if (empty($merged['setting_server']) && !empty($sys['host'])) $merged['setting_server'] = $sys['host'];
        $oldfile = rtrim($PROVISION_DIR,'/')."/{$mac}.xml"; if (file_exists($oldfile)) @unlink($oldfile);
        [$ok,$res] = write_profile($PROVISION_DIR, $sys['host'], $found, $mac, $merged, $exts);
        if ($ok) { $wiz['generated'][$ext]=['mac'=>$res,'url'=>$PUBLIC_PROVISION_PATH.'/'.$res.'.xml','created'=>date('c')]; $count++; } else $errors[]="Failed {$ext}: {$res}";
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    $msg = "Generated {$count} profiles."; if (!empty($errors)) $msg .= ' Errors: '.implode('; ',$errors);
    $wiz['flash']=['msg'=>$msg,'type'=>$count ? 'success' : 'warn'];
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
    header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_generated']) && $_POST['delete_generated']!=='') {
    $ext=(string)$_POST['delete_generated']; $mac=$wiz['generated'][$ext]['mac'] ?? ($wiz['assign'][$ext]['mac'] ?? '');
    if ($mac!=='') {
        $file = rtrim($PROVISION_DIR,'/')."/{$mac}.xml";
        if (file_exists($file)) {
            if (@unlink($file)) { unset($wiz['generated'][$ext]); $wiz['flash']=['msg'=>"Deleted generated file for {$ext}.",'type'=>'success']; }
            else $wiz['flash']=['msg'=>"Failed to delete file for {$ext}",'type'=>'warn'];
        } else { $wiz['flash']=['msg'=>"No generated file found for {$ext}",'type'=>'warn']; }
    } else { $wiz['flash']=['msg'=>"No MAC known for {$ext}",'type'=>'warn']; }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz); header('Location: extensions.php?system_id='.(int)$sysId); exit;
}

/* ========================= Client-side data ========================= */
$mac_list_for_js = [];
if (!empty($_SESSION['mac_list']) && is_array($_SESSION['mac_list'])) foreach($_SESSION['mac_list'] as $mac=>$info) $mac_list_for_js[]=$info;
$mac_list_json = json_encode($mac_list_for_js, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);
$assigned_macs = []; foreach ($wiz['assign'] as $aext=>$adata) { $am = normalize_mac((string)$adata['mac']); if ($am!=='') $assigned_macs[$am] = $aext; }
$assigned_macs_json = json_encode($assigned_macs, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);

// flash -> toast
$toast_msg = ''; $toast_type = 'success';
if (!empty($wiz['flash']) && is_array($wiz['flash'])) {
    $toast_msg = sanitize_for_ui($wiz['flash']['msg'] ?? '');
    $toast_msg = preg_replace('/\?+\s*$/', '', $toast_msg);
    $toast_type = $wiz['flash']['type'] ?? 'success';
    $wiz['flash'] = null;
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
}

// open modals via GET
$show_edit_ext = null;
if (isset($_GET['edit']) && trim((string)$_GET['edit']) !== '') $show_edit_ext = sanitize_for_ui((string)$_GET['edit']);
$show_global = (isset($_GET['global']) && (string)$_GET['global'] === '1');

// Ensure passwords exist on Edit open
if (!empty($show_edit_ext)) {
    $ext = $show_edit_ext;
    if (!isset($wiz['settings'][$ext])) $wiz['settings'][$ext] = [];
    if (empty($wiz['settings'][$ext]['http_pass'])) {
        $wiz['settings'][$ext]['http_pass'] = random_password(16);
    }
    if (empty($wiz['settings'][$ext]['user_http_pass'])) {
        $wiz['settings'][$ext]['user_http_pass'] = random_password(16);
    }
    save_wiz_to_db($pdo,$sysId,$uid,$wiz);
}

// Extension -> fullname map for JS (sanitized)
$ext_to_fullname = [];
foreach ($exts as $row) {
    $ee = (string)($row['extension'] ?? '');
    $nm = sanitize_for_ui((string)($row['fullname'] ?? ''));
    if ($ee !== '') $ext_to_fullname[$ee] = $nm;
}
$ext_to_fullname_json = json_encode($ext_to_fullname, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);

/* ========================= Render ========================= */
$title_safe = sanitize_for_ui((string)($sys['label'] ?? 'Provisioning'));
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?= e($title_safe) ?> - Extensions</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Request font subsets for Vietnamese and Cyrillic glyph support -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap&subset=latin,latin-ext,cyrillic,vietnamese" rel="stylesheet">
<style>
:root{--bg:#f3f5f9;--card:#fff;--muted:#475569;--accent:#2f3bd6;--accent-2:#0ea5e9;--danger:#dc2626;--input-h:36px;--tab:#e7ecfb}
body{background:var(--bg);margin:18px;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial;color:#0f1724}
.container{max-width:1200px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.logo{height:48px;width:auto;border-radius:8px;padding:6px;background:#fff;object-fit:contain}
.small{font-size:13px;color:var(--muted)}
.btn{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.btn.secondary{background:#334155}
.btn.warn{background:var(--danger)}
.btn.ghost{background:#edf2ff;color:#0b2548}
.table{margin-top:12px;border-radius:10px;overflow:hidden;box-shadow:0 8px 30px rgba(2,6,23,0.06)}
.table table{width:100%;border-collapse:collapse;background:var(--card)}
.table th, .table td{padding:12px;border-bottom:1px solid #eef2f6;vertical-align:middle}
.table thead th{background:#fbfdff; text-align:left; padding-left:18px}
.macs-input, select[name$="[model]"]{height:var(--input-h);padding:6px 10px;border-radius:8px;border:1px solid #e6eef8;font-size:13px;box-sizing:border-box}
.mac-combo-input{width:220px;text-transform:uppercase}
.row-actions{display:flex;gap:8px;align-items:center;white-space:nowrap}
.sel-chk{width:18px;height:18px;margin:0}
.small-input{padding:8px 10px;border-radius:8px;border:1px solid #e6eef8;background:#fff}
.modal-card{width:980px;max-width:100%;max-height:92vh;overflow:auto;background:var(--card);border-radius:14px;padding:20px;box-shadow:0 30px 80px rgba(2,6,23,0.18);border:1px solid rgba(30,64,175,0.06)}
.center-toast-overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;z-index:200000;background:rgba(7,12,20,0.25)}
.center-toast{min-width:260px;max-width:92%;padding:12px 16px;border-radius:10px;color:#fff;font-weight:700;text-align:center;display:flex;align-items:center;gap:12px}
.center-toast.success{background:linear-gradient(90deg,#059669,#047857)}
.center-toast.warn{background:linear-gradient(90deg,#f97316,#dc2626)}
.center-toast .close-btn{background:transparent;border:0;color:rgba(255,255,255,0.95);font-size:18px;cursor:pointer;padding:6px;border-radius:8px}
.center-toast .close-btn:hover{background:rgba(255,255,255,0.06)}
.mac-combo{position:relative;display:inline-block}
.mac-combo-list{position:absolute;left:0;right:0;top:calc(100% + 6px);background:#fff;border:1px solid #e6eef8;border-radius:8px;max-height:220px;overflow:auto;z-index:120;box-shadow:0 12px 40px rgba(2,6,23,0.08);display:none}
.mac-combo-item{padding:8px 10px;border-bottom:1px solid #f1f5f9;cursor:pointer;font-family:monospace}
.mac-combo-item:hover,.mac-combo-item.active{background:#f1f7ff}
.mac-combo-empty{padding:8px 10px;color:#64748b}
.tabs{display:flex;gap:8px;border-bottom:1px solid #e6eef8;margin-bottom:12px}
.tab{padding:8px 12px;border-radius:10px 10px 0 0;background:var(--tab);cursor:pointer;color:#0b2548}
.tab.active{background:#fff;border:1px solid #e6eef8;border-bottom-color:#fff}
.tabpanel{display:none}
.tabpanel.active{display:block}
.kv{display:flex;gap:12px;align-items:flex-end}
.kv .label{min-width:160px;color:#475569;font-size:13px}
.kv .value{flex:1}
.inline-actions{display:flex;gap:8px}
.icon-btn{background:#0b1020;color:#fff;border:0;border-radius:8px;padding:6px 8px;cursor:pointer}
.icon-btn.blue{background:var(--accent-2)}
.textarea{width:100%;min-height:140px;padding:10px;border:1px solid #e6eef8;border-radius:10px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;font-size:12px;line-height:1.4;white-space:pre}
</style>
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

    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn secondary" type="button" onclick="document.getElementById('switch-site-modal').style.display='flex'">Switch Site</button>
      <a href="logout.php" class="btn warn" style="text-decoration:none;padding:8px 10px;border-radius:8px">Logout</a>
      <form method="post" style="margin:0"><input type="hidden" name="fetch_ucm" value="1"><button class="btn secondary" type="submit">Refresh Extensions</button></form>
      <button id="generate-selected-btn" type="button" class="btn">Generate Selected</button>
      <form method="post" enctype="multipart/form-data" style="margin:0;display:inline-flex;align-items:center;gap:6px">
        <input type="file" name="mac_csv" accept=".csv">
        <button class="btn" type="submit">Upload CSV</button>
      </form>
    </div>
  </div>

  <?php if (!empty($csv_msg)): ?><div style="margin-top:6px" class="small"><?= e($csv_msg) ?></div><?php endif; ?>

  <div style="margin-top:12px;display:flex;gap:8px;align-items:center;justify-content:space-between">
    <div style="display:flex;gap:8px;align-items:center">
      <form method="post" style="margin:0;display:inline">
        <button class="btn" type="submit" name="open_global" value="1">Global Settings</button>
      </form>
      <button class="btn" id="save-assignments-btn" type="button" onclick="document.getElementById('assign-form').submit()">Save Assignments</button>
    </div>
    <div class="small" style="color:#64748b">Edit opens per-device Admin Password, BLF Keys, and Custom Tags</div>
  </div>

  <div class="table" style="margin-top:12px">
    <form method="post" id="assign-form">
      <table>
        <thead><tr><th></th><th style="width:120px">Extension</th><th>Fullname</th><th style="width:240px">MAC</th><th style="width:180px">Model</th><th style="width:260px">Actions</th></tr></thead>
        <tbody>
        <?php if (!empty($exts)): foreach ($exts as $r):
          $ext = sanitize_for_ui((string)$r['extension']);
          $full = sanitize_for_ui((string)$r['fullname']);
          $macVal = $wiz['assign'][$ext]['mac'] ?? ''; $modelVal = $wiz['assign'][$ext]['model'] ?? ''; $isGen = isset($wiz['generated'][$ext]);
          $comboId = 'mac_combo_'.preg_replace('/[^A-Za-z0-9_-]/','_',$ext);
        ?>
          <tr>
            <td><input type="checkbox" class="sel-chk" value="<?= e($ext) ?>"></td>
            <td><?= e($ext) ?></td>
            <td><?= e($full) ?></td>
            <td>
              <div class="mac-combo" data-ext="<?= e($ext) ?>">
                <input type="text" name="assign[<?= e($ext) ?>][mac]" value="<?= e($macVal) ?>" class="mac-combo-input macs-input" data-combo-id="<?= e($comboId) ?>" placeholder="AABBCCDDEEFF" maxlength="17" autocomplete="off" aria-label="MAC for <?= e($ext) ?>">
                <div class="mac-combo-list" id="<?= e($comboId) ?>" role="listbox" aria-label="MAC suggestions"></div>
              </div>
            </td>
            <td>
              <select name="assign[<?= e($ext) ?>][model]" class="small-input">
                <option value="">Select</option>
                <?php foreach (['D895','D892','D865','D862','D815','D812','D150','D140','D810WB'] as $m) { $sel = ($modelVal === $m) ? 'selected' : ''; echo "<option value=\"".e($m)."\" $sel>".e($m)."</option>"; } ?>
              </select>
            </td>
            <td>
              <div class="row-actions" role="group">
                <button class="btn" type="button" onclick="postGenerate('<?= e($ext) ?>')">Generate</button>
                <button class="btn secondary" type="button" onclick="postEdit('<?= e($ext) ?>')">Edit</button>
                <?php if ($isGen): $url = $wiz['generated'][$ext]['url'] ?? ''; if ($url): ?>
                  <a class="btn secondary" href="<?= e($url) ?>" target="_blank" rel="noopener noreferrer">Download</a>
                <?php endif; ?>
                  <button type="button" class="btn warn" onclick="confirmDelete('<?= e($ext) ?>')">Delete File</button>
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
      <div><button type="button" class="btn secondary" onclick="document.getElementById('switch-site-modal').style.display='none'">Close</button></div>
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
        <button type="button" class="btn secondary" onclick="document.getElementById('switch-site-modal').style.display='none'">Cancel</button>
        <button type="button" class="btn" onclick="switchSiteGo()">Go</button>
      </div>
    </div>
  </div>
</div>

<!-- Global Settings modal (Localization updated, LDAP removed) -->
<?php if ($show_global): ?>
<div id="global-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9998">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="global-modal-title" style="max-width:980px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 id="global-modal-title" style="margin:0">Global Settings</h3>
      <div><a class="btn secondary" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Close</a></div>
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="tab-loc">Localization</div>
      <div class="tab" data-tab="tab-contacts">Contact List</div>
      <div class="tab" data-tab="tab-maint">Maintenance</div>
      <div class="tab" data-tab="tab-net">Network</div>
      <div class="tab" data-tab="tab-sec">Security</div>
      <div class="tab" data-tab="tab-prov">Provisioning</div>
      <div class="tab" data-tab="tab-call">Call Features</div>
      <div class="tab" data-tab="tab-log">Logging</div>
    </div>

    <form method="post" style="display:block">
      <!-- Localization (UPDATED) -->
      <div id="tab-loc" class="tabpanel active" style="display:block">
        <div class="kv">
          <div class="label">Web UI Language</div>
          <div class="value">
            <select class="small-input" name="global[loc_web_language]">
              <?php
              $webLang = $wiz['global']['loc_web_language'] ?? 'English';
              $webOpts = ['English','Dansk','Deutsch','Espa ol','Fran ais','Italiano','Polski','Svenska','??????????'];
              foreach ($webOpts as $opt) { $sel = ($webLang === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
              ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">Phone LCD Language</div>
          <div class="value">
            <select class="small-input" name="global[loc_lcd_language]">
              <?php
              $lcdLang = $wiz['global']['loc_lcd_language'] ?? ($wiz['global']['loc_language'] ?? 'English'); // legacy fallback
              $lcdOpts = ['English','Dansk','Deutsch','Espa ol','Fran ais','Italiano','Magyar','Nederlands','Polski','Svenska','Ti?ng Vi?t','??????????'];
              foreach ($lcdOpts as $opt) { $sel = ($lcdLang === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
              ?>
            </select>
          </div>
        </div>
        <div class="kv">
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
        </div>
        <div class="kv">
          <div class="label">Locale (date/time)</div>
          <div class="value">
            <select class="small-input" name="global[loc_locale]">
              <?php
              $loc = $wiz['global']['loc_locale'] ?? 'en_US';
              $localeOpts = [
"om_ET","om_KE","aa_ET","af_ZA","af_NA","sq_AL","sq_MK","sq_XK","am_ET","ar_EG","ar_DZ","ar_BH","ar_TD","ar_KM","ar_DJ","ar_ER","ar_IQ","ar_IL","ar_JO","ar_KW","ar_LB","ar_LY","ar_MR","ar_MA","ar_OM","ar_PS","ar_QA","ar_SA","ar_SO","ar_SD","ar_SY","ar_TN","ar_AE","ar_EH","ar_YE","ar_SS","ar_001","hy_AM","as_IN","az_AZ","az_IR","az_AZ","ba_RU","eu_ES","bn_BD","bn_IN","dz_BT","br_FR","bg_BG","my_MM","be_BY","km_KH","ca_ES","ca_AD","ca_FR","ca_IT","zh_CN","zh_HK","zh_MO","zh_SG","zh_HK","zh_MO","zh_TW","co_FR","hr_HR","hr_BA","cs_CZ","da_DK","da_GL","nl_NL","nl_AW","nl_BE","nl_CW","nl_SR","nl_BQ","nl_SX","en_US","en_US","en_AS","en_AI","en_AG","en_AU","en_AT","en_BS","en_BB","en_BE","en_BZ","en_BM","en_BW","en_IO","en_BI","en_CM","en_CA","en_KY","en_CX","en_CC","en_CK","en_CY","en_DK","en_DM","en_ER","en_FK","en_FJ","en_FI","en_GG","en_GM","en_DE","en_GH","en_GI","en_GD","en_GU","en_GY","en_HK","en_IN","en_IE","en_IL","en_JM","en_KE","en_KI","en_LS","en_LR","en_MO","en_MG","en_MW","en_MY","en_MT","en_MH","en_MU","en_FM","en_MS","en_NA","en_NR","en_NL","en_NZ","en_NG","en_NU","en_NF","en_MP","en_PK","en_PW","en_PG","en_PH","en_PN","en_PR","en_RW","en_KN","en_LC","en_VC","en_WS","en_SC","en_SL","en_SG","en_SI","en_SB","en_ZA","en_SH","en_SD","en_SZ","en_SE","en_CH","en_TZ","en_TK","en_TO","en_TT","en_TC","en_TV","en_UG","en_AE","en_GB","en_UM","en_VU","en_VG","en_VI","en_ZM","en_ZW","en_DG","en_IM","en_JE","en_SS","en_SX","en_001","en_150","eo_001","et_EE","fo_FO","fo_DK","fi_FI","fr_FR","fr_DZ","fr_BE","fr_BJ","fr_BF","fr_BI","fr_CM","fr_CA","fr_CF","fr_TD","fr_KM","fr_CD","fr_CG","fr_CI","fr_DJ","fr_GQ","fr_GF","fr_PF","fr_GA","fr_GP","fr_GN","fr_HT","fr_LU","fr_MG","fr_ML","fr_MQ","fr_MR","fr_MU","fr_YT","fr_MC","fr_MA","fr_NC","fr_NE","fr_RE","fr_RW","fr_SN","fr_SC","fr_PM","fr_CH","fr_SY","fr_TG","fr_TN","fr_VU","fr_WF","fr_BL","fr_MF","fy_NL","gd_GB","gl_ES","ka_GE","de_DE","de_AT","de_BE","de_IT","de_LI","de_LU","de_CH","el_GR","el_CY","kl_GL","gn_PY","gu_IN","ha_NG","ha_NG","ha_GH","ha_NE","he_IL","hi_IN","hi_IN","hu_HU","is_IS","id_ID","ia_001","iu_CA","iu_CA","ga_IE","ga_GB","it_IT","it_SM","it_CH","it_VA","ja_JP","jv_ID","kn_IN","ks_IN","ks_IN","kk_KZ","rw_RW","ky_KG","ko_KR","ko_KP","ku_TR","rn_BI","lo_LA","la_VA","lv_LV","ln_CD","ln_AO","ln_CF","ln_CG","lt_LT","mk_MK","mg_MG","ms_MY","ms_MY","ms_BN","ms_ID","ms_SG","ml_IN","mt_MT","mi_NZ","mr_IN","mn_MN","mn_CN","ne_NP","ne_IN","nb_NO","nb_SJ","oc_FR","or_IN","ps_AF","ps_PK","fa_IR","fa_AF","pl_PL","pt_BR","pt_AO","pt_CV","pt_TL","pt_GQ","pt_GW","pt_LU","pt_MO","pt_MZ","pt_PT","pt_ST","pt_CH","pa_IN","pa_PK","qu_PE","qu_BO","qu_EC","rm_CH","ro_RO","ro_MD","ru_RU","ru_BY","ru_KZ","ru_KG","ru_MD","ru_UA","sg_CF","sa_IN","sr_RS","sr_BA","sr_ME","sr_RS","sr_BA","sr_ME","sr_XK","sr_XK","os_GE","os_RU","st_ZA","tn_ZA","sn_ZW","sd_PK","sd_IN","si_LK","ss_ZA","sk_SK","sl_SI","so_SO","so_DJ","so_ET","so_KE","es_ES","es_AR","es_BZ","es_BO","es_BR","es_CL","es_CO","es_CR","es_CU","es_DO","es_EC","es_SV","es_GQ","es_GT","es_HN","es_MX","es_NI","es_PA","es_PY","es_PE","es_PH","es_PR","es_US","es_UY","es_VE","es_IC","es_419","es_EA","su_ID","sw_TZ","sw_CD","sw_KE","sw_UG","sv_SE","sv_FI","sv_AX","sc_IT","tg_TJ","ta_IN","ta_MY","ta_SG","ta_LK","tt_RU","te_IN","th_TH","bo_CN","bo_IN","ti_ET","ti_ER","to_TO","ts_ZA","tr_TR","tr_CY","tk_TM","ug_CN","uk_UA","ur_PK","ur_IN","uz_UZ","uz_AF","uz_UZ","vi_VN","vo_001","cy_GB","wo_SN","xh_ZA","yi_001","yo_NG","yo_BJ","zu_ZA","nn_NO","bs_BA","bs_BA","dv_MV","gv_IM","kw_GB","ak_GH","kok_IN","gaa_GH","ig_NG","kam_KE","syr_IQ","byn_ER","gez_ET","sid_ET","cch_NG","tig_ER","kaj_NG","fur_IT","ve_ZA","ee_GH","ee_TG","wal_ET","haw_US","kcg_NG","ny_MW","fil_PH","gsw_CH","gsw_FR","gsw_LI","ii_CN","kpe_LR","nds_DE","nds_NL","nr_ZA","nso_ZA","se_NO","se_FI","se_SE","trv_TW","guz_KE","dav_KE","ff_SN","ff_BF","ff_CM","ff_GM","ff_GH","ff_GN","ff_GW","ff_LR","ff_MR","ff_NE","ff_NG","ff_SL","ki_KE","saq_KE","seh_MZ","nd_ZW","rof_TZ","shi_MA","shi_MA","kab_DZ","nyn_UG","bez_TZ","vun_TZ","bm_ML","bm_ML","ebu_KE","chr_US","mfe_MU","kde_TZ","lag_TZ","lg_UG","bem_ZM","kea_CV","mer_KE","kln_KE","naq_NA","jmc_TZ","ksh_DE","mas_KE","mas_TZ","xog_UG","luy_KE","asa_TZ","teo_UG","teo_KE","ssy_ER","khq_ML","rwk_TZ","luo_KE","cgg_UG","tzm_MA","ses_ML","ksb_TZ","brx_IN","ce_RU","cu_RU","cv_RU","lu_CD","lb_LU","nv_US","wa_BE","agq_CM","bas_CM","dje_NE","dua_CM","dyo_SN","ewo_CM","ksf_CM","mgh_MZ","mua_CM","nmg_CM","nus_SS","sah_RU","sbp_TZ","twq_NE","vai_LR","vai_LR","wae_CH","yav_CM","ast_ES","jgo_CM","kkj_CM","mgo_CM","nnh_CM","an_ES","doi_IN","mni_IN","mni_IN","sat_IN","sat_IN","blt_VN","bss_CM","lkt_US","zgh_MA","arn_CL","ckb_IQ","ckb_IR","dsb_DE","hsb_DE","ken_CM","moh_CA","nqo_GN","prg_001","quc_GT","sma_SE","smj_SE","smn_FI","sms_FI","wbp_AU","mai_IN","mzn_IR","lrc_IR","lrc_IQ","yue_HK","yue_CN","osa_US","io_001","jbo_001","scn_IT","sdh_IR","bgn_PK","ceb_PH","myv_RU","cic_US","mus_US","szl_PL","pcm_NG"
              ];
              foreach ($localeOpts as $opt) { $sel = ($loc === $opt) ? 'selected' : ''; echo '<option '.$sel.'>'.e($opt).'</option>'; }
              ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">NTP servers</div>
          <div class="value"><input class="small-input" name="global[loc_ntp]" value="<?= e($wiz['global']['loc_ntp'] ?? 'pool.ntp.org') ?>" placeholder="Comma-separated"></div>
        </div>
        <div class="kv">
          <div class="label">Date format</div>
          <div class="value" style="display:flex;gap:8px">
            <select class="small-input" name="global[loc_date_fmt]">
              <?php $df = $wiz['global']['loc_date_fmt'] ?? 'YYYY-MM-DD';
                foreach (['YYYY-MM-DD','DD-MM-YYYY','MM-DD-YYYY'] as $fmt) {
                  $sel = ($df===$fmt)?'selected':'';
                  echo '<option '.$sel.'>'.e($fmt).'</option>';
                } ?>
            </select>
            <!-- Removed 24h/12h time selection; locale governs time display -->
          </div>
        </div>
      </div>

      <!-- Contact List (LDAP removed) -->
      <div id="tab-contacts" class="tabpanel">
        <div class="kv">
          <div class="label">Local Directory URL</div>
          <div class="value">
            <input class="small-input" name="global[contacts_local_dir_url]" value="<?= e($wiz['global']['contacts_local_dir_url'] ?? '') ?>" placeholder="http(s)://.../directory.xml">
          </div>
        </div>
      </div>

      <!-- Maintenance -->
      <div id="tab-maint" class="tabpanel">
        <div class="kv">
          <div class="label">Firmware URL</div>
          <div class="value"><input class="small-input" name="global[maint_fw_url]" value="<?= e($wiz['global']['maint_fw_url'] ?? '') ?>" placeholder="http(s)://.../firmware.bin"></div>
        </div>
        <div class="kv">
          <div class="label">Scheduled Reboot (CRON)</div>
          <div class="value"><input class="small-input" name="global[maint_reboot_cron]" value="<?= e($wiz['global']['maint_reboot_cron'] ?? '') ?>" placeholder="e.g. 0 3 * * 1"></div>
        </div>
      </div>

      <!-- Network -->
      <div id="tab-net" class="tabpanel">
        <div class="kv">
          <div class="label">VLAN (Voice)</div>
          <div class="value"><input class="small-input" name="global[net_vlan_voice]" value="<?= e($wiz['global']['net_vlan_voice'] ?? '') ?>" placeholder="e.g. 20"></div>
        </div>
        <div class="kv">
          <div class="label">LLDP-MED</div>
          <div class="value">
            <select class="small-input" name="global[net_lldp_med]">
              <?php $lldp = $wiz['global']['net_lldp_med'] ?? 'on';
                foreach (['on'=>'On','off'=>'Off'] as $k=>$v){ $sel=($lldp===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">DSCP (SIP/RTP)</div>
          <div class="value" style="display:flex;gap:8px">
            <input class="small-input" name="global[net_dscp_sip]" value="<?= e($wiz['global']['net_dscp_sip'] ?? '24') ?>" placeholder="SIP (e.g. 24)">
            <input class="small-input" name="global[net_dscp_rtp]" value="<?= e($wiz['global']['net_dscp_rtp'] ?? '46') ?>" placeholder="RTP (e.g. 46)">
          </div>
        </div>
        <div class="kv">
          <div class="label">Codec priority list</div>
          <div class="value"><input class="small-input" name="global[codec_priority_list]" value="<?= e($wiz['global']['codec_priority_list'] ?? 'g722,pcmu,pcma,g729,telephone-event') ?>"></div>
        </div>
        <div class="kv" style="gap:8px">
          <div class="label">RTP Ports</div>
          <div class="value" style="display:flex;gap:8px">
            <input class="small-input" name="global[rtp_port_start]" value="<?= e($wiz['global']['rtp_port_start'] ?? '49152') ?>" placeholder="Start">
            <input class="small-input" name="global[rtp_port_end]" value="<?= e($wiz['global']['rtp_port_end'] ?? '65534') ?>" placeholder="End">
          </div>
        </div>
      </div>

      <!-- Security -->
      <div id="tab-sec" class="tabpanel">
        <div class="kv">
          <div class="label">SIP Transport</div>
          <div class="value">
            <select class="small-input" name="global[sec_sip_transport]">
              <?php $tr = $wiz['global']['sec_sip_transport'] ?? 'udp';
                foreach (['udp'=>'UDP','tcp'=>'TCP','tls'=>'TLS'] as $k=>$v){ $sel=($tr===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">SRTP</div>
          <div class="value">
            <select class="small-input" name="global[sec_srtp]">
              <?php $srtp = $wiz['global']['sec_srtp'] ?? 'optional';
                foreach (['off'=>'Off','optional'=>'Optional','mandatory'=>'Mandatory'] as $k=>$v){ $sel=($srtp===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">TLS min version</div>
          <div class="value">
            <select class="small-input" name="global[sec_tls_min]">
              <?php $tls = $wiz['global']['sec_tls_min'] ?? '1.2';
                foreach (['1.0','1.1','1.2','1.3'] as $ver){ $sel=($tls===$ver)?'selected':''; echo "<option $sel>".e($ver)."</option>"; } ?>
            </select>
          </div>
        </div>
      </div>

      <!-- Provisioning -->
      <div id="tab-prov" class="tabpanel">
        <div class="kv">
          <div class="label">Provisioning Server</div>
          <div class="value"><input class="small-input" name="global[prov_server]" value="<?= e($wiz['global']['prov_server'] ?? ($wiz['global']['setting_server'] ?? '')) ?>" placeholder="host or IP (can include http[s]://)"></div>
        </div>
        <div class="kv">
          <div class="label">Poll Interval (min)</div>
          <div class="value"><input class="small-input" name="global[prov_interval]" value="<?= e($wiz['global']['prov_interval'] ?? '60') ?>"></div>
        </div>
        <div class="kv">
          <div class="label">Resync on Boot</div>
          <div class="value">
            <select class="small-input" name="global[prov_resync_boot]">
              <?php $rb = $wiz['global']['prov_resync_boot'] ?? 'on';
                foreach (['on'=>'On','off'=>'Off'] as $k=>$v){ $sel=($rb===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
      </div>

      <!-- Call Features -->
      <div id="tab-call" class="tabpanel">
        <div class="kv">
          <div class="label">DND default</div>
          <div class="value">
            <select class="small-input" name="global[call_dnd]">
              <?php $dnd = $wiz['global']['call_dnd'] ?? 'off';
                foreach (['off'=>'Off','on'=>'On'] as $k=>$v){ $sel=($dnd===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">Call Waiting</div>
          <div class="value">
            <select class="small-input" name="global[call_waiting]">
              <?php $cw = $wiz['global']['call_waiting'] ?? 'on';
                foreach (['on'=>'On','off'=>'Off'] as $k=>$v){ $sel=($cw===$k)?'selected':''; echo "<option value=\"$k\" $sel>$v</option>"; } ?>
            </select>
          </div>
        </div>
        <div class="kv">
          <div class="label">Pickup/ Park codes</div>
          <div class="value" style="display:flex;gap:8px">
            <input class="small-input" name="global[call_pickup]" value="<?= e($wiz['global']['call_pickup'] ?? '*97') ?>" placeholder="Pickup (*97)">
            <input class="small-input" name="global[call_park]" value="<?= e($wiz['global']['call_park'] ?? '*88') ?>" placeholder="Park (*88)">
          </div>
        </div>
      </div>

      <!-- Logging -->
      <div id="tab-log" class="tabpanel">
        <div class="kv">
          <div class="label">Syslog Server</div>
          <div class="value"><input class="small-input" name="global[log_server]" value="<?= e($wiz['global']['log_server'] ?? '') ?>" placeholder="host or IP"></div>
        </div>
        <div class="kv">
          <div class="label">Syslog Level</div>
          <div class="value">
            <select class="small-input" name="global[log_level]">
              <?php $lvl = $wiz['global']['log_level'] ?? 'info';
                foreach (['emerg','alert','crit','err','warning','notice','info','debug'] as $lv){ $sel=($lvl===$lv)?'selected':''; echo "<option $sel>".e($lv)."</option>"; } ?>
            </select>
          </div>
        </div>
      </div>

      <div style="margin-top:14px;text-align:right">
        <a class="btn secondary" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Cancel</a>
        <button class="btn" type="submit" name="save_global" value="1">Save Global</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<!-- Edit modal -->
<?php if (!empty($show_edit_ext)): $edit_ext = $show_edit_ext; $over = $wiz['settings'][$edit_ext] ?? []; $edit_model = $wiz['assign'][$edit_ext]['model'] ?? ''; $edit_cap = fkey_cap_for_model($edit_model); ?>
<div id="edit-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9999">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div>
        <h3 style="margin:0">Edit Device - Ext <?= e($edit_ext) ?></h3>
        <div class="small" style="margin-top:4px;color:#64748b">Model: <?= e($edit_model ?: 'Unknown') ?> - Max F-keys: <?= (int)$edit_cap ?></div>
      </div>
      <div><a class="btn secondary" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Close</a></div>
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="tab-pass">Admin Password</div>
      <div class="tab" data-tab="tab-blf">BLF Keys</div>
      <div class="tab" data-tab="tab-custom">Custom Tags</div>
    </div>

    <form method="post">
      <input type="hidden" name="ext" value="<?= e($edit_ext) ?>">

      <!-- Password tab -->
      <div id="tab-pass" class="tabpanel active">
        <div class="kv">
          <div class="label">Admin password</div>
          <div class="value">
            <div class="inline-actions">
              <?php $masked = !empty($over['http_pass']) ? '*********' : ''; ?>
              <input class="small-input" id="http_pass_mask" type="password" value="<?= e($masked) ?>" readonly placeholder="*********">
              <button type="button" class="icon-btn" onclick="toggleHttpPass()">Show/Hide</button>
              <button type="button" class="icon-btn blue" onclick="copyHttpPass()">Copy</button>
              <input type="hidden" name="cfg_http_pass_real" id="cfg_http_pass_real" value="<?= e($over['http_pass'] ?? '') ?>">
            </div>
            <div class="small" style="margin-top:6px;color:#64748b">Generated automatically on first open. You can view or copy it.</div>
          </div>
        </div>
      </div>

      <!-- BLF tab -->
      <div id="tab-blf" class="tabpanel">
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
              <button type="button" class="btn ghost" onclick="this.closest('div').remove()">Remove</button>
            </div>
          <?php $idx++; endforeach; ?>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px">
          <div class="small" style="color:#64748b">Up to <?= (int)$edit_cap ?> keys</div>
          <button type="button" class="btn secondary" onclick="addBLF()">+ Add BLF</button>
        </div>
      </div>

      <!-- Custom tags tab -->
      <div id="tab-custom" class="tabpanel">
        <div class="small" style="margin-bottom:6px;color:#64748b">Optional: custom XML fragment inserted under &lt;phone-settings&gt; for this device.</div>
        <textarea class="textarea" name="cfg[custom_xml]" placeholder="Example:&#10;&lt;setting name=&quot;foo&quot;&gt;bar&lt;/setting&gt;"><?php
          $cx = (string)($over['custom_xml'] ?? '');
          echo htmlspecialchars(sanitize_for_ui($cx), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        ?></textarea>
      </div>

      <div style="margin-top:14px;text-align:right">
        <a class="btn secondary" href="extensions.php?system_id=<?= (int)$sysId ?>" style="text-decoration:none">Close</a>
        <button class="btn" name="save_settings" value="1" type="submit">Save</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<script>
// Client data
const MAC_LIST = <?= $mac_list_json ?: '[]' ?>;
const ASSIGNED_MACS = <?= $assigned_macs_json ?: '{}' ?>;
const FLASH_MSG = <?= json_encode($toast_msg) ?: '""' ?>;
const FLASH_TYPE = <?= json_encode($toast_type) ?: '"success"' ?>;
const SYSTEM_ID = <?= json_encode($sysId) ?>;
const TOAST_DURATION_MS = 5000;
const EXT_TO_NAME = <?= $ext_to_fullname_json ?: '{}' ?>;
<?php if (!empty($show_edit_ext)): ?>const BLF_CAP = <?= (int)$edit_cap ?>;<?php else: ?>const BLF_CAP = null;<?php endif; ?>

function showToast(message, type='success', duration=TOAST_DURATION_MS) {
  message = String(message || '')
    .replace(/\s+/g,' ')
    .replace(/\?+\s*$/,'')
    .trim();
  if (!message) return;
  document.querySelectorAll('.center-toast-overlay').forEach(el => el.remove());
  const overlay = document.createElement('div'); overlay.className = 'center-toast-overlay'; overlay.setAttribute('role','status');
  const box = document.createElement('div'); box.className = 'center-toast ' + (type==='warn' ? 'warn' : 'success');
  const txt = document.createElement('div'); txt.style.flex = '1'; txt.style.textAlign = 'center'; txt.textContent = message;
  const close = document.createElement('button'); close.className = 'close-btn'; close.innerHTML = '&times;'; close.title='Close';
  close.addEventListener('click', () => overlay.remove());
  box.appendChild(txt); box.appendChild(close); overlay.appendChild(box); document.body.appendChild(overlay);
  setTimeout(()=>{ overlay.remove(); }, duration);
}

function switchSiteGo(){
  const sel = document.getElementById('switch-site-select');
  const modal = document.getElementById('switch-site-modal');
  if (!sel || !sel.value) { if (modal) modal.style.display='none'; return; }
  if (String(sel.value) === String(<?= (int)$sysId ?>)) { if (modal) modal.style.display='none'; return; }
  window.location.href = 'extensions.php?system_id=' + encodeURIComponent(sel.value);
}

document.addEventListener('DOMContentLoaded', function(){
  try { if (FLASH_MSG) showToast(FLASH_MSG, FLASH_TYPE, TOAST_DURATION_MS); } catch(e){}

  // Tabs
  document.querySelectorAll('.tab').forEach(tab=>{
    tab.addEventListener('click', ()=>{
      const tgt = tab.getAttribute('data-tab');
      document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
      document.querySelectorAll('.tabpanel').forEach(p=>p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tgt)?.classList.add('active');
    });
  });

  // Generate Selected includes current MAC/model
  document.getElementById('generate-selected-btn')?.addEventListener('click', ()=> {
    const checked = Array.from(document.querySelectorAll('.sel-chk')).filter(c=>c.checked).map(c=>c.value);
    if (!checked.length){ showToast('No devices selected','warn'); return; }
    const f=document.createElement('form'); f.method='post'; f.style.display='none'; f.action = 'extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID);
    checked.forEach(ext=>{
      const sel=document.createElement('input'); sel.type='hidden'; sel.name='generate_selected[]'; sel.value=ext; f.appendChild(sel);
      const macInput = document.querySelector('input[name="assign['+ext+'][mac]"]');
      if (macInput) { const h=document.createElement('input'); h.type='hidden'; h.name='assign['+ext+'][mac]'; h.value=(macInput.value||''); f.appendChild(h); }
      const modelSel = document.querySelector('select[name="assign['+ext+'][model]"]');
      if (modelSel) { const h=document.createElement('input'); h.type='hidden'; h.name='assign['+ext+'][model]'; h.value=(modelSel.value||''); f.appendChild(h); }
    });
    document.body.appendChild(f); f.submit();
  });

  // BLF label/value auto-fill when selecting an Extension in Edit modal
  const blfList = document.getElementById('blf-list');
  if (blfList) {
    blfList.addEventListener('change', function(ev){
      const sel = ev.target.closest('select[name^="cfg_blf_ext"]');
      if (!sel) return;
      const ext = (sel.value || '').trim();
      const row = sel.closest('div');
      const labelInput = row?.querySelector('input[name^="cfg_blf_label"]');
      const valueInput = row?.querySelector('input[name^="cfg_blf_value"]');
      if (valueInput) valueInput.value = ext; // set extension value automatically
      if (labelInput) {
        let name = EXT_TO_NAME[ext] && String(EXT_TO_NAME[ext]).trim() !== '' ? EXT_TO_NAME[ext] : ext;
        labelInput.value = name || '';
      }
    });
  }

  attachMacCombos();
});

// Admin password UI controls
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

// Robust copy with fallback for HTTP/non-secure contexts
function copyHttpPass() {
  const real = document.getElementById('cfg_http_pass_real');
  const mask = document.getElementById('http_pass_mask');

  let secret = (real && real.value) ? real.value : '';
  if (!secret && mask && mask.type === 'text' && mask.value && mask.value !== '*********') {
    secret = mask.value;
  }
  if (!secret) { showToast('No password available to copy','warn'); return; }

  const canUseClipboardAPI =
    typeof navigator !== 'undefined' &&
    navigator &&
    'clipboard' in navigator &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === 'function' &&
    (window && (window.isSecureContext || location.hostname === 'localhost' || location.hostname === '127.0.0.1'));

  if (canUseClipboardAPI) {
    navigator.clipboard.writeText(secret)
      .then(() => showToast('Password copied','success'))
      .catch(() => fallbackCopy(secret));
  } else {
    fallbackCopy(secret);
  }

  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(ok ? 'Password copied' : 'Copy failed', ok ? 'success' : 'warn');
    } catch (e) {
      showToast('Copy failed','warn');
    }
  }
}

function currentBLFRowCount(){
  const list=document.getElementById('blf-list'); if (!list) return 0;
  return Array.from(list.querySelectorAll('select[name^="cfg_blf_type"]')).filter(s=> (s.value||'blf') !== 'none').length;
}
function addBLF(){
  const list=document.getElementById('blf-list'); if(!list) return;
  if (BLF_CAP !== null && currentBLFRowCount() >= BLF_CAP) { showToast('Reached maximum F-keys for this model ('+BLF_CAP+').','warn'); return; }
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
    <button type="button" class="btn ghost" onclick="this.closest('div').remove()">Remove</button>`;
  list.appendChild(div);
}

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
function confirmDelete(ext){
  if (!ext) return;
  if (!confirm('Delete generated provisioning file for extension ' + ext + ' ? This cannot be undone.')) return;
  const f=document.createElement('form'); f.method='post'; f.style.display='none'; f.action='extensions.php?system_id=' + encodeURIComponent(SYSTEM_ID);
  const i=document.createElement('input'); i.type='hidden'; i.name='delete_generated'; i.value = ext; f.appendChild(i);
  document.body.appendChild(f); f.submit();
}

/* MAC combo with model autofill */
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
        const m = (macList[i].mac || '').toString().replace(/[^A-Fa-f0-9]/g,'').toUpperCase();
        if (m === mac) return (macList[i].model || '').toString();
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
          item.dataset.value = mac; item.dataset.model = (it.model || '').toString();
          item.textContent = mac + (it.model ? ' ' + it.model : '');
          listEl.appendChild(item); any++;
        }
      });
      if (any === 0) { const empty = document.createElement('div'); empty.className = 'mac-combo-empty'; empty.textContent = 'No suggestions'; listEl.appendChild(empty); }
      const first = listEl.querySelector('.mac-combo-item'); if (first) first.classList.add('active');
    }
    function showList() { buildList(input.value || ''); listEl.style.display = 'block'; }
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
</script>
</body>
</html>