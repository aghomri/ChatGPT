<?php
// Debug toggle: add ?debug=1 to URL to enable on-page diagnostics and detailed logging
$DEBUG = isset($_GET['debug']) && $_GET['debug'] === '1';
ini_set('display_errors', $DEBUG ? '1' : '0');
error_reporting($DEBUG ? E_ALL : 0);

session_start();
$UI_BUILD = '2025-10-25-19: DECT menu SRAPS toggle + logo->home + SRAPS push semantics (Disabled = push) + remove search button + use MSeries profile';
header('X-UI-Build: '.$UI_BUILD);

ini_set('default_charset', 'UTF-8');
if (function_exists('mb_internal_encoding')) mb_internal_encoding('UTF-8');
if (function_exists('mb_http_output')) mb_http_output('UTF-8');
header('Content-Type: text/html; charset=UTF-8');

/* ========== Debug/logger helpers ========== */
$DBG_LOG = __DIR__ . '/../provision_ac_debug.log';
function dbg_write($line){
    global $DBG_LOG;
    @file_put_contents($DBG_LOG, date('c').' '.$line.PHP_EOL, FILE_APPEND);
}
function tail_file($filename, $lines = 200){
    if (!is_file($filename)) return '';
    $f = fopen($filename, 'rb'); if (!$f) return '';
    $buffer = ''; $chunk = 4096; $pos = -1; $linecount = 0;
    fseek($f, 0, SEEK_END); $filesize = ftell($f);
    while ($linecount < $lines && $filesize + $pos > 0) {
        $seek = max($filesize + $pos - $chunk, 0);
        $readlen = min($chunk, $filesize + $pos);
        fseek($f, $seek); $data = fread($f, $readlen);
        $buffer = $data . $buffer; $pos -= $chunk;
        $linecount = substr_count($buffer, "\n");
    }
    fclose($f);
    $parts = explode("\n", $buffer);
    return implode("\n", array_slice($parts, -$lines));
}

/* ========== General helpers ========== */
function clean_utf8($s) {
    if ($s === null) return '';
    if (!is_string($s)) $s = (string)$s;
    if (function_exists('mb_detect_encoding') && function_exists('mb_convert_encoding')) {
        $enc = @mb_detect_encoding($s, ['UTF-8','Windows-1252','ISO-8859-1'], true);
        if ($enc && $enc !== 'UTF-8') $s = @mb_convert_encoding($s, 'UTF-8', $enc);
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

/* Password generators */
function random_password($len = 16) {
    // general use (may include symbols) - not used for DECT http_pass anymore
    if ($len < 1) $len = 16;
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*()-_=+[]{}?,.:;~';
    $out = ''; $max = strlen($chars)-1;
    for ($i=0;$i<$len;$i++) $out .= $chars[random_int(0,$max)];
    return $out;
}
function random_password_safe($len = 20) {
    // safe for devices that reject symbols (A-Za-z0-9 only, no ambiguous O0Il)
    if ($len < 1) $len = 20;
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    $out=''; $max = strlen($chars)-1;
    for ($i=0;$i<$len;$i++) $out .= $chars[random_int(0,$max)];
    return $out;
}

/* Model helpers */
function dect_capacity(string $model): int {
    $m = strtoupper(trim($model));
    if ($m === 'M400') return 20;
    if ($m === 'M900') return 2000;
    return 20;
}

/* Normalizers */
function normalize_ipui(string $s): string {
    $s = trim($s);
    if ($s === '') return '0xFFFFFFFFFF';
    if (preg_match('/^0x[0-9A-Fa-f]{10}$/', $s)) return strtoupper($s);
    $hex = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $s));
    if (strlen($hex) === 10) return '0x'.$hex;
    return '0xFFFFFFFFFF';
}
function normalize_ac_code(string $s): string {
    $digits = preg_replace('/\D+/', '', (string)$s);
    return $digits ?? '';
}
function normalize_ac_code_4(string $s): string {
    $digits = preg_replace('/\D+/', '', (string)$s);
    $digits = substr($digits, 0, 4);
    if ($digits === '') $digits = '0000';
    if (strlen($digits) < 4) $digits = str_pad($digits, 4, '0', STR_PAD_LEFT);
    return $digits;
}
function current_base_url(): string {
    $scheme = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $scheme = explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'])[0];
    } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $scheme = 'https';
    }
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
    return $scheme.'://'.$host;
}

/* ========== Boot & data access ========== */
if (!file_exists(__DIR__ . '/db.php')) { dbg_write('db.php missing'); die("Missing db.php - cannot continue"); }
require_once __DIR__ . '/db.php';
if (empty($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$uid = (int)$_SESSION['user_id'];

try { $pdo = db(); } catch (Throwable $e) { dbg_write('db() error: '.$e->getMessage()); die("DB error"); }

/* Load system */
$sysId = isset($_REQUEST['system_id']) ? (int)$_REQUEST['system_id'] : 0;
$st = $pdo->prepare('SELECT * FROM systems WHERE id=? AND user_id=?');
$st->execute([$sysId, $uid]);
$sys = $st->fetch(PDO::FETCH_ASSOC);
if (!$sys) { http_response_code(404); die('<pre>Invalid or unauthorized system ID.</pre>'); }
$sys['label'] = isset($sys['label']) ? sanitize_for_ui((string)$sys['label']) : 'Provisioning';

/* Sites list */
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
} catch (Throwable $e) { dbg_write('Switch Site load error: '.$e->getMessage()); }

/* Assets/paths */
$local_logo_path = 'assets/logos/snom_logo_gray_60.svg';
$logo_src = file_exists(__DIR__.'/'.$local_logo_path)
    ? $local_logo_path
    : 'data:image/svg+xml;utf8,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" width="120" height="88"><rect rx="8" width="120" height="88" fill="#eef6ff"/><text x="50%" y="50%" font-size="20" fill="#0b2548" text-anchor="middle" dominant-baseline="central">snom</text></svg>');

$PROVISION_DIR = rtrim(__DIR__, '/').'/provisioning_files';
if (!is_dir($PROVISION_DIR)) { @mkdir($PROVISION_DIR, 0777, true); @chmod($PROVISION_DIR, 0777); }
$PUBLIC_PROVISION_PATH = '/' . trim(str_replace(rtrim($_SERVER['DOCUMENT_ROOT'],'/'), '', $PROVISION_DIR), '/');
if ($PUBLIC_PROVISION_PATH === '') $PUBLIC_PROVISION_PATH = '/provisioning_files';
$PROVISION_URL = rtrim(current_base_url(), '/').$PUBLIC_PROVISION_PATH.'/';

/* Session state */
if (!isset($_SESSION['wiz'])) $_SESSION['wiz'] = [];
if (!isset($_SESSION['wiz'][$sysId])) $_SESSION['wiz'][$sysId] = [
    'exts' => [],
    'dect' => [],
    'flash' => null,
    'global' => [] // ensure global bucket exists for SRAPS toggle
];
$wiz = &$_SESSION['wiz'][$sysId];

/* ===== SRAPS helpers (local bridge to sraps.php) =====
   IMPORTANT (per user request) — inverted semantics on DECT page:
   - Showing "SRAPS Enabled" means DO NOT push devices to SRAPS.
   - Showing "SRAPS Disabled" means PUSH devices to SRAPS on Generate and RELEASE on Delete.
*/
function sraps_local_url(): string {
    $base = rtrim(current_base_url(), '/');
    $dir  = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    return $base . ($dir ? $dir : '') . '/sraps.php';
}
function http_json_local_ext(string $method, string $url, ?array $body=null, int $timeout=25): array {
    $ch = curl_init($url);
    $headers = ['Accept: application/json'];
    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADER => false,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_USERAGENT => 'DECT-SRAPS-Bridge/1.0',
    ]);
    $raw = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    $data = null;
    if (is_string($raw) && $raw !== '') {
        $maybe = json_decode($raw, true);
        if (json_last_error() === JSON_ERROR_NONE) $data = $maybe;
    }
    if ($errno !== 0) return ['ok'=>false,'code'=>0,'data'=>null,'error'=>"cURL: {$err}"];
    if ($code < 200 || $code >= 300) return ['ok'=>false,'code'=>$code,'data'=>$data,'error'=>is_string($raw)?$raw:'HTTP '.$code];
    return ['ok'=>true,'code'=>$code,'data'=>$data,'error'=>null];
}
function sraps_find_profile_uuid(string $srapsUrl, string $profileName): ?string {
    $resp = http_json_local_ext('GET', $srapsUrl.'?action=profiles&page_size=1000', null, 30);
    if (!$resp['ok'] || !is_array($resp['data'])) {
        dbg_write('SRAPS profiles error: '.($resp['error'] ?? 'unknown'));
        return null;
    }
    $want = strtolower($profileName);
    foreach ($resp['data'] as $p) {
        $name = strtolower((string)($p['name'] ?? ''));
        if ($name === $want || strpos($name, $want) !== false) {
            $uuid = (string)($p['uuid'] ?? ($p['uuid_v4'] ?? ''));
            if ($uuid !== '') return $uuid;
        }
    }
    return null;
}
function sraps_assign_profile_by_name(string $macUpper, string $profileName, string $endpointName=''): array {
    $path = __DIR__.'/sraps.php';
    if (!is_file($path)) {
        $msg = 'SRAPS: sraps.php not found; skipped.';
        dbg_write($msg);
        return ['ok'=>false,'msg'=>$msg];
    }
    $srapsUrl = sraps_local_url();
    http_json_local_ext('GET', $srapsUrl.'?action=status', null, 10);

    $uuid = sraps_find_profile_uuid($srapsUrl, $profileName);
    if ($uuid === null) {
        $msg = "SRAPS: profile '{$profileName}' not found.";
        dbg_write($msg);
        return ['ok'=>false,'msg'=>$msg];
    }

    $macLower = strtolower(preg_replace('/[^0-9A-Fa-f]/','', $macUpper));
    $payload = ['profileUuid'=>$uuid, 'mac'=>$macLower, 'autoprovisioning_enabled'=>true];
    if ($endpointName !== '') $payload['name'] = $endpointName;

    $res = http_json_local_ext('POST', $srapsUrl.'?action=assign', $payload, 30);
    if ($res['ok']) {
        dbg_write("SRAPS assign ok: {$macLower} -> {$profileName}");
        return ['ok'=>true,'msg'=>"SRAPS: assigned to {$profileName}"];
    }
    $reason = '';
    if (is_array($res['data'])) {
        if (isset($res['data']['message'])) $reason = is_string($res['data']['message']) ? $res['data']['message'] : json_encode($res['data']['message']);
        elseif (isset($res['data']['error'])) $reason = is_string($res['data']['error']) ? $res['data']['error'] : json_encode($res['data']['error']);
    }
    if ($reason === '') $reason = (string)($res['error'] ?? '');
    $msg = 'SRAPS assign failed' . ($res['code'] ? " (HTTP {$res['code']})" : '') . ($reason ? ": {$reason}" : '');
    dbg_write('SRAPS assign failed: '.$msg);
    return ['ok'=>false,'msg'=>$msg];
}
function sraps_release_endpoint(string $macUpper): array {
    $path = __DIR__.'/sraps.php';
    if (!is_file($path)) {
        $msg = 'SRAPS: sraps.php not found; release skipped.';
        dbg_write($msg);
        return ['ok'=>false,'msg'=>$msg];
    }
    $srapsUrl = sraps_local_url();
    http_json_local_ext('GET', $srapsUrl.'?action=status', null, 10);

    $macLower = strtolower(preg_replace('/[^0-9A-Fa-f]/','', $macUpper));
    $res = http_json_local_ext('POST', $srapsUrl.'?action=release', ['mac'=>$macLower], 30);
    if ($res['ok']) {
        dbg_write("SRAPS release ok: {$macLower}");
        return ['ok'=>true,'msg'=>'SRAPS: endpoint released'];
    }
    $reason = '';
    if (is_array($res['data'])) {
        if (isset($res['data']['message'])) $reason = is_string($res['data']['message']) ? $res['data']['message'] : json_encode($res['data']['message']);
        elseif (isset($res['data']['error'])) $reason = is_string($res['data']['error']) ? $res['data']['error'] : json_encode($res['data']['error']);
    }
    if ($reason === '') $reason = (string)($res['error'] ?? '');
    $msg = 'SRAPS release failed' . ($res['code'] ? " (HTTP {$res['code']})" : '') . ($reason ? ": {$reason}" : '');
    dbg_write('SRAPS release failed: '.$msg);
    return ['ok'=>false,'msg'=>$msg];
}

/* UCM API (extensions dropdown only) */
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

/* Fetch UCM users (for Extension selects) */
$msg = '';
$exts = $wiz['exts'] ?? [];
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
        }
    }
}

/* Quick maps */
$fullname_by_ext = []; $secret_by_ext = []; $authid_by_ext = [];
foreach ($exts as $ee) {
    $x = (string)($ee['extension'] ?? '');
    $fullname_by_ext[$x] = sanitize_for_ui($ee['fullname'] ?? '');
    $secret_by_ext[$x]   = (string)($ee['secret'] ?? '');
    $authid_by_ext[$x]   = (string)($ee['authid'] ?? $x);
}

/* Ensure DECT bucket exists */
if (!isset($wiz['dect']) || !is_array($wiz['dect'])) $wiz['dect'] = [];

/* PP Types */
$PP_TYPES = ['M25','M65','M70','M80','M85','M90'];

/* Allowed codecs (Snom tokens) */
$CODECS = ['pcma' => 'G.711 A-law (pcma)', 'pcmu' => 'G.711 u-law (pcmu)', 'g722' => 'G.722', 'g729' => 'G.729', 'g726' => 'G.726'];

/* Tone Scheme codes -> display country names (value=code, label=country) */
$TONE_CODES = [
    'AUS' => 'Australia',
    'AUT' => 'Austria',
    'CHN' => 'China',
    'DNK' => 'Denmark',
    'FRA' => 'France',
    'GER' => 'Germany',
    'GBR' => 'United Kingdom',
    'IND' => 'India',
    'ITA' => 'Italy',
    'JPN' => 'Japan',
    'MEX' => 'Mexico',
    'NLD' => 'Netherlands',
    'NOR' => 'Norway',
    'NZL' => 'New Zealand',
    'ESP' => 'Spain',
    'SWE' => 'Sweden',
    'SWI' => 'Switzerland',
    'USA' => 'United States',
];

/* Language/Web Language options: display item (label), save option value */
$LANG_OPTIONS = [
    ['value'=>'English',   'label'=>'English'],
    ['value'=>'Dansk',     'label'=>'Dansk'],
    ['value'=>'Italiano',  'label'=>'Italiano'],
    ['value'=>'Türkce',    'label'=>'Türkce'],
    ['value'=>'Deutsch',   'label'=>'Deutsch'],
    ['value'=>'Dutch',     'label'=>'Dutch'],
    ['value'=>'Português', 'label'=>'Português'],
    ['value'=>'Slovenian', 'label'=>'Slovenian'],
    ['value'=>'Francais',  'label'=>'Francais'],
    ['value'=>'Español',   'label'=>'Español'],
    ['value'=>'Russian',   'label'=>'Russian'],
    ['value'=>'Polski',    'label'=>'Polski'],
];
$LANG_ALLOWED_VALUES = array_column($LANG_OPTIONS, 'value');

/* Timezone code => label mapping (value is code, label is human-friendly) */
$TZ_LABELS = [
  'USA-10'=>'USA West -10','USA-9'=>'USA -9','CAN-8'=>'Canada -8','MEX-8'=>'Mexico -8','USA-8'=>'USA -8',
  'CAN-7'=>'Canada -7','MEX-7'=>'Mexico -7','USA2-7'=>'USA -7 (DST)','USA-7'=>'USA -7','CAM-6'=>'Central America -6',
  'CAN-6'=>'Canada -6','CAN2-6'=>'Canada -6 (DST)','CHL-6'=>'Chile -6','MEX-6'=>'Mexico -6','USA-6'=>'USA -6',
  'BHS-5'=>'Bahamas -5','CAN-5'=>'Canada -5','CUB-5'=>'Cuba -5','USA-5'=>'USA -5','VEN-4.5'=>'Venezuela -4.5',
  'CAN-4'=>'Canada -4','CHL-4'=>'Chile -4','PRY-4'=>'Paraguay -4','BMU-4'=>'Bermuda -4','FLK-4'=>'Falkland -4',
  'TTB-4'=>'Trinidad Tobago -4','CAN-3.5'=>'Canada -3.5','GRL-3'=>'Greenland -3','ARG-3'=>'Argentina -3','BRA2-3'=>'Brazil -3 East',
  'BRA1-3'=>'Brazil -3 West','BRA-2'=>'Brazil -2','PRT-1'=>'Portugal -1','FRO-0'=>'Faroe 0','IRL-0'=>'Ireland 0',
  'PRT-0'=>'Portugal 0','ESP-0'=>'Spain 0','GBR-0'=>'UK 0','ALB+1'=>'Albania +1','AUT+1'=>'Austria +1',
  'BEL+1'=>'Belgium +1','CAI+1'=>'Cairo +1','CHA+1'=>'Chad +1','HRV+1'=>'Croatia +1','CZE+1'=>'Czech +1',
  'DNK+1'=>'Denmark +1','FRA+1'=>'France +1','GER+1'=>'Germany +1','HUN+1'=>'Hungary +1','ITA+1'=>'Italy +1',
  'LUX+1'=>'Luxembourg +1','MAK+1'=>'Macedonia +1','NLD+1'=>'Netherlands +1','NAM+1'=>'Namibia +1','NOR+1'=>'Norway +1',
  'POL+1'=>'Poland +1','SVK+1'=>'Slovakia +1','ESP+1'=>'Spain +1','SWE+1'=>'Sweden +1','CHE+1'=>'Switzerland +1',
  'GIB+1'=>'Gibraltar +1','YUG+1'=>'Yugoslavia +1','WAT+1'=>'West Africa +1','BLR+2'=>'Belarus +2','BGR+2'=>'Bulgaria +2',
  'CYP+2'=>'Cyprus +2','CAT+2'=>'Catalonia +2','EGY+2'=>'Egypt +2','EST+2'=>'Estonia +2','FIN+2'=>'Finland +2',
  'GAZ+2'=>'Gaza +2','GRC+2'=>'Greece +2','ISR+2'=>'Israel +2','JOR+2'=>'Jordan +2','LVA+2'=>'Latvia +2',
  'LBN+2'=>'Lebanon +2','MDA+2'=>'Moldova +2','RUS+2'=>'Russia +2','ROU+2'=>'Romania +2','SYR+2'=>'Syria +2',
  'TUR+2'=>'Türkiye +2','UKR+2'=>'Ukraine +2','EAT+3'=>'East Africa +3','IRQ+3'=>'Iraq +3','RUS+3'=>'Russia +3',
  'IRN+3.5'=>'Iran +3.5','ARM+4'=>'Armenia +4','AZE+4'=>'Azerbaijan +4','GEO+4'=>'Georgia +4','KAZ+4'=>'Kazakhstan +4',
  'RUS+4'=>'Russia +4','KAZ+5'=>'Kazakhstan +5','KGZ+5'=>'Kyrgyzstan +5','PAK+5'=>'Pakistan +5','RUS+5'=>'Russia +5',
  'IND+5.5'=>'India +5.5','KAZ+6'=>'Kazakhstan +6','RUS+6'=>'Russia +6','RUS+7'=>'Russia +7','THA+7'=>'Thailand +7',
  'CHN+7'=>'China +7','SGP+8'=>'Singapore +8','KOR+8'=>'Korea +8','AUS+8'=>'Australia +8','JPN+9'=>'Japan +9',
  'AUS+9.5'=>'Australia +9.5','AUS2+9.5'=>'Australia +9.5 (SA)','AUS+10'=>'Australia +10','AUS2+10'=>'Australia +10 (QLD)',
  'AUS3+10'=>'Australia +10 (ACT)','RUS+10'=>'Russia +10','AUS+10.5'=>'Australia +10.5','NCL+11'=>'New Caledonia +11',
  'NZL+12'=>'New Zealand +12','RUS+12'=>'Russia +12','NZL+12.75'=>'New Zealand +12.75','TON+13'=>'Tonga +13'
];

/* ========== Generator ========== */
function write_dect_profile(string $dir, string $mac, array $d, array $extMaps): array {
    global $PP_TYPES, $CODECS;
    $mac = normalize_mac($mac);
    if ($mac === '' || strlen($mac) !== 12) return [false, 'Invalid MAC'];
    if (!is_dir($dir)) { if (!@mkdir($dir, 0777, true)) return [false, "Cannot create directory"]; @chmod($dir, 0777); }
    if (!is_writable($dir)) return [false, "Directory not writable"];

    [$fullMap,$authMap] = $extMaps;

    $host      = (string)($d['host'] ?? '');
    $outbound  = (string)($d['outbound'] ?? '');
    $alias     = (string)($d['alias'] ?? '');

    $transport = strtolower(trim((string)($d['transport'] ?? 'udp')));
    if (!in_array($transport, ['udp','tcp','tls','auto'], true)) $transport = 'udp';

    $model     = strtoupper((string)($d['model'] ?? ''));
    $multicell = (string)($d['multicell'] ?? 'off');

    // Contact / phonebook
    $phonebook_location = (string)($d['phonebook_location'] ?? '');
    $phonebook_filename = (string)($d['phonebook_filename'] ?? 'phonebook.xml');

    // Localisation / time & tone
    $ntp_server         = (string)($d['ntp_server'] ?? '');
    $ntp_refresh_timer  = (string)($d['ntp_refresh_timer'] ?? '3600');
    $tone_scheme        = (string)($d['tone_scheme'] ?? '');
    $timezone           = (string)($d['timezone'] ?? '');
    $language           = (string)($d['language'] ?? '');
    $web_language       = (string)($d['web_language'] ?? '');

    // Security
    $http_user = (string)($d['http_user'] ?? 'admin');
    $http_pass = (string)($d['http_pass'] ?? '');
    $base_ac_code = normalize_ac_code_4((string)($d['ac_code'] ?? '0000'));

    // Audio
    $codec1 = (string)($d['codec1'] ?? 'pcma');
    $codec2 = (string)($d['codec2'] ?? 'pcmu');
    $codec3 = (string)($d['codec3'] ?? 'g722');
    $codec4 = (string)($d['codec4'] ?? 'g729');
    $codec_size = (string)($d['codec_size'] ?? '20');
    $user_srtp = (string)($d['user_srtp'] ?? 'disabled');
    $srv_srtp_auth = (string)($d['srv_srtp_auth'] ?? 'off');
    $user_dtmf_info = (string)($d['user_dtmf_info'] ?? 'off');
    $user_full_sdp_answer = (string)($d['user_full_sdp_answer'] ?? 'on');

    // Firmware (base URL default HTTPS)
    $firmware_url = (string)($d['firmware_url'] ?? 'https://dect.snom.com');
    $fp_sw        = (string)($d['fp_sw'] ?? '');
    $fp_branch    = (string)($d['fp_branch'] ?? '');
    $PP_TYPES = ['M25','M65','M70','M80','M85','M90'];
    $pp_sw = []; $pp_branch = [];
    foreach ($PP_TYPES as $t) {
        $pp_sw[$t]     = (string)($d['pp_sw_'.$t] ?? '');
        $pp_branch[$t] = (string)($d['pp_branch_'.$t] ?? '');
    }

    $vm_number = (string)($d['vm_number'] ?? '');

    $accounts = $d['accounts'] ?? [];
    $cap = dect_capacity($model);
    $accounts = array_values(array_slice($accounts, 0, $cap));

    $custom_xml = isset($d['custom_xml']) ? (string)$d['custom_xml'] : '';

    // Build codec list (validate tokens)
    $allowed = array_keys($CODECS);
    $codec_tokens = [];
    foreach ([$codec1,$codec2,$codec3,$codec4] as $cc) {
        $cc = strtolower(trim($cc));
        if (in_array($cc, $allowed, true)) $codec_tokens[] = $cc;
    }
    if (empty($codec_tokens)) $codec_tokens = ['pcma','pcmu','g722','g729'];
    $codec_priority_list = implode(', ', $codec_tokens);

    $xml = [];
    $xml[] = '<?xml version="1.0" encoding="UTF-8"?>';
    $xml[] = '<settings>';

    // Global
    $xml[] = '  <global>';
    if ($phonebook_location !== '') $xml[] = '    <phonebook_location>'.$phonebook_location.'</phonebook_location>';
    if ($phonebook_filename !== '') $xml[] = '    <phonebook_filename>'.htmlspecialchars($phonebook_filename, ENT_QUOTES, 'UTF-8').'</phonebook_filename>';
    if ($ntp_server !== '')         $xml[] = '    <ntp_server>'.$ntp_server.'</ntp_server>';
    if ($ntp_refresh_timer !== '')  $xml[] = '    <ntp_refresh_timer>'.htmlspecialchars($ntp_refresh_timer, ENT_QUOTES, 'UTF-8').'</ntp_refresh_timer>';
    if ($tone_scheme !== '')        $xml[] = '    <tone_scheme>'.htmlspecialchars($tone_scheme, ENT_QUOTES, 'UTF-8').'</tone_scheme>';
    if ($timezone !== '')           $xml[] = '    <timezone>'.htmlspecialchars($timezone, ENT_QUOTES, 'UTF-8').'</timezone>';
    if ($language !== '')           $xml[] = '    <language>'.htmlspecialchars($language, ENT_QUOTES, 'UTF-8').'</language>';
    if ($web_language !== '')       $xml[] = '    <web_language>'.htmlspecialchars($web_language, ENT_QUOTES, 'UTF-8').'</web_language>';
    if ($http_user !== '')          $xml[] = '    <http_user>'.htmlspecialchars($http_user, ENT_QUOTES, 'UTF-8').'</http_user>';
    if ($http_pass !== '')          $xml[] = '    <http_pass>'.htmlspecialchars($http_pass, ENT_QUOTES, 'UTF-8').'</http_pass>';
    if ($base_ac_code !== '')       $xml[] = '    <ac_code>'.htmlspecialchars($base_ac_code, ENT_QUOTES, 'UTF-8').'</ac_code>';
    $xml[] = '    <auto_dect_register>on</auto_dect_register>';
    $xml[] = '  </global>';

    // Server (idx=1)
    $xml[] = '  <server>';
    if ($alias !== '')    $xml[] = '    <srv_sip_server_alias idx="1">'.htmlspecialchars($alias, ENT_QUOTES, 'UTF-8').'</srv_sip_server_alias>';
    if ($host !== '')     $xml[] = '    <user_host idx="1">'.htmlspecialchars($host, ENT_QUOTES, 'UTF-8').'</user_host>';
    if ($outbound !== '') $xml[] = '    <user_outbound idx="1">'.htmlspecialchars($outbound, ENT_QUOTES, 'UTF-8').'</user_outbound>';
    $xml[] = '    <srv_sip_transport idx="1">'.htmlspecialchars($transport, ENT_QUOTES, 'UTF-8').'</srv_sip_transport>';
    $xml[] = '    <codec_priority_list idx="1">'.htmlspecialchars($codec_priority_list, ENT_QUOTES, 'UTF-8').'</codec_priority_list>';
    $xml[] = '    <codec_size idx="1">'.htmlspecialchars($codec_size, ENT_QUOTES, 'UTF-8').'</codec_size>';
    $xml[] = '    <user_srtp idx="1">'.htmlspecialchars($user_srtp, ENT_QUOTES, 'UTF-8').'</user_srtp>';
    $xml[] = '    <srv_srtp_auth idx="1">'.htmlspecialchars($srv_srtp_auth, ENT_QUOTES, 'UTF-8').'</srv_srtp_auth>';
    $xml[] = '    <user_dtmf_info idx="1">'.htmlspecialchars($user_dtmf_info, ENT_QUOTES, 'UTF-8').'</user_dtmf_info>';
    $xml[] = '    <user_full_sdp_answer idx="1">'.htmlspecialchars($user_full_sdp_answer, ENT_QUOTES, 'UTF-8').'</user_full_sdp_answer>';
    $xml[] = '  </server>';

    // Extension (accounts)
    $xml[] = '  <extension>';
    $idx = 1;
    foreach ($accounts as $a) {
        $ext = trim((string)($a['extension'] ?? ''));
        if ($ext === '') { $idx++; continue; }

        $authid   = trim((string)($authMap[$ext] ?? '')) ?: $ext;
        $fullname = (string)($fullMap[$ext] ?? ($a['user_realname'] ?? ''));
        $secret   = (string)($a['user_pass'] ?? '');

        $ipui     = normalize_ipui((string)($a['ipui'] ?? ''));
        $ac       = normalize_ac_code((string)($a['ac_code'] ?? ''));

        $xml[] = '    <auto_answer_mode idx="'.(int)$idx.'">disabled</auto_answer_mode>';
        if ($ac !== '') $xml[] = '    <subscr_dect_ac_code idx="'.(int)$idx.'">'.$ac.'</subscr_dect_ac_code>';
        $xml[] = '    <subscr_dect_ipui idx="'.(int)$idx.'">'.$ipui.'</subscr_dect_ipui>';
        $xml[] = '    <push_to_talk idx="'.(int)$idx.'">off</push_to_talk>';
        $xml[] = '    <subscr_sip_hs_idx idx="'.(int)$idx.'">'.(int)$idx.'</subscr_sip_hs_idx>';
        $xml[] = '    <subscr_sip_line_name idx="'.(int)$idx.'">'.htmlspecialchars($ext, ENT_QUOTES, 'UTF-8').'</subscr_sip_line_name>';

        $xml[] = '    <user_pname idx="'.(int)$idx.'">'.htmlspecialchars($authid, ENT_QUOTES, 'UTF-8').'</user_pname>';
        if ($secret !== '') $xml[] = '    <user_pass idx="'.(int)$idx.'">'.htmlspecialchars($secret, ENT_QUOTES, 'UTF-8').'</user_pass>';
        $xml[] = '    <dfks idx="'.(int)$idx.'">off</dfks>';
        $xml[] = '    <user_shared_line idx="'.(int)$idx.'">off</user_shared_line>';
        $xml[] = '    <call_waiting idx="'.(int)$idx.'">on</call_waiting>';
        $xml[] = '    <user_active idx="'.(int)$idx.'">on</user_active>';
        $xml[] = '    <fwd_busy_enabled idx="'.(int)$idx.'">off</fwd_busy_enabled>';
        $xml[] = '    <fwd_time_enabled idx="'.(int)$idx.'">off</fwd_time_enabled>';
        $xml[] = '    <fwd_all_enabled idx="'.(int)$idx.'">off</fwd_all_enabled>';
        $xml[] = '    <fwd_busy_target idx="'.(int)$idx.'"></fwd_busy_target>';
        $xml[] = '    <fwd_time_target idx="'.(int)$idx.'"></fwd_time_target>';
        $xml[] = '    <fwd_all_target idx="'.(int)$idx.'"></fwd_all_target>';
        $xml[] = '    <fwd_time_secs idx="'.(int)$idx.'">20</fwd_time_secs>';
        $xml[] = '    <subscr_sip_ua_data_server_id idx="'.(int)$idx.'">1</subscr_sip_ua_data_server_id>';
        $xml[] = '    <user_name idx="'.(int)$idx.'">'.htmlspecialchars($ext, ENT_QUOTES, 'UTF-8').'</user_name>';
        $xml[] = '    <user_mailbox idx="'.(int)$idx.'"></user_mailbox>';
        $xml[] = '    <user_mailnumber idx="'.(int)$idx.'">'.htmlspecialchars($vm_number, ENT_QUOTES, 'UTF-8').'</user_mailnumber>';
        $xml[] = '    <subscr_sip_ua_use_base idx="'.(int)$idx.'">255</subscr_sip_ua_use_base>';
        $xml[] = '    <subscr_ua_data_bw_blf_reslist_uri idx="'.(int)$idx.'"></subscr_ua_data_bw_blf_reslist_uri>';
        $xml[] = '    <user_shared_line_mapping idx="'.(int)$idx.'">65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535</user_shared_line_mapping>';
        $xml[] = '    <user_realname idx="'.(int)$idx.'">'.htmlspecialchars($fullname, ENT_QUOTES, 'UTF-8').'</user_realname>';
        $xml[] = '    <subscr_ua_data_emergency_line idx="'.(int)$idx.'">65535</subscr_ua_data_emergency_line>';
        $xml[] = '    <subscr_ua_data_emergency_number idx="'.(int)$idx.'"></subscr_ua_data_emergency_number>';
        $xml[] = '    <subscr_ua_data_emergency_profiles idx="'.(int)$idx.'">00000000</subscr_ua_data_emergency_profiles>';
        $xml[] = '    <xsi_auth_user idx="'.(int)$idx.'"></xsi_auth_user>';
        $xml[] = '    <xsi_auth_pass idx="'.(int)$idx.'">**********</xsi_auth_pass>';

        $idx++;
    }
    $xml[] = '  </extension>';

    // Base settings: Multi-Cell
    $xml[] = '  <multicell>';
    $xml[] = '    <network_sync_enable>'.($multicell === 'on' ? 'on' : 'off').'</network_sync_enable>';
    $xml[] = '  </multicell>';

    // Firmware settings
    $xml[] = '  <firmware-settings>';
    $xml[] = '    <firmware>'.htmlspecialchars($firmware_url, ENT_QUOTES, 'UTF-8').'</firmware>';
    if ($fp_sw !== '')     $xml[] = '    <fp_fwu_sw_version>'.htmlspecialchars($fp_sw, ENT_QUOTES, 'UTF-8').'</fp_fwu_sw_version>';
    if ($fp_branch !== '') $xml[] = '    <fp_fwu_branch_version>'.htmlspecialchars($fp_branch, ENT_QUOTES, 'UTF-8').'</fp_fwu_branch_version>';
    foreach ($PP_TYPES as $t) {
        if ($pp_sw[$t] !== '')     $xml[] = '    <pp_fwu_sw_version type="'.htmlspecialchars($t, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($pp_sw[$t], ENT_QUOTES, 'UTF-8').'</pp_fwu_sw_version>';
        if ($pp_branch[$t] !== '') $xml[] = '    <pp_fwu_branch_version type="'.htmlspecialchars($t, ENT_QUOTES, 'UTF-8').'">'.htmlspecialchars($pp_branch[$t], ENT_QUOTES, 'UTF-8').'</pp_fwu_branch_version>';
    }
    $xml[] = '  </firmware-settings>';

    // Custom XML
    if (trim($custom_xml) !== '') {
        $xml[] = trim($custom_xml);
    }

    $xml[] = '</settings>';
    $contents = implode("\n", $xml) . "\n";

    $file = rtrim($dir,'/').'/dect_'.$mac.'.xml';
    $ok = @file_put_contents($file, $contents);
    if ($ok === false) return [false, 'Write failed'];
    @chmod($file, 0666);
    return [true, $file];
}

/* ========== Actions ========== */
$show_add_dect_modal = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['open_add_dect'])) { $show_add_dect_modal = true; }
if (isset($_GET['add']) && $_GET['add'] === '1') { $show_add_dect_modal = true; }

/* SRAPS toggle button (system-wide state kept in wiz.global.sraps_enable)
   NOTE: On this DECT page, SRAPS Enabled means: DO NOT PUSH to SRAPS.
         SRAPS Disabled means: PUSH/RELEASE via SRAPS (profile: MSeries).
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_sraps'])) {
    $cur = ($wiz['global']['sraps_enable'] ?? 'off') === 'on';
    $wiz['global']['sraps_enable'] = $cur ? 'off' : 'on';
    $stateText = ($wiz['global']['sraps_enable'] === 'on') ? 'SRAPS Enabled (no push to SRAPS)' : 'SRAPS Disabled (push to SRAPS)';
    $wiz['flash'] = ['msg' => $stateText, 'type' => 'success'];
    header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_dect'])) {
    $mac = normalize_mac((string)$_POST['dect_mac']);
    $model = strtoupper(trim((string)($_POST['dect_model'] ?? '')));
    $label = sanitize_for_ui((string)($_POST['dect_label'] ?? ''));
    if (!is_valid_mac($mac)) {
        $wiz['flash'] = ['msg'=>'Invalid MAC. Use 12 hex chars (0-9,A-F).','type'=>'warn'];
    } elseif (!in_array($model, ['M400','M900'], true)) {
        $wiz['flash'] = ['msg'=>'Invalid model. Choose M400 or M900.','type'=>'warn'];
    } elseif (isset($wiz['dect'][$mac])) {
        $wiz['flash'] = ['msg'=>'This DECT system already exists.','type'=>'warn'];
    } else {
        // Build empty defaults for PP software versions (no prefill)
        $ppDefaults = [];
        foreach ($PP_TYPES as $t) { $ppDefaults['pp_sw_'.$t]=''; $ppDefaults['pp_branch_'.$t]=''; }
        $wiz['dect'][$mac] = array_merge([
            'label' => $label,
            'model' => $model,
            'host' => '',
            'outbound' => '',
            'alias' => '',
            'transport' => 'udp',
            'multicell' => 'off',
            // Contact
            'phonebook_location' => $PROVISION_URL,
            'phonebook_filename' => 'phonebook.xml',
            // Localisation defaults
            'ntp_server' => 'pool.ntp.org',
            'ntp_refresh_timer' => '3600',
            'tone_scheme' => '',
            'timezone' => '',
            'language' => '',
            'web_language' => '',
            // Firmware
            'firmware_url' => 'https://dect.snom.com',
            'fp_sw' => '',
            'fp_branch' => '',
            // Audio
            'codec1' => 'pcma', 'codec2' => 'pcmu', 'codec3' => 'g722', 'codec4' => 'g729',
            'codec_size' => '20',
            'user_srtp' => 'disabled',
            'srv_srtp_auth' => 'off',
            'user_dtmf_info' => 'off',
            'user_full_sdp_answer' => 'on',
            // Security
            'http_user' => 'admin',
            'http_pass' => random_password_safe(20),
            'ac_code'   => '0000',
            // Accounts, VM and custom XML
            'vm_number' => '',
            'custom_xml' => '',
            'accounts' => [],
            'generated' => null
        ], $ppDefaults);
        $wiz['flash'] = ['msg'=>'DECT system added.','type'=>'success'];
    }
    header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_dect']) && isset($_POST['mac'])) {
    $mac = normalize_mac((string)$_POST['mac']);
    if (!isset($wiz['dect'][$mac])) { $wiz['flash']=['msg'=>'DECT system not found.','type'=>'warn']; header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit; }
    $cap = dect_capacity($wiz['dect'][$mac]['model'] ?? '');
    // Label
    $wiz['dect'][$mac]['label']       = sanitize_for_ui((string)($_POST['label'] ?? ($wiz['dect'][$mac]['label'] ?? '')));
    // SIP server
    $wiz['dect'][$mac]['host']        = sanitize_for_ui((string)($_POST['host'] ?? ''));
    $wiz['dect'][$mac]['outbound']    = sanitize_for_ui((string)($_POST['outbound'] ?? ''));
    $wiz['dect'][$mac]['alias']       = sanitize_for_ui((string)($_POST['alias'] ?? ''));
    $t = strtolower(trim((string)($_POST['transport'] ?? ($wiz['dect'][$mac]['transport'] ?? 'udp'))));
    $wiz['dect'][$mac]['transport']   = in_array($t, ['udp','tcp','tls','auto'], true) ? $t : 'udp';
    // Base settings
    $wiz['dect'][$mac]['multicell']   = (isset($_POST['multicell']) && $_POST['multicell'] === 'on') ? 'on' : 'off';
    // Contact
    $wiz['dect'][$mac]['phonebook_location'] = trim((string)($_POST['phonebook_location'] ?? $wiz['dect'][$mac]['phonebook_location'] ?? $PROVISION_URL));
    $wiz['dect'][$mac]['phonebook_filename'] = sanitize_for_ui((string)($_POST['phonebook_filename'] ?? $wiz['dect'][$mac]['phonebook_filename'] ?? 'phonebook.xml'));
    // Localisation
    $wiz['dect'][$mac]['ntp_server']         = trim((string)($_POST['ntp_server'] ?? $wiz['dect'][$mac]['ntp_server'] ?? 'pool.ntp.org'));
    $wiz['dect'][$mac]['ntp_refresh_timer']  = preg_replace('/\D+/', '', (string)($_POST['ntp_refresh_timer'] ?? $wiz['dect'][$mac]['ntp_refresh_timer'] ?? '3600')) ?: '3600';

    // Tone Scheme
    $posted_tone = strtoupper(trim((string)($_POST['tone_scheme'] ?? '')));
    $wiz['dect'][$mac]['tone_scheme'] = array_key_exists($posted_tone, $TONE_CODES) ? $posted_tone : '';

    // Timezone (keep as-is)
    $wiz['dect'][$mac]['timezone'] = sanitize_for_ui((string)($_POST['timezone'] ?? $wiz['dect'][$mac]['timezone'] ?? ''));

    // Language and Web UI Language
    $posted_lang = (string)($_POST['language'] ?? '');
    $posted_web  = (string)($_POST['web_language'] ?? '');
    $wiz['dect'][$mac]['language']     = in_array($posted_lang, $LANG_ALLOWED_VALUES, true) ? $posted_lang : 'English';
    $wiz['dect'][$mac]['web_language'] = in_array($posted_web,  $LANG_ALLOWED_VALUES, true) ? $posted_web  : 'English';

    // Firmware
    $wiz['dect'][$mac]['firmware_url'] = trim((string)($_POST['firmware_url'] ?? 'https://dect.snom.com'));
    $wiz['dect'][$mac]['fp_sw']        = sanitize_for_ui((string)($_POST['fp_sw'] ?? ''));
    $wiz['dect'][$mac]['fp_branch']    = sanitize_for_ui((string)($_POST['fp_branch'] ?? ''));
    foreach ($PP_TYPES as $tpp) {
        $wiz['dect'][$mac]['pp_sw_'.$tpp]     = sanitize_for_ui((string)($_POST['pp_sw_'.$tpp] ?? ''));
        $wiz['dect'][$mac]['pp_branch_'.$tpp] = sanitize_for_ui((string)($_POST['pp_branch_'.$tpp] ?? ''));
    }
    // Audio
    $allowedC = array_keys($CODECS);
    foreach (['codec1','codec2','codec3','codec4'] as $cKey) {
        $val = strtolower(trim((string)($_POST[$cKey] ?? $wiz['dect'][$mac][$cKey] ?? '')));
        $wiz['dect'][$mac][$cKey] = in_array($val, $allowedC, true) ? $val : ($wiz['dect'][$mac][$cKey] ?? 'pcma');
    }
    $cz = preg_replace('/\D+/', '', (string)($_POST['codec_size'] ?? $wiz['dect'][$mac]['codec_size'] ?? '20'));
    $wiz['dect'][$mac]['codec_size'] = $cz !== '' ? $cz : '20';
    foreach (['user_srtp'=>['disabled','optional','mandatory'], 'srv_srtp_auth'=>['on','off'], 'user_dtmf_info'=>['on','off'], 'user_full_sdp_answer'=>['on','off']] as $k=>$opts) {
        $val = strtolower(trim((string)($_POST[$k] ?? $wiz['dect'][$mac][$k] ?? '')));
        $wiz['dect'][$mac][$k] = in_array($val, $opts, true) ? $val : ($wiz['dect'][$mac][$k] ?? ($k==='user_srtp'?'disabled':($k==='user_full_sdp_answer'?'on':'off')));
    }
    // Security
    $wiz['dect'][$mac]['http_user'] = sanitize_for_ui((string)($_POST['http_user'] ?? $wiz['dect'][$mac]['http_user'] ?? 'admin'));
    $posted_http_pass = (string)($_POST['http_pass'] ?? '');
    if ($posted_http_pass !== '') {
        $wiz['dect'][$mac]['http_pass'] = $posted_http_pass;
    } elseif (empty($wiz['dect'][$mac]['http_pass'])) {
        $wiz['dect'][$mac]['http_pass'] = random_password_safe(20);
    }
    $wiz['dect'][$mac]['ac_code'] = normalize_ac_code_4((string)($_POST['ac_code'] ?? $wiz['dect'][$mac]['ac_code'] ?? '0000'));
    // VM + custom
    $wiz['dect'][$mac]['vm_number']  = trim((string)($_POST['vm_number'] ?? ''));
    $wiz['dect'][$mac]['custom_xml'] = (string)($_POST['custom_xml'] ?? '');

    // Accounts
    $accIn = (array)($_POST['acct'] ?? []);
    $newAcc = []; $idxCount = 0;
    foreach ($accIn as $k=>$row) {
        $extension = sanitize_for_ui((string)($row['extension'] ?? ''));
        $ipui_raw  = (string)($row['ipui'] ?? '');
        $ac_raw    = (string)($row['ac_code'] ?? '');
        $pass      = (string)($row['user_pass'] ?? '');
        if ($extension === '' && $ipui_raw === '' && $ac_raw === '' && $pass === '') continue;
        $idxCount++; if ($idxCount > $cap) break;

        $ipui_norm = normalize_ipui($ipui_raw);
        $ac_norm   = normalize_ac_code($ac_raw);

        global $secret_by_ext;
        if ($pass === '' && isset($secret_by_ext[$extension])) $pass = $secret_by_ext[$extension];

        $newAcc[] = [
            'extension' => $extension,
            'user_pass' => $pass,
            'ipui'      => $ipui_norm,
            'ac_code'   => $ac_norm
        ];
    }
    $wiz['dect'][$mac]['accounts'] = $newAcc;
    $wiz['flash']=['msg'=>'DECT configuration saved.','type'=>'success'];
    header('Location: dect.php?system_id='.(int)$sysId.'&edit='.urlencode($mac).($DEBUG ? '&debug=1' : '')); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_dect']) && isset($_POST['mac'])) {
    $mac = normalize_mac((string)$_POST['mac']);
    if (!isset($wiz['dect'][$mac])) { $wiz['flash']=['msg'=>'DECT system not found.','type'=>'warn']; header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit; }
    $d = $wiz['dect'][$mac];
    [$ok,$fileOrErr] = write_dect_profile($PROVISION_DIR, $mac, $d, [$fullname_by_ext, $authid_by_ext]);
    if ($ok) {
        $wiz['dect'][$mac]['generated'] = [
            'file' => basename($fileOrErr),
            'url'  => $PUBLIC_PROVISION_PATH.'/'.basename($fileOrErr),
            'created' => date('c')
        ];
        // SRAPS behavior per user request: push only when SRAPS is "Disabled"
        $sraps_on = (($wiz['global']['sraps_enable'] ?? 'off') === 'on'); // on => DO NOT push; off => push
        $extra = '';
        if (!$sraps_on) {
            $endpointName = trim((string)($d['label'] ?? '')) ?: ('DECT '.$mac);
            // Use MSeries profile for DECT (fix product family mismatch)
            $sr = sraps_assign_profile_by_name($mac, 'MSeries', $endpointName);
            $extra = ' ' . ($sr['msg'] ?? '');
        }
        $wiz['flash']=['msg'=>'DECT profile generated.'. $extra,'type'=>'success'];
    } else {
        $wiz['flash']=['msg'=>"Failed to generate: {$fileOrErr}",'type'=>'warn'];
        dbg_write("WRITE failed for MAC=$mac: $fileOrErr");
    }
    header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['regenerate_all_existing'])) {
    $count=0; $errors=[];
    foreach ($wiz['dect'] as $mac=>$d) {
        if (empty($d['generated'])) continue;
        [$ok,$fileOrErr] = write_dect_profile($PROVISION_DIR, $mac, $d, [$fullname_by_ext, $authid_by_ext]);
        if ($ok) {
            $wiz['dect'][$mac]['generated'] = [
                'file' => basename($fileOrErr),
                'url'  => $PUBLIC_PROVISION_PATH.'/'.basename($fileOrErr),
                'created' => date('c')
            ];
            $count++;
        } else {
            $errors[] = $mac.': '.$fileOrErr;
            dbg_write("REWRITE failed for MAC=$mac: $fileOrErr");
        }
    }
    $msg = "Regenerated {$count} DECT profiles."; if (!empty($errors)) $msg .= ' Errors: '.implode('; ', $errors);
    $wiz['flash']=['msg'=>$msg,'type'=>$count ? 'success' : 'warn'];
    header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_dect']) && isset($_POST['mac'])) {
    $mac = normalize_mac((string)$_POST['mac']);
    $extra = '';
    if (isset($wiz['dect'][$mac])) {
        $gen = $wiz['dect'][$mac]['generated']['file'] ?? null;
        if ($gen) {
            $file = rtrim($PROVISION_DIR,'/').'/'.$gen;
            if (is_file($file)) @unlink($file);
        }
        // SRAPS behavior per user: release only when SRAPS is "Disabled"
        $sraps_on = (($wiz['global']['sraps_enable'] ?? 'off') === 'on'); // on => no action; off => release
        if (!$sraps_on) {
            $sr = sraps_release_endpoint($mac);
            $extra = ' ' . ($sr['msg'] ?? '');
        }

        unset($wiz['dect'][$mac]);
        $wiz['flash']=['msg'=>'DECT system deleted.'. $extra,'type'=>'success'];
        dbg_write("DELETE base MAC=$mac");
    } else {
        $wiz['flash']=['msg'=>'DECT system not found.','type'=>'warn'];
    }
    header('Location: dect.php?system_id='.(int)$sysId.($DEBUG ? '&debug=1' : '')); exit;
}

/* UI helpers */
$show_edit_mac = null;
if (isset($_GET['edit']) && trim((string)$_GET['edit']) !== '') $show_edit_mac = normalize_mac((string)$_GET['edit']);

$exts_json = json_encode(array_map(function($r){
    return [
        'extension'=>(string)$r['extension'],
        'fullname'=>sanitize_for_ui((string)$r['fullname']),
        'authid'=>(string)($r['authid'] ?? $r['extension']),
        'secret'=>(string)($r['secret'] ?? '')
    ];
}, $wiz['exts'] ?? []), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);

$dect_list = $wiz['dect'];

/* Toast flash */
$toast_msg = ''; $toast_type = 'success';
if (!empty($wiz['flash']) && is_array($wiz['flash'])) {
    $toast_msg = sanitize_for_ui($wiz['flash']['msg'] ?? '');
    $toast_msg = preg_replace('/\?+\s*$/', '', $toast_msg);
    $toast_type = $wiz['flash']['type'] ?? 'success';
    $wiz['flash'] = null;
}

$title_safe = sanitize_for_ui((string)($sys['label'] ?? 'Provisioning'));
$sraps_on = (($wiz['global']['sraps_enable'] ?? 'off') === 'on'); // label only; logic inverted as above
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?= e($title_safe) ?> - DECT</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f5f7fb;--card:#fff;--muted:#5b6472;--ink:#0d1321;--accent:#2f3bd6;--danger:#dc2626;--border:#e6eaf2;--tab:#eef2ff;--shadow:0 10px 30px rgba(2,6,23,0.08)}
*{box-sizing:border-box}
body{background:var(--bg);margin:18px;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial;color:var(--ink)}
.container{max-width:1220px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.brand a{display:flex;align-items:center;gap:12px;text-decoration:none;color:inherit}
.logo{height:48px;width:auto;border-radius:10px;padding:6px;background:#fff;object-fit:contain;border:1px solid var(--border)}
.small{font-size:13px;color:var(--muted)}
.btn{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:8px 10px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;font-weight:600;font-size:12px}
.btn.secondary{background:#334155}.btn.warn{background:var(--danger)}.btn.inline{padding:6px 9px}.btn.ghost{background:#eef2ff;color:#0b2548}
.header-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.table{margin-top:12px;border-radius:14px;overflow:hidden;box-shadow:var(--shadow);border:1px solid var(--border);background:var(--card)}
.table table{width:100%;border-collapse:collapse}
.table th,.table td{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:middle}
.table thead th{background:#fafcff;text-align:left}
.small-input, select.small-input, textarea.small-input{height:30px;padding:6px 8px;border-radius:10px;border:1px solid var(--border);font-size:12px;background:#fff;width:100%}
textarea.small-input{min-height:120px;height:auto}
.row-actions{display:flex;gap:8px;align-items:center;white-space:nowrap}
.section-card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:12px;margin-bottom:12px}
.group-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:10px}
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--border);margin-bottom:8px;flex:0 0 auto}
.tab{padding:6px 9px;border-radius:10px 10px 0 0;background:var(--tab);cursor:pointer;color:#0b2548;font-weight:600;font-size:12px}
.tab.active{background:#fff;border:1px solid var(--border);border-bottom-color:#fff}
.tabpanel{display:none}
.tabpanel.active{display:block}
.modal-card{width:1000px;max-width:96vw;background:#fff;border:1px solid var(--border);border-radius:16px;padding:0;box-shadow:var(--shadow);max-height:92vh;display:flex;flex-direction:column}
.modal-header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.modal-body{padding:12px 16px;overflow:auto;flex:1}
.grid{display:grid;grid-template-columns:220px 1fr;gap:8px 12px;align-items:center}
.hr{height:1px;background:var(--border);margin:10px 0}
.tabpanel{max-height:calc(92vh - 200px);overflow:auto}
.accounts-table{width:100%;border-collapse:collapse;border:1px solid var(--border);border-radius:12px;overflow:hidden}
.accounts-table th,.accounts-table td{border-bottom:1px solid var(--border);padding:8px 10px;font-size:12px}
.accounts-table thead th{background:#fafcff;text-align:left}
.debug-card{background:#111827;color:#e5e7eb;border-radius:12px;padding:10px;margin-top:12px;white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
.debug-card h4{margin:0 0 6px 0;color:#93c5fd}
.debug-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:6px}
/* Toast styles */
.center-toast-overlay{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;z-index:200000;background:rgba(7,12,20,0.25)}
.center-toast{min-width:260px;max-width:92%;padding:12px 16px;border-radius:10px;color:#fff;font-weight:700;text-align:center;display:flex;align-items:center;gap:12px}
.center-toast.success{background:linear-gradient(90deg,#059669,#047857)}
.center-toast.warn{background:linear-gradient(90deg,#f97316,#dc2626)}
.center-toast .close-btn{background:transparent;border:0;color:rgba(255,255,255,0.95);font-size:18px;cursor:pointer;padding:6px;border-radius:8px}
.center-toast .close-btn:hover{background:rgba(255,255,255,0.06)}
/* Search input */
.search-input{height:30px;padding:6px 8px;border:1px solid var(--border);border-radius:10px;font-size:12px;width:240px;min-width:180px}
</style>
<?php
// Include same theme (optional)
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
      <!-- Make logo/title clickable to go "Home" (extensions.php) -->
      <a href="extensions.php?system_id=<?= (int)$sysId ?><?= $DEBUG ? '&debug=1' : '' ?>" title="Go to Extensions">
        <img id="site-logo" src="<?= e($logo_src) ?>" class="logo" alt="logo" onerror="this.onerror=null;this.src='<?= e($local_logo_path) ?>';">
        <div>
          <div style="font-weight:700"><?= e($title_safe) ?></div>
          <div class="small">Host: <?= e((string)$sys['host'] ?? '') ?></div>
        </div>
      </a>
    </div>
    <div class="header-actions">
      <!-- SRAPS toggle replaces "Home" button -->
      <form method="post" style="margin:0;display:inline">
        <button class="btn inline" type="submit" name="toggle_sraps" value="1"><?= $sraps_on ? 'SRAPS Enabled' : 'SRAPS Disabled' ?></button>
      </form>
      <button class="btn secondary inline" type="button" onclick="document.getElementById('switch-site-modal').style.display='flex'">Switch Site</button>
      <a href="logout.php" class="btn warn inline" style="text-decoration:none">Logout</a>
      <form method="post" style="margin:0"><input type="hidden" name="fetch_ucm" value="1"><button class="btn secondary inline" type="submit">Refresh Extensions</button></form>
      <form method="post" style="margin:0"><input type="hidden" name="regenerate_all_existing" value="1"><button class="btn inline" type="submit">Regenerate All Existing</button></form>
      <form method="post" style="margin:0;display:inline"><input type="hidden" name="open_add_dect" value="1"><button class="btn inline" type="submit">Add DECT System</button></form>
      <input id="search-dect" class="search-input" type="text" placeholder="Search MAC, Label or Extension" aria-label="Search">
      <!-- Removed Search button to keep layout clean -->
    </div>
  </div>

  <div class="table" style="margin-top:12px">
    <table id="dect-table">
      <thead><tr><th style="width:240px">Label</th><th style="width:180px">MAC</th><th style="width:120px">Model</th><th>Accounts</th><th style="width:420px">Actions</th></tr></thead>
      <tbody>
        <?php if (!empty($dect_list)): foreach ($dect_list as $mac=>$d): $gen = $d['generated']['url'] ?? ''; $label = trim((string)($d['label'] ?? ''));
          $assigned_exts = [];
          foreach (($d['accounts'] ?? []) as $acc) {
              $ev = trim((string)($acc['extension'] ?? ''));
              if ($ev !== '') $assigned_exts[] = $ev;
          }
          $data_exts = strtolower(implode(' ', $assigned_exts));
          $exts_title = empty($assigned_exts) ? '' : ('Extensions: '.implode(', ', $assigned_exts));
        ?>
          <tr data-exts="<?= e($data_exts) ?>">
            <td class="col-label" title="<?= e($exts_title) ?>">
              <?= e($label) ?>
              <!-- hidden extensions text to ensure search works even if dataset not read -->
              <?php if (!empty($assigned_exts)): ?>
                <span class="ext-haystack" style="display:none"><?= e(implode(' ', $assigned_exts)) ?></span>
              <?php endif; ?>
            </td>
            <td class="col-mac"><?= e($mac) ?></td>
            <td><?= e($d['model'] ?? '') ?></td>
            <td><?= (int)count($d['accounts'] ?? []) ?> / <?= dect_capacity((string)($d['model'] ?? '')) ?></td>
            <td>
              <div class="row-actions">
                <a class="btn secondary inline" href="dect.php?system_id=<?= (int)$sysId ?>&edit=<?= e($mac) ?><?= $DEBUG ? '&debug=1' : '' ?>" style="text-decoration:none">Configure</a>
                <form method="post" style="margin:0;display:inline">
                  <input type="hidden" name="mac" value="<?= e($mac) ?>">
                  <button class="btn inline" name="generate_dect" value="1">Generate</button>
                </form>
                <?php if ($gen): ?><a class="btn secondary inline" href="<?= e($gen) ?>" target="_blank" rel="noopener noreferrer">Download</a><?php endif; ?>
                <form method="post" style="margin:0;display:inline" onsubmit="return confirm('Delete DECT system <?= e($mac) ?> ?');">
                  <input type="hidden" name="mac" value="<?= e($mac) ?>">
                  <button class="btn warn inline" name="delete_dect" value="1">Delete</button>
                </form>
              </div>
            </td>
          </tr>
        <?php endforeach; else: ?>
          <tr><td colspan="5" class="small">No DECT systems yet. Use "Add DECT System".</td></tr>
        <?php endif; ?>
      </tbody>
    </table>
  </div>

  <?php if ($DEBUG): ?>
  <div class="debug-card">
    <h4>Debug: Last 200 log lines (provision_ac_debug.log)</h4>
    <?= e(tail_file($DBG_LOG, 200)) ?>
  </div>
  <?php endif; ?>
</div>

<?php
// Clear debug log action (manual trigger if needed)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['__clear_debug_log'])) {
    @unlink($DBG_LOG);
    header('Location: dect.php?system_id='.(int)$sysId.'&debug=1'); exit;
}
?>

<!-- Switch Site modal -->
<div id="switch-site-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);align-items:center;justify-content:center;z-index:9998">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="switch-site-title">
    <div class="modal-header">
      <h3 id="switch-site-title" style="margin:0;font-size:16px">Switch Site</h3>
      <div><button type="button" class="btn secondary inline" onclick="document.getElementById('switch-site-modal').style.display='none'">Close</button></div>
    </div>
    <div class="modal-body">
      <div class="grid">
        <div class="label">Choose a site</div>
        <div class="value">
          <select id="switch-site-select" class="small-input" style="width:100%">
            <?php if (!empty($sites)): foreach ($sites as $s): ?>
              <option value="<?= (int)$s['id'] ?>" <?= ((int)$s['id'] === (int)$sysId) ? 'selected' : '' ?>>
                <?= e($s['label']) ?> <?= $s['host'] ? (' - '.e($s['host'])) : '' ?>
              </option>
            <?php endforeach; else: ?>
              <option value="">No sites found</option>
            <?php endif; ?>
          </select>
        </div>
      </div>
      <div class="group-actions">
        <button type="button" class="btn secondary inline" onclick="document.getElementById('switch-site-modal').style.display='none'">Cancel</button>
        <button type="button" class="btn inline" onclick="switchSiteGo()">Go</button>
      </div>
    </div>
  </div>
</div>

<!-- Add DECT System modal -->
<?php if ($show_add_dect_modal): ?>
<div id="add-dect-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9999">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="add-dect-title" style="max-width:640px">
    <div class="modal-header">
      <h3 id="add-dect-title" style="margin:0;font-size:16px">Add DECT System</h3>
      <div><a class="btn secondary inline" href="dect.php?system_id=<?= (int)$sysId ?><?= $DEBUG ? '&debug=1' : '' ?>" style="text-decoration:none">Close</a></div>
    </div>
    <div class="modal-body">
      <form method="post" style="display:block">
        <div class="section-card">
          <div class="grid">
            <div class="label">Label</div>
            <div class="value"><input class="small-input" name="dect_label" placeholder="Warehouse DECT"></div>

            <div class="label">MAC Address</div>
            <div class="value"><input class="small-input" name="dect_mac" placeholder="AABBCCDDEEFF" maxlength="17"></div>

            <div class="label">Model</div>
            <div class="value">
              <select class="small-input" name="dect_model">
                <option value="M400">M400</option>
                <option value="M900">M900</option>
              </select>
            </div>
          </div>
        </div>
        <div class="group-actions">
          <a class="btn secondary inline" href="dect.php?system_id=<?= (int)$sysId ?><?= $DEBUG ? '&debug=1' : '' ?>" style="text-decoration:none">Cancel</a>
          <button class="btn inline" type="submit" name="create_dect" value="1">Create</button>
        </div>
      </form>
    </div>
  </div>
</div>
<?php endif; ?>

<!-- Configure DECT modal -->
<?php if (!empty($show_edit_mac) && isset($wiz['dect'][$show_edit_mac])): $D = $wiz['dect'][$show_edit_mac]; $cap = dect_capacity((string)($D['model'] ?? '')); $accounts = $D['accounts'] ?? []; ?>
<div id="edit-dect-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9999">
  <div class="modal-card">
    <div class="modal-header">
      <div>
        <h3 style="margin:0;font-size:16px">Configure DECT - <?= e($show_edit_mac) ?> <?= e(($D['label']??'') ? ' — '.$D['label'] : '') ?></h3>
        <div class="small" style="margin-top:3px;color:#64748b">Accounts: <?= (int)count($accounts) ?> / <?= (int)$cap ?></div>
      </div>
      <div><a class="btn secondary inline" href="dect.php?system_id=<?= (int)$sysId ?><?= $DEBUG ? '&debug=1' : '' ?>" style="text-decoration:none">Close</a></div>
    </div>
    <div class="modal-body">
      <div class="tabs">
        <div class="tab active" data-tab="tab-sip">SIP Settings</div>
        <div class="tab" data-tab="tab-accounts">Accounts</div>
        <div class="tab" data-tab="tab-base">Base Settings</div>
        <div class="tab" data-tab="tab-contact">Contact</div>
        <div class="tab" data-tab="tab-localisation">Localisation</div>
        <div class="tab" data-tab="tab-audio">Audio</div>
        <div class="tab" data-tab="tab-security">Security</div>
        <div class="tab" data-tab="tab-custom">Custom XML</div>
      </div>

      <form method="post">
        <input type="hidden" name="mac" value="<?= e($show_edit_mac) ?>">

        <div id="tab-sip" class="tabpanel active">
          <div class="section-card">
            <div class="grid">
              <div class="label">Label</div>
              <div class="value"><input class="small-input" name="label" value="<?= e($D['label'] ?? '') ?>" placeholder="Warehouse DECT"></div>

              <div class="label">user_host</div>
              <div class="value"><input class="small-input" name="host" value="<?= e($D['host'] ?? '') ?>" placeholder="IP or FQDN of system"></div>

              <div class="label">user_outbound</div>
              <div class="value"><input class="small-input" name="outbound" value="<?= e($D['outbound'] ?? '') ?>" placeholder="IP or FQDN of system"></div>

              <div class="label">Server Alias</div>
              <div class="value"><input class="small-input" name="alias" value="<?= e($D['alias'] ?? '') ?>" placeholder="Alias name"></div>

              <div class="label">SIP Transport</div>
              <div class="value">
                <?php $trans = strtolower((string)($D['transport'] ?? 'udp')); ?>
                <select class="small-input" name="transport">
                  <option value="udp"  <?= $trans==='udp'  ? 'selected':'' ?>>UDP</option>
                  <option value="tcp"  <?= $trans==='tcp'  ? 'selected':'' ?>>TCP</option>
                  <option value="tls"  <?= $trans==='tls'  ? 'selected':'' ?>>TLS</option>
                  <option value="auto" <?= $trans==='auto' ? 'selected':'' ?>>AUTO</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        <div id="tab-accounts" class="tabpanel">
          <div class="section-card">
            <table class="accounts-table">
              <thead>
                <tr>
                  <th style="width:70px">#</th>
                  <th style="width:380px">Extension</th>
                  <th style="width:220px">IPEI / IPUI</th>
                  <th style="width:180px">AC code</th>
                  <th style="width:220px">SIP Password</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="acct-body">
                <?php
                  $rows = $accounts;
                  if (empty($rows)) $rows = [['extension'=>'','user_pass'=>'','ipui'=>'','ac_code'=>'']];
                  $i = 1;
                  foreach ($rows as $r):
                    $extVal  = sanitize_for_ui((string)($r['extension'] ?? ''));
                    $ipuiVal = sanitize_for_ui((string)($r['ipui'] ?? ''));
                    $acVal   = sanitize_for_ui((string)($r['ac_code'] ?? ''));
                    $passVal = sanitize_for_ui((string)($r['user_pass'] ?? ''));
                ?>
                <tr>
                  <td><?= (int)$i ?></td>
                  <td>
                    <select class="small-input ext-select" name="acct[<?= (int)$i ?>][extension]" onchange="extSelectChanged(this)">
                      <option value=""></option>
                      <?php foreach (($wiz['exts'] ?? []) as $eRow):
                        $optVal = sanitize_for_ui((string)$eRow['extension']);
                        $optName = sanitize_for_ui((string)$eRow['fullname']);
                        $sel = ($optVal === $extVal) ? 'selected' : '';
                        $label = $optVal . ($optName !== '' ? (' — '.$optName) : '');
                      ?>
                        <option value="<?= e($optVal) ?>" <?= $sel ?>><?= e($label) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </td>
                  <td><input class="small-input" name="acct[<?= (int)$i ?>][ipui]" value="<?= e($ipuiVal) ?>" placeholder="0xFFFFFFFFFF or 10 hex e.g. 0260A12345"></td>
                  <td><input class="small-input" name="acct[<?= (int)$i ?>][ac_code]" value="<?= e($acVal) ?>" placeholder="Digits only e.g. 0987"></td>
                  <td><input class="small-input" type="password" name="acct[<?= (int)$i ?>][user_pass]" value="<?= e($passVal) ?>" placeholder="********"></td>
                  <td><button type="button" class="btn ghost inline" onclick="removeRow(this)">Remove</button></td>
                </tr>
                <?php $i++; endforeach; ?>
              </tbody>
            </table>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
              <div class="small" style="color:#64748b">Capacity: <?= (int)$cap ?> accounts</div>
              <button type="button" class="btn secondary inline" onclick="addAccountRow()">+ Add Account</button>
            </div>
            <div class="hr"></div>
            <div class="grid">
              <div class="label">Voicemail Number</div>
              <div class="value"><input class="small-input" name="vm_number" value="<?= e($D['vm_number'] ?? '') ?>" placeholder="5000"></div>
            </div>
          </div>
        </div>

        <div id="tab-base" class="tabpanel">
          <div class="section-card">
            <div class="grid">
              <div class="label">Multi-Cell</div>
              <div class="value">
                <label style="display:inline-flex;align-items:center;gap:8px">
                  <input type="checkbox" name="multicell" value="on" <?= (($D['multicell'] ?? 'off') === 'on') ? 'checked' : '' ?>>
                </label>
              </div>
            </div>
          </div>

          <div class="section-card">
            <div style="font-weight:600;margin-bottom:6px">Firmware Settings</div>
            <div class="grid">
              <div class="label">Firmware Base URL</div>
              <div class="value"><input class="small-input" name="firmware_url" value="<?= e($D['firmware_url'] ?? 'https://dect.snom.com') ?>" placeholder="https://dect.snom.com"></div>
              <div class="label">FP SW Version</div>
              <div class="value"><input class="small-input" name="fp_sw" value="<?= e($D['fp_sw'] ?? '') ?>" placeholder=""></div>
              <div class="label">FP Branch</div>
              <div class="value"><input class="small-input" name="fp_branch" value="<?= e($D['fp_branch'] ?? '') ?>" placeholder=""></div>
            </div>
            <div class="hr"></div>
            <div class="grid">
              <?php foreach ($PP_TYPES as $t): ?>
                <div class="label">PP <?= e($t) ?> SW</div>
                <div class="value"><input class="small-input" name="pp_sw_<?= e($t) ?>" value="<?= e($D['pp_sw_'.$t] ?? '') ?>"></div>
                <div class="label">PP <?= e($t) ?> Branch</div>
                <div class="value"><input class="small-input" name="pp_branch_<?= e($t) ?>" value="<?= e($D['pp_branch_'.$t] ?? '') ?>"></div>
              <?php endforeach; ?>
            </div>
          </div>
        </div>

        <div id="tab-contact" class="tabpanel">
          <div class="section-card">
            <div class="grid">
              <div class="label">Phonebook Location</div>
              <div class="value"><input class="small-input" name="phonebook_location" value="<?= e($D['phonebook_location'] ?? $PROVISION_URL) ?>" placeholder="Full URL folder e.g. <?= e($PROVISION_URL) ?> or %%PROVLINKLOCAL%%/"></div>
              <div class="label">Phonebook Filename</div>
              <div class="value"><input class="small-input" name="phonebook_filename" value="<?= e($D['phonebook_filename'] ?? 'phonebook.xml') ?>" placeholder="phonebook.xml"></div>
            </div>
          </div>
        </div>

        <div id="tab-localisation" class="tabpanel">
          <div class="section-card">
            <div class="grid">
              <div class="label">NTP Server</div>
              <div class="value"><input class="small-input" name="ntp_server" value="<?= e($D['ntp_server'] ?? 'pool.ntp.org') ?>" placeholder="pool.ntp.org"></div>

              <div class="label">NTP Refresh Timer</div>
              <div class="value"><input class="small-input" type="number" min="300" step="60" name="ntp_refresh_timer" value="<?= e($D['ntp_refresh_timer'] ?? '3600') ?>" placeholder="3600"></div>

              <div class="label">Tone Scheme</div>
              <div class="value">
                <?php
                  $toneVal = strtoupper((string)($D['tone_scheme'] ?? ''));
                  if (!array_key_exists($toneVal, $TONE_CODES)) $toneVal = '';
                ?>
                <select class="small-input" name="tone_scheme">
                  <option value=""></option>
                  <?php foreach ($TONE_CODES as $code=>$country): $sel = ($toneVal === $code) ? 'selected' : ''; ?>
                    <option value="<?= e($code) ?>" <?= $sel ?>><?= e($country) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="label">Timezone</div>
              <div class="value">
                <?php $tz = (string)($D['timezone'] ?? ''); ?>
                <select class="small-input" name="timezone">
                  <option value=""></option>
                  <?php foreach ($TZ_LABELS as $code=>$label): $sel = ($tz === $code) ? 'selected' : ''; ?>
                    <option value="<?= e($code) ?>" <?= $sel ?>><?= e($label) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="label">Language</div>
              <div class="value">
                <?php
                  $langVal = (string)($D['language'] ?? '');
                  if (!in_array($langVal, $LANG_ALLOWED_VALUES, true)) $langVal = 'English'; // fallback in UI
                ?>
                <select class="small-input" name="language">
                  <?php foreach ($LANG_OPTIONS as $opt): $sel = ($langVal===$opt['value']) ? 'selected' : ''; ?>
                    <option value="<?= e($opt['value']) ?>" <?= $sel ?>><?= e($opt['label']) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="label">Web UI Language</div>
              <div class="value">
                <?php
                  $wlangVal = (string)($D['web_language'] ?? '');
                  if (!in_array($wlangVal, $LANG_ALLOWED_VALUES, true)) $wlangVal = 'English'; // fallback in UI
                ?>
                <select class="small-input" name="web_language">
                  <?php foreach ($LANG_OPTIONS as $opt): $sel = ($wlangVal===$opt['value']) ? 'selected' : ''; ?>
                    <option value="<?= e($opt['value']) ?>" <?= $sel ?>><?= e($opt['label']) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
            </div>
          </div>
        </div>

        <div id="tab-audio" class="tabpanel">
          <div class="section-card">
            <div class="grid">
              <div class="label">Codec 1</div>
              <div class="value">
                <select class="small-input" name="codec1">
                  <?php $c1 = strtolower((string)($D['codec1'] ?? 'pcma')); foreach ($CODECS as $val=>$lab): ?>
                  <option value="<?= e($val) ?>" <?= $c1===$val?'selected':'' ?>><?= e($lab) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="label">Codec 2</div>
              <div class="value">
                <?php $c2 = strtolower((string)($D['codec2'] ?? 'pcmu')); ?>
                <select class="small-input" name="codec2">
                  <?php foreach ($CODECS as $val=>$lab): ?>
                  <option value="<?= e($val) ?>" <?= $c2===$val?'selected':'' ?>><?= e($lab) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="label">Codec 3</div>
              <div class="value">
                <?php $c3 = strtolower((string)($D['codec3'] ?? 'g722')); ?>
                <select class="small-input" name="codec3">
                  <?php foreach ($CODECS as $val=>$lab): ?>
                  <option value="<?= e($val) ?>" <?= $c3===$val?'selected':'' ?>><?= e($lab) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="label">Codec 4</div>
              <div class="value">
                <?php $c4 = strtolower((string)($D['codec4'] ?? 'g729')); ?>
                <select class="small-input" name="codec4">
                  <?php foreach ($CODECS as $val=>$lab): ?>
                  <option value="<?= e($val) ?>" <?= $c4===$val?'selected':'' ?>><?= e($lab) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="label">Packet Size</div>
              <div class="value"><input class="small-input" type="number" name="codec_size" min="10" step="10" value="<?= e($D['codec_size'] ?? '20') ?>"></div>
              <div class="label">SRTP</div>
              <div class="value">
                <?php $usrtp = strtolower((string)($D['user_srtp'] ?? 'disabled')); ?>
                <select class="small-input" name="user_srtp">
                  <option value="disabled" <?= $usrtp==='disabled'?'selected':'' ?>>disabled</option>
                  <option value="optional" <?= $usrtp==='optional'?'selected':'' ?>>optional</option>
                  <option value="mandatory" <?= $usrtp==='mandatory'?'selected':'' ?>>mandatory</option>
                </select>
              </div>
              <div class="label">SRTP Auth</div>
              <div class="value">
                <?php $sa = strtolower((string)($D['srv_srtp_auth'] ?? 'off')); ?>
                <select class="small-input" name="srv_srtp_auth">
                  <option value="off" <?= $sa==='off'?'selected':'' ?>>off</option>
                  <option value="on" <?= $sa==='on'?'selected':'' ?>>on</option>
                </select>
              </div>
              <div class="label">DTMF INFO</div>
              <div class="value">
                <?php $ud = strtolower((string)($D['user_dtmf_info'] ?? 'off')); ?>
                <select class="small-input" name="user_dtmf_info">
                  <option value="off" <?= $ud==='off'?'selected':'' ?>>off</option>
                  <option value="on" <?= $ud==='on'?'selected':'' ?>>on</option>
                </select>
              </div>
              <div class="label">Full SDP Answer</div>
              <div class="value">
                <?php $fa = strtolower((string)($D['user_full_sdp_answer'] ?? 'on')); ?>
                <select class="small-input" name="user_full_sdp_answer">
                  <option value="on" <?= $fa==='on'?'selected':'' ?>>on</option>
                  <option value="off" <?= $fa==='off'?'selected':'' ?>>off</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        <div id="tab-security" class="tabpanel">
          <div class="section-card">
            <div class="grid">
              <div class="label">Web UI Username</div>
              <div class="value"><input class="small-input" name="http_user" value="<?= e($D['http_user'] ?? 'admin') ?>" placeholder="admin"></div>
              <div class="label">Web UI Password</div>
              <div class="value">
                <?php $httpPassVal = (string)($D['http_pass'] ?? ''); ?>
                <div style="display:flex; gap:8px; align-items:center">
                  <input class="small-input" id="http_pass" name="http_pass" type="password" value="<?= e($httpPassVal) ?>" placeholder="auto-generated if empty" style="flex:1">
                  <button type="button" class="btn ghost inline" onclick="togglePw('http_pass')">View</button>
                  <button type="button" class="btn ghost inline" onclick="copyPw('http_pass')">Copy</button>
                  <button type="button" class="btn ghost inline" onclick="genPw('http_pass', 20)">Generate</button>
                </div>
              </div>
              <div class="label">Base AC Code</div>
              <div class="value"><input class="small-input" name="ac_code" value="<?= e($D['ac_code'] ?? '0000') ?>" maxlength="4" pattern="\d{4}" oninput="this.value=this.value.replace(/\D+/g,'').slice(0,4)" placeholder="4 digits e.g. 0000"></div>
            </div>
          </div>
        </div>

        <div id="tab-custom" class="tabpanel">
          <div class="section-card">
            <textarea class="small-input" name="custom_xml" placeholder="<your-tags>...</your-tags>"><?= htmlspecialchars((string)($D['custom_xml'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></textarea>
          </div>
        </div>

        <div class="group-actions">
          <a class="btn secondary inline" href="dect.php?system_id=<?= (int)$sysId ?><?= $DEBUG ? '&debug=1' : '' ?>" style="text-decoration:none">Cancel</a>
          <button class="btn inline" type="submit" name="save_dect" value="1">Save</button>
        </div>
      </form>
    </div>
  </div>
</div>
<?php endif; ?>

<script>
const FLASH_MSG = <?= json_encode($toast_msg) ?: '""' ?>;
const FLASH_TYPE = <?= json_encode($toast_type) ?: '"success"' ?>;
const SYSTEM_ID = <?= json_encode($sysId) ?>;
const EXTS = <?= $exts_json ?: '[]' ?>;

// Toast popup
function showToast(message, type='success', duration=3000) {
  message = String(message || '').replace(/\s+/g,' ').replace(/\?+\s*$/,'').trim();
  if (!message) return;
  document.querySelectorAll('.center-toast-overlay').forEach(el => el.remove());
  const overlay = document.createElement('div'); overlay.className = 'center-toast-overlay'; overlay.setAttribute('role','status');
  const box = document.createElement('div'); box.className = 'center-toast ' + (type==='warn' ? 'warn' : 'success');
  const txt = document.createElement('div'); txt.style.flex = '1'; txt.style.textAlign = 'center'; txt.textContent = message;
  const close = document.createElement('button'); close.className = 'close-btn'; close.innerHTML = '&times;'; close.title='Close';
  close.addEventListener('click', () => overlay.remove());
  box.appendChild(txt); box.appendChild(close); overlay.appendChild(box); document.body.appendChild(overlay);
  const ms = Math.min(Math.max(0, Number(duration) || 3000), 3000);
  setTimeout(()=>{ overlay.remove(); }, ms);
}

document.addEventListener('DOMContentLoaded', function(){
  try { if (FLASH_MSG) showToast(FLASH_MSG, FLASH_TYPE, 3000); } catch(e){}

  document.querySelectorAll('.tabpanel').forEach(p=>{
    p.style.display = p.classList.contains('active') ? 'block' : 'none';
  });

  document.querySelectorAll('.tabs').forEach(tabsEl=>{
    tabsEl.querySelectorAll('.tab').forEach(tab=>{
      tab.addEventListener('click', ()=>{
        const tgt = tab.getAttribute('data-tab');
        const container = tabsEl.parentElement;
        const panel = document.getElementById(tgt);

        tabsEl.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        tab.classList.add('active');

        const groupPanels = Array.from(container.querySelectorAll('.tabpanel'));
        groupPanels.forEach(p=>{ p.classList.remove('active'); p.style.display = 'none'; });
        if (panel) { panel.classList.add('active'); panel.style.display = 'block'; }
      });
    });
  });

  // Search: filter by MAC, Label, or assigned Extensions (data-exts and hidden span)
  const searchInput = document.getElementById('search-dect');
  function applySearchFilter() {
    const q = (searchInput.value || '').toLowerCase().trim();
    const rows = document.querySelectorAll('#dect-table tbody tr');
    rows.forEach(tr => {
      const mac = (tr.querySelector('.col-mac')?.textContent || '').toLowerCase();
      const label = (tr.querySelector('.col-label')?.textContent || '').toLowerCase();
      const extsAttr = (tr.getAttribute('data-exts') || '').toLowerCase();
      const extsText = (tr.querySelector('.ext-haystack')?.textContent || '').toLowerCase();
      const hay = [mac, label, extsAttr, extsText].join(' ');
      tr.style.display = (q === '' || hay.indexOf(q) !== -1) ? '' : 'none';
    });
  }
  if (searchInput) {
    searchInput.addEventListener('input', applySearchFilter);
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); applySearchFilter(); }
    });
  }

  document.querySelectorAll('.ext-select').forEach(sel => {
    sel.addEventListener('change', () => extSelectChanged(sel));
  });
});

function switchSiteGo(){
  const sel = document.getElementById('switch-site-select');
  const modal = document.getElementById('switch-site-modal');
  if (!sel || !sel.value) { if (modal) modal.style.display='none'; return; }
  window.location.href = 'dect.php?system_id=' + encodeURIComponent(sel.value) + '<?= $DEBUG ? '&debug=1' : '' ?>';
}
function removeRow(btn){
  const tr = btn.closest('tr'); if (!tr) return;
  const tbody = tr.parentElement; tr.remove();
  renumberRows(tbody);
}
function renumberRows(tbody){
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.forEach((tr,idx)=>{
    tr.querySelector('td:first-child').textContent = (idx+1);
    tr.querySelectorAll('input,select,textarea').forEach(inp=>{
      ['name','id','for'].forEach(attr=>{
        const v = inp.getAttribute(attr); if (!v) return;
        const v2 = v.replace(/acct\[\d+\]/,'acct['+(idx+1)+']');
        if (v2 !== v) inp.setAttribute(attr, v2);
      });
    });
  });
}
function addAccountRow(){
  const tbody = document.getElementById('acct-body');
  const idx = tbody.querySelectorAll('tr').length + 1;
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>${idx}</td>
    <td>
      <select class="small-input ext-select" name="acct[${idx}][extension]" onchange="extSelectChanged(this)">${getExtOptionsHtml('')}</select>
    </td>
    <td><input class="small-input" name="acct[${idx}][ipui]" placeholder="0xFFFFFFFFFF or 10 hex e.g. 0260A12345"></td>
    <td><input class="small-input" name="acct[${idx}][ac_code]" placeholder="Digits only e.g. 0987"></td>
    <td><input class="small-input" type="password" name="acct[${idx}][user_pass]" placeholder="********"></td>
    <td><button type="button" class="btn ghost inline" onclick="removeRow(this)">Remove</button></td>
  `;
  tbody.appendChild(tr);
}
function getExtOptionsHtml(selected){
  let html = `<option value=""></option>`;
  const sel = String(selected || '');
  (EXTS || []).forEach(x=>{
    const v = String(x.extension || '');
    const n = String(x.fullname || '');
    const lab = v + (n ? ' — ' + n : '');
    const s = (v === sel) ? ' selected' : '';
    html += `<option value="${escapeHtml(v)}"${s}>${escapeHtml(lab)}</option>`;
  });
  return html;
}
function extSelectChanged(selectEl){
  const nameAttr = selectEl.getAttribute('name') || '';
  const m = nameAttr.match(/acct\[(\d+)\]\[extension\]/);
  const idx = m ? m[1] : null;
  const ext = selectEl.value || '';
  if (idx) {
    const passInput = document.querySelector(`input[name="acct[${idx}][user_pass]"]`);
    const info = (EXTS || []).find(x => String(x.extension) === String(ext));
    if (passInput && !passInput.value && info && info.secret) passInput.value = info.secret;
  }
}
function escapeHtml(s){
  return String(s || '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}
function togglePw(id){
  const el = document.getElementById(id);
  if (!el) return;
  el.type = (el.type === 'password') ? 'text' : 'password';
}
function copyPw(id){
  const el = document.getElementById(id);
  if (!el) { showToast('No password field found','warn'); return; }
  const secret = String(el.value || '');
  if (!secret) { showToast('No password available to copy','warn'); return; }

  if (navigator && navigator.clipboard && navigator.clipboard.writeText && (window.isSecureContext || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    navigator.clipboard.writeText(secret)
      .then(() => showToast('Password copied','success', 3000))
      .catch(() => fallbackCopy(secret));
  } else {
    fallbackCopy(secret);
  }

  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly','');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(ok ? 'Password copied' : 'Copy failed', ok ? 'success' : 'warn', 3000);
    } catch(e){
      showToast('Copy failed','warn', 3000);
    }
  }
}
function genPw(id, len){
  const el = document.getElementById(id);
  if (!el) return;
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'; // SAFE charset (no symbols)
  let out=''; for(let i=0;i<(len||20);i++){ out += chars[Math.floor(Math.random()*chars.length)]; }
  el.value = out;
}
</script>
<!-- UI_BUILD: <?= e($UI_BUILD) ?> | file: <?= e(__FILE__) ?> | time: <?= e(date('c')) ?> -->
</body>
</html>