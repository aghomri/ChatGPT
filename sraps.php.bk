<?php
/*
  SRAPS single-file tool (Hardcoded credentials + Select Profile + Assign MAC)

  What this file does
  - You hardcode your SRAPS credentials below once (constants).
  - The app auto-logs in using those credentials (no UI typing).
  - You can:
      1) Load your provisioning profiles and select one
      2) Assign a MAC to the selected profile (PUT /companies/{company}/endpoints/{mac})

  IMPORTANT SECURITY NOTE
  - Storing secrets in source code is risky. Only do this on a trusted server and keep this file private.
  - Prefer file permissions 600 and a private directory not accessible to others.
  - Always serve this over HTTPS.

  How to use
  1) Fill the constants under "HARD-CODED CREDENTIALS" below with your real values.
  2) Upload this file to your server and open it in the browser.
  3) It will auto-login using the constants. Click "Load/Refresh profiles", select one, then assign a MAC.
*/

declare(strict_types=1);

// ---------------------------
// HARD-CODED CREDENTIALS (FILL THESE)
// ---------------------------
// Base URL example: https://secure-provisioning.snom.com/api  or  https://api.sraps.snom.com/api
const SRAPS_HARD_BASE_URL   = 'https://secure-provisioning.snom.com/api';
const SRAPS_HARD_VERSION    = 'v1';
const SRAPS_HARD_COMPANY_ID = '708eb208e44d412dacf5fcf5230ccf1c';
const SRAPS_HARD_HAWK_ID    = 'ck_685f8911c8744e0b9637cc1c95451ef8';
const SRAPS_HARD_HAWK_KEY   = '9fed0906a5994c4992728d74a1a9ce79';

// ---------------------------
// Session (proxy-aware HTTPS detection)
// ---------------------------
$proto  = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
$https  = $_SERVER['HTTPS'] ?? '';
$port   = (int)($_SERVER['SERVER_PORT'] ?? 0);
$secure = ($https === 'on' || $https === '1') || $port === 443 || strtolower($proto) === 'https';

if (PHP_VERSION_ID >= 70300) {
  session_set_cookie_params([
    'secure'   => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
    'path'     => '/',
  ]);
} else {
  session_set_cookie_params(0, '/', '', $secure, true);
}
session_start();

// ---------------------------
// Defaults
// ---------------------------
$DEFAULT_BASE_URL = SRAPS_HARD_BASE_URL ?: 'https://secure-provisioning.snom.com/api';
$DEFAULT_VERSION  = SRAPS_HARD_VERSION ?: 'v1';

// ---------------------------
// Utilities
// ---------------------------
function json_response(int $status, $data): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
}
function read_json_input(): array {
  $raw = file_get_contents('php://input') ?: '';
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}
function parse_link_next(?string $linkHeader): ?string {
  if (!$linkHeader) return null;
  foreach (array_map('trim', explode(',', $linkHeader)) as $p) {
    if (preg_match('/<([^>]+)>\s*;\s*rel="next"/i', $p, $m)) return $m[1];
  }
  return null;
}

// ---------------------------
// Session config helpers
// ---------------------------
function get_session_config(string $defaultBase, string $defaultVer): array {
  $conf = $_SESSION['sraps'] ?? [];
  return [
    'baseUrl'   => isset($conf['baseUrl']) && $conf['baseUrl'] !== '' ? $conf['baseUrl'] : $defaultBase,
    'version'   => isset($conf['version']) && $conf['version'] !== '' ? $conf['version'] : $defaultVer,
    'companyId' => (string)($conf['companyId'] ?? ''),
    'hawkId'    => (string)($conf['hawkId'] ?? ''),
    'hawkKey'   => (string)($conf['hawkKey'] ?? ''),
  ];
}
function is_configured(array $conf): bool {
  return $conf['companyId'] !== '' && $conf['hawkId'] !== '' && $conf['hawkKey'] !== '';
}
function require_config_or_fail(array $conf): void {
  if (!is_configured($conf)) {
    json_response(401, ['error' => 'Not configured. Edit sraps.php and fill the HARD-CODED CREDENTIALS constants.']);
  }
}
function hardcoded_creds_available(): bool {
  return SRAPS_HARD_COMPANY_ID !== '' && SRAPS_HARD_HAWK_ID !== '' && SRAPS_HARD_HAWK_KEY !== '' &&
         strpos(SRAPS_HARD_COMPANY_ID, 'PUT_') !== 0 &&
         strpos(SRAPS_HARD_HAWK_ID, 'PUT_') !== 0 &&
         strpos(SRAPS_HARD_HAWK_KEY, 'PUT_') !== 0;
}
function autologin_from_hardcoded(): bool {
  if (!empty($_SESSION['sraps'])) return false;
  if (!hardcoded_creds_available()) return false;
  $_SESSION['sraps'] = [
    'baseUrl'   => SRAPS_HARD_BASE_URL ?: 'https://secure-provisioning.snom.com/api',
    'version'   => SRAPS_HARD_VERSION ?: 'v1',
    'companyId' => SRAPS_HARD_COMPANY_ID,
    'hawkId'    => SRAPS_HARD_HAWK_ID,
    'hawkKey'   => SRAPS_HARD_HAWK_KEY,
  ];
  return true;
}

// ---------------------------
// Hawk helpers
// ---------------------------
function canonical_content_type(string $contentType): string {
  if ($contentType === '') return '';
  $base = explode(';', $contentType, 2)[0];
  return strtolower(trim($base));
}
function hawk_payload_hash(string $payload, string $contentType, string $algorithm = 'sha256'): string {
  $normalized = "hawk.1.payload\n" . canonical_content_type($contentType) . "\n" . $payload . "\n";
  $digest = hash($algorithm, $normalized, true);
  return base64_encode($digest);
}
function hawk_header(string $id, string $key, string $method, string $url, ?string $payload = null, string $contentType = 'application/json', string $algorithm = 'sha256'): string {
  $parts = parse_url($url);
  if (!$parts) throw new RuntimeException("Invalid URL for Hawk signing: {$url}");
  $host = $parts['host'] ?? '';
  $scheme = strtolower($parts['scheme'] ?? 'https');
  $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
  $path = $parts['path'] ?? '/';
  $query = isset($parts['query']) ? ('?' . $parts['query']) : '';
  $requestUri = $path . $query;

  $ts = (string) time();
  $nonce = bin2hex(random_bytes(6));
  $hash = null;
  if ($payload !== null && $payload !== '') {
    $hash = hawk_payload_hash($payload, $contentType, $algorithm);
  }

  $normalized =
    "hawk.1.header\n{$ts}\n{$nonce}\n" . strtoupper($method) . "\n{$requestUri}\n{$host}\n{$port}\n" . ($hash ?? '') . "\n\n";
  $mac = base64_encode(hash_hmac($algorithm, $normalized, $key, true));

  $attrs = ['id' => $id, 'ts' => $ts, 'nonce' => $nonce, 'mac' => $mac];
  if ($hash !== null) $attrs['hash'] = $hash;

  $pairs = [];
  foreach ($attrs as $k => $v) {
    $pairs[] = $k . '="' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
  }
  return 'Hawk ' . implode(', ', $pairs);
}

// ---------------------------
// HTTP client (Hawk + cURL)
// ---------------------------
function hawk_request(string $method, string $pathOrUrl, ?array $body, string $baseRoot, string $acceptVersion, string $hawkId, string $hawkKey): array {
  $isAbsolute = (bool) preg_match('#^https?://#i', $pathOrUrl);
  $url = $isAbsolute ? $pathOrUrl : rtrim($baseRoot, '/') . '/' . ltrim($pathOrUrl, '/');

  $payload = null;
  $contentType = 'application/json';
  if ($body !== null) $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

  $auth = hawk_header($hawkId, $hawkKey, $method, $url, $payload, $contentType);
  $headersOut = [
    'Authorization: ' . $auth,
    'Accept: application/json; version=' . $acceptVersion,
    'User-Agent: SRAPS-PHP-Client/1.0',
  ];
  if ($payload !== null) $headersOut[] = 'Content-Type: ' . $contentType;

  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headersOut);
  curl_setopt($ch, CURLOPT_HEADER, false);
  curl_setopt($ch, CURLOPT_TIMEOUT, 30);
  if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

  $raw = curl_exec($ch);
  $errno = curl_errno($ch);
  $error = curl_error($ch);
  $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
  curl_close($ch);

  if ($errno !== 0) throw new RuntimeException("Request error: {$error}");

  $decoded = null;
  if (is_string($raw) && $raw !== '') {
    $maybe = json_decode($raw, true);
    if (json_last_error() === JSON_ERROR_NONE) $decoded = $maybe;
  }

  if ($status < 200 || $status >= 300) {
    $msg = is_string($raw) ? $raw : '';
    throw new RuntimeException("SRAPS {$method} {$url} failed: {$status} - {$msg}");
  }

  return ['status' => $status, 'data' => $decoded !== null ? $decoded : $raw];
}

// ---------------------------
// API endpoints
// ---------------------------
$action = $_GET['action'] ?? '';

if ($action === 'status') {
  $auto = autologin_from_hardcoded();
  $conf = get_session_config($DEFAULT_BASE_URL, $DEFAULT_VERSION);
  json_response(200, [
    'configured'  => is_configured($conf),
    'baseUrl'     => $conf['baseUrl'],
    'version'     => $conf['version'],
    'companyId'   => $conf['companyId'],
    'autoLogged'  => $auto,
    'hasHardcoded'=> hardcoded_creds_available(),
  ]);
}

if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  unset($_SESSION['sraps']);
  json_response(200, ['ok' => true]);
}

if ($action === 'profiles') {
  autologin_from_hardcoded();
  $conf = get_session_config($DEFAULT_BASE_URL, $DEFAULT_VERSION);
  require_config_or_fail($conf);
  $pageSize = isset($_GET['page_size']) && (int)$_GET['page_size'] > 0 ? (int)$_GET['page_size'] : 1000;
  $apiRoot = rtrim($conf['baseUrl'], '/') . '/' . ltrim($conf['version'], '/');

  try {
    $all = [];
    $url = "/companies/{$conf['companyId']}/provisioning-profiles/?page_size=" . $pageSize;
    $next = $url; $safety = 50;
    while ($next && $safety-- > 0) {
      $resp = hawk_request('GET', $next, null, $apiRoot, $conf['version'], $conf['hawkId'], $conf['hawkKey']);
      $data = $resp['data'];
      if (is_array($data)) {
        if (isset($data['results']) && is_array($data['results'])) {
          $all = array_merge($all, $data['results']);
          $next = !empty($data['next']) && is_string($data['next']) ? $data['next'] : null;
        } elseif (array_keys($data) === range(0, count($data) - 1)) {
          $all = array_merge($all, $data);
          $next = null;
        } else {
          $all[] = $data;
          $next = null;
        }
      } else {
        $next = null;
      }
    }
    json_response(200, $all);
  } catch (Throwable $e) {
    json_response(500, ['error' => $e->getMessage()]);
  }
}

if ($action === 'assign' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  autologin_from_hardcoded();
  $conf = get_session_config($DEFAULT_BASE_URL, $DEFAULT_VERSION);
  require_config_or_fail($conf);
  $apiRoot = rtrim($conf['baseUrl'], '/') . '/' . ltrim($conf['version'], '/');

  $in = read_json_input();

  $macRaw = (string)($in['mac'] ?? '');
  $mac = strtolower(preg_replace('/[^0-9A-Fa-f]/', '', $macRaw));
  if ($mac === '' || strlen($mac) !== 12) {
    json_response(400, ['error' => 'MAC must be 12 hex characters (lowercase).']);
  }

  $profileUuid = trim((string)($in['profileUuid'] ?? ''));
  if ($profileUuid === '') json_response(400, ['error' => 'Missing profile UUID.']);

  $autoProv = isset($in['autoprovisioning_enabled']) ? (bool)$in['autoprovisioning_enabled'] : true;
  $endpointName = trim((string)($in['name'] ?? ''));

  $settingsManager = null;
  if (!empty($in['settings_manager_json']) && is_string($in['settings_manager_json'])) {
    $decoded = json_decode($in['settings_manager_json'], true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded) || array_keys($decoded) === range(0, count($decoded)-1)) {
      json_response(400, ['error' => 'settings_manager_json must be a JSON object keyed by setting UUIDs.']);
    }
    $settingsManager = $decoded;
  }

  try {
    $payload = [
      'mac' => $mac,
      'autoprovisioning_enabled' => $autoProv,
      'provisioning_profile' => $profileUuid,
    ];
    if ($endpointName !== '') $payload['name'] = $endpointName;
    if ($settingsManager !== null) $payload['settings_manager'] = $settingsManager;

    $resp = hawk_request(
      'PUT',
      "/companies/{$conf['companyId']}/endpoints/" . rawurlencode($mac),
      $payload,
      $apiRoot,
      $conf['version'],
      $conf['hawkId'],
      $conf['hawkKey']
    );

    json_response(200, ['ok' => true, 'payload_sent' => $payload, 'endpoint' => $resp['data']]);
  } catch (Throwable $e) {
    json_response(500, ['error' => $e->getMessage()]);
  }
}

// ---------------------------
// HTML UI
// ---------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SRAPS: Hardcoded Creds → Select Profile → Assign MAC</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial, "Noto Sans"; margin: 2rem; line-height: 1.4; }
    .bar { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
    fieldset { margin-bottom: 2rem; padding: 1rem; }
    label { display: block; margin-top: 0.5rem; }
    input, select, button, textarea { font: inherit; padding: 0.4rem 0.5rem; margin-top: 0.25rem; min-width: 220px; }
    textarea { width: 100%; min-height: 120px; }
    .muted { opacity: 0.85; }
    .error { color: #b00020; white-space: pre-wrap; }
    .ok { color: #0b7a0b; }
    pre { overflow: auto; max-height: 400px; background: rgba(127,127,127,.08); padding: .75rem; }
    .disabled { opacity: 0.55; pointer-events: none; }
    .wide { min-width: 420px; }
    .badge { display:inline-block; padding:.2rem .5rem; border-radius:.4rem; background:#1b5e20; color:#fff; font-size:.85rem; }
    .warn { background:#9a6700; }
  </style>
</head>
<body>
  <div class="bar">
    <strong>Status:</strong>
    <span id="statusText" class="muted">Checking…</span>
    <button id="logoutBtn">Reset session</button>
    <span id="hardcodedBadge" class="badge" style="display:none;">Using hardcoded credentials</span>
    <span id="missingBadge" class="badge warn" style="display:none;">Edit sraps.php and fill HARD-CODED CREDENTIALS</span>
    <span id="baseInfo" class="muted"></span>
  </div>

  <fieldset id="profilesBox" class="disabled">
    <legend>1) Select a Provisioning Profile</legend>
    <div class="bar">
      <input id="profileFilter" type="text" placeholder="Filter profiles by name…" style="min-width:260px" />
      <button id="loadBtn">Load/Refresh profiles</button>
      <span><strong id="profilesCount">0</strong> profiles</span>
    </div>
    <label>Profiles
      <select id="profilesSelect" class="wide">
        <option value="">-- click "Load/Refresh profiles" --</option>
      </select>
    </label>
    <pre id="profilePreview" class="muted"></pre>
  </fieldset>

  <fieldset id="assignBox" class="disabled">
    <legend>2) Assign MAC to Selected Profile</legend>
    <div class="bar">
      <label>Endpoint MAC (12 hex, lower-case)
        <input id="macInput" type="text" placeholder="e.g., 001122aabbcc" />
      </label>
      <label>Autoprovisioning enabled
        <select id="autoProvInput">
          <option value="true" selected>true</option>
          <option value="false">false</option>
        </select>
      </label>
    </div>
    <div class="bar">
      <label>Endpoint name (optional)
        <input id="nameInput" type="text" placeholder="e.g., Front desk phone" />
      </label>
    </div>
    <details>
      <summary>Advanced: settings_manager JSON (optional)</summary>
      <p class="muted">JSON object keyed by setting UUIDs, e.g. {"50a4...":{"value":"...","attrs":{"perm":"RW"}}}</p>
      <textarea id="settingsManagerInput" placeholder='{"50a40056...":{"value":"setting-value","attrs":{"perm":"RW"}}}'></textarea>
    </details>
    <div class="bar">
      <button id="assignBtn">Assign MAC to profile</button>
    </div>
    <div id="assignResult"></div>
  </fieldset>

  <div id="errors" class="error"></div>

  <script>
    const $ = (id) => document.getElementById(id);

    // Status / Session
    const statusText = $('statusText');
    const baseInfo = $('baseInfo');
    const logoutBtn = $('logoutBtn');
    const hardcodedBadge = $('hardcodedBadge');
    const missingBadge = $('missingBadge');

    // Profiles UI
    const profilesBox = $('profilesBox');
    const profileFilter = $('profileFilter');
    const loadBtn = $('loadBtn');
    const profilesSelect = $('profilesSelect');
    const profilesCount = $('profilesCount');
    const profilePreview = $('profilePreview');

    // Assign UI
    const assignBox = $('assignBox');
    const macInput = $('macInput');
    const nameInput = $('nameInput');
    const autoProvInput = $('autoProvInput');
    const settingsManagerInput = $('settingsManagerInput');
    const assignBtn = $('assignBtn');
    const assignResult = $('assignResult');

    const errors = $('errors');

    let profiles = [];
    let filteredProfiles = [];

    function setError(err) { errors.textContent = err || ''; }
    function setEnabled(el, enabled) {
      el.classList.toggle('disabled', !enabled);
      el.querySelectorAll('input, select, button, textarea').forEach(n => n.disabled = !enabled);
    }

    async function refreshStatus() {
      setError('');
      try {
        const res = await fetch('?action=status', { method: 'GET' });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error || 'Failed to load status');

        statusText.textContent = data.configured
          ? `Logged in (company: ${data.companyId || 'unknown'})`
          : 'Not configured';
        baseInfo.textContent = `Base: ${data.baseUrl} | API: ${data.version}`;

        hardcodedBadge.style.display = data.hasHardcoded ? 'inline-block' : 'none';
        missingBadge.style.display = data.hasHardcoded ? 'none' : 'inline-block';

        setEnabled(profilesBox, data.configured);
        setEnabled(assignBox, data.configured);

        // Auto-load profiles once configured
        if (data.configured && profiles.length === 0) {
          await loadProfiles();
        }
      } catch (e) {
        statusText.textContent = 'Status error';
        setEnabled(profilesBox, false);
        setEnabled(assignBox, false);
        setError(String(e.message || e));
      }
    }

    async function loadProfiles() {
      setError(''); assignResult.innerHTML = '';
      profiles = []; filteredProfiles = [];
      profilesSelect.innerHTML = '<option value="">-- loading --</option>';
      profilesCount.textContent = '0'; profilePreview.textContent = '';

      const params = new URLSearchParams();
      params.set('page_size', '1000');

      const res = await fetch(`?action=profiles&${params.toString()}`, { method: 'GET' });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Failed to load profiles');

      profiles = Array.isArray(data) ? data : [];
      filteredProfiles = profiles.slice(0);
      renderProfiles();
    }

    function renderProfiles() {
      profilesCount.textContent = String(filteredProfiles.length);
      profilesSelect.innerHTML =
        '<option value="">-- select a profile --</option>' +
        filteredProfiles.map(p => {
          const uuid = p.uuid || p.uuid_v4 || '';
          const name = (p.name || p.uuid || '').replace(/</g, '&lt;');
          return `<option value="${uuid}">${name}</option>`;
        }).join('');
      profilePreview.textContent = '';
    }

    profileFilter.addEventListener('input', () => {
      const q = profileFilter.value.trim().toLowerCase();
      if (!q) {
        filteredProfiles = profiles.slice(0);
      } else {
        filteredProfiles = profiles.filter(p => {
          const name = (p.name || '').toLowerCase();
          const uuid = (p.uuid || p.uuid_v4 || '').toLowerCase();
          return name.includes(q) || uuid.includes(q);
        });
      }
      renderProfiles();
    });

    profilesSelect.addEventListener('change', () => {
      setError(''); assignResult.innerHTML = '';
      const uuid = profilesSelect.value;
      if (!uuid) { profilePreview.textContent = ''; return; }
      const profile = profiles.find(p => (p.uuid || p.uuid_v4) === uuid);
      profilePreview.textContent = JSON.stringify(profile ?? {}, null, 2);
    });

    loadBtn.addEventListener('click', async () => {
      try {
        await loadProfiles();
      } catch (e) {
        setError(String(e.message || e));
      }
    });

    logoutBtn.addEventListener('click', async () => {
      setError('');
      try {
        const res = await fetch('?action=logout', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error || 'Reset failed');
        profiles = []; filteredProfiles = [];
        renderProfiles();
        await refreshStatus();
      } catch (e) {
        setError(String(e.message || e));
      }
    });

    assignBtn.addEventListener('click', async () => {
      setError(''); assignResult.innerHTML = '';
      const uuid = profilesSelect.value;
      const mac = macInput.value.trim();
      if (!uuid) return setError('Please select a profile.');
      if (!mac) return setError('Please enter a MAC address (12 hex, lower-case).');

      const body = {
        profileUuid: uuid,
        mac,
        autoprovisioning_enabled: autoProvInput.value === 'true',
      };
      if (nameInput.value.trim()) body.name = nameInput.value.trim();
      if (settingsManagerInput.value.trim()) body.settings_manager_json = settingsManagerInput.value.trim();

      try {
        const res = await fetch('?action=assign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error || 'Failed to assign MAC to profile');
        assignResult.innerHTML = `<div class="ok">Endpoint created/updated and linked to profile.</div><pre>${JSON.stringify(data, null, 2)}</pre>`;
      } catch (e) {
        setError(String(e.message || e));
      }
    });

    // Initial
    refreshStatus();
  </script>
</body>
</html>