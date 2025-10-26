<?php
// sraps.php -- SRAPS API helper for SNOM provisioning

function sraps_log($msg) {
    @file_put_contents(__DIR__ . '/../provision_debug.log', date('c').' [SRAPS] '.$msg.PHP_EOL, FILE_APPEND);
}

function sraps_hawk_header($id, $key, $method, $url, $payload = null, $contentType = 'application/json', $algorithm = 'sha256') {
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
        $normalized = "hawk.1.payload\n" . strtolower(trim(explode(';',$contentType,2)[0])) . "\n" . $payload . "\n";
        $digest = hash($algorithm, $normalized, true);
        $hash = base64_encode($digest);
    }
    $normalized = "hawk.1.header\n{$ts}\n{$nonce}\n".strtoupper($method)."\n{$requestUri}\n{$host}\n{$port}\n".($hash ?? '')."\n\n";
    $mac = base64_encode(hash_hmac($algorithm, $normalized, $key, true));
    $attrs = ['id'=>$id,'ts'=>$ts,'nonce'=>$nonce,'mac'=>$mac];
    if ($hash !== null) $attrs['hash'] = $hash;
    $pairs = []; foreach ($attrs as $k=>$v) $pairs[] = $k.'="'.str_replace(['\\','"'],['\\\\','\\"'],$v).'"';
    return 'Hawk ' . implode(', ', $pairs);
}

function sraps_request($method, $url, $accessId, $secretKey, $body = null) {
    $payload = null; $contentType = 'application/json';
    if ($body !== null) $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $auth = sraps_hawk_header($accessId, $secretKey, $method, $url, $payload, $contentType);
    $headersOut = ['Authorization: '.$auth, 'Accept: application/json', 'User-Agent: SRAPS-PHP-Client/1.0'];
    if ($payload !== null) $headersOut[] = 'Content-Type: '.$contentType;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headersOut);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    $raw = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($errno !== 0) {
        sraps_log("Network error: {$error}");
        throw new RuntimeException("Network error: {$error}");
    }
    $decoded = null;
    if (is_string($raw) && $raw !== '') {
        $maybe = json_decode($raw, true);
        if (json_last_error() === JSON_ERROR_NONE) $decoded = $maybe;
    }
    if ($status < 200 || $status >= 300) {
        $msg = is_string($raw) ? $raw : '';
        sraps_log("SRAPS {$method} failed ({$status}): {$msg}");
        throw new RuntimeException("SRAPS {$method} failed ({$status}): {$msg}");
    }
    return ['status'=>$status, 'data'=>$decoded !== null ? $decoded : $raw];
}

function sraps_pick_category($model) {
    $up = strtoupper(trim($model));
    if (strpos($up, 'M500') === 0) return 'M500';
    if (strpos($up, 'M') === 0) return 'M';
    if (strpos($up, 'HOTEL') === 0 || strpos($up, 'H') === 0) return 'HOTEL';
    if (strpos($up, 'D') === 0) return 'D';
    return 'D';
}

function sraps_assign_device($conf, $macUpper, $model, $name = '', $profileOverride = null) {
    $mac = strtolower($macUpper);
    $profile = $profileOverride;
    if (!$profile) {
        $cat = sraps_pick_category($model);
        $profile = (string)($conf['profilesCat'][$cat] ?? '');
        if ($profile === '') throw new RuntimeException("No SRAPS profile mapped for category {$cat}");
    }
    $endpointUrl = rtrim($conf['baseUrl'], '/') . '/companies/' . rawurlencode((string)$conf['orgId']) . '/endpoints/' . rawurlencode($mac);
    $payload = ['mac'=>$mac, 'autoprovisioning_enabled'=>true, 'provisioning_profile'=>$profile];
    if ($name !== '') $payload['name'] = $name;
    sraps_log("Assign device: $mac model=$model profile=$profile name=$name");
    $resp = sraps_request('PUT', $endpointUrl, (string)$conf['accessKey'], (string)$conf['secretKey'], $payload);
    return $resp;
}

function sraps_release_device($conf, $macUpper) {
    $mac = strtolower($macUpper);
    $endpointUrl = rtrim($conf['baseUrl'], '/') . '/companies/' . rawurlencode((string)$conf['orgId']) . '/endpoints/' . rawurlencode($mac);
    sraps_log("Release device: $mac");
    $resp = sraps_request('DELETE', $endpointUrl, (string)$conf['accessKey'], (string)$conf['secretKey'], null);
    return $resp;
}

function sraps_test_connection($conf) {
    $url = rtrim($conf['baseUrl'], '/') . '/companies/' . rawurlencode((string)$conf['orgId']);
    sraps_log("Test connection to company: " . $conf['orgId']);
    return sraps_request('GET', $url, (string)$conf['accessKey'], (string)$conf['secretKey'], null);
}

// Robust profile fetching (walk all pages)
function sraps_resolve_profiles_url($companyData, $conf) {
    $links = $companyData['links'] ?? null;
    $candidates = [];
    if (is_array($links)) {
        foreach (['provisioning-profiles','provisioning_profiles','provisioningProfiles'] as $k) {
            if (isset($links[$k]) && is_string($links[$k]) && $links[$k] !== '') {
                $candidates[] = $links[$k];
            }
        }
        if (array_keys($links) === range(0, count($links)-1)) {
            foreach ($links as $lnk) {
                if (is_array($lnk)) {
                    $rel = strtolower((string)($lnk['rel'] ?? ''));
                    $href = (string)($lnk['href'] ?? '');
                    if ($href && (strpos($rel, 'provision') !== false && strpos($rel, 'profile') !== false)) {
                        $candidates[] = $href;
                    }
                }
            }
        }
        foreach ($links as $k=>$v) {
            if (is_string($v) && preg_match('#/provisioning-?profiles/?$#i', $v)) $candidates[] = $v;
        }
    }
    foreach ($candidates as $u) {
        if (is_string($u) && $u !== '') return $u;
    }
    return rtrim($conf['baseUrl'] ?? 'https://api.sraps.snom.com/api/v1/', '/') . '/companies/' . rawurlencode((string)($conf['orgId'] ?? '')) . '/provisioning-profiles/';
}
function sraps_next_url($data) {
    if (is_array($data)) {
        if (isset($data['next']) && is_string($data['next']) && $data['next'] !== '') return $data['next'];
        if (isset($data['links']['next']) && is_string($data['links']['next']) && $data['links']['next'] !== '') return $data['links']['next'];
        if (isset($data['next_page']) && is_string($data['next_page']) && $data['next_page'] !== '') return $data['next_page'];
    }
    return null;
}
function sraps_fetch_profiles($conf) {
    $companyUrl = rtrim($conf['baseUrl'], '/') . '/companies/' . rawurlencode((string)$conf['orgId']);
    $compResp = sraps_request('GET', $companyUrl, (string)$conf['accessKey'], (string)$conf['secretKey']);
    $company = is_array($compResp['data']) ? $compResp['data'] : [];
    $ppUrl = sraps_resolve_profiles_url($company, $conf);
    $out = []; $next = $ppUrl; $guard = 50;
    while ($next && $guard-- > 0) {
        $page = sraps_request('GET', $next, (string)$conf['accessKey'], (string)$conf['secretKey']);
        $data = $page['data'];
        if (isset($data['results']) && is_array($data['results'])) {
            $out = array_merge($out, $data['results']);
            $next = sraps_next_url($data);
        } elseif (is_array($data) && array_keys($data) === range(0, count($data)-1)) {
            $out = array_merge($out, $data);
            $next = null;
        } elseif (isset($data['items']) && is_array($data['items'])) {
            $out = array_merge($out, $data['items']);
            $next = sraps_next_url($data);
        } else {
            $out[] = $data;
            $next = null;
        }
    }
    $norm = [];
    foreach ($out as $p) {
        if (!is_array($p)) continue;
        $uuid = (string)($p['uuid'] ?? ($p['uuid_v4'] ?? ($p['id'] ?? '')));
        $name = (string)($p['name'] ?? ($p['display_name'] ?? $uuid));
        if ($uuid !== '') $norm[] = ['uuid'=>$uuid, 'name'=>$name] + $p;
    }
    return $norm;
}
?>