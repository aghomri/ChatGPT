<?php
// Minimal SRAPS Hawk client used by both extensions.php and dect.php
// No dependency on sraps.php. Reads credentials from $wiz['sraps'].

// Return shape for HTTP calls:
// ['ok'=>bool,'code'=>int,'data'=>mixed|null,'error'=>string|null]

if (!function_exists('sr_canonical_content_type')) {
    function sr_canonical_content_type(string $contentType): string {
        if ($contentType === '') return '';
        $base = explode(';', $contentType, 2)[0];
        return strtolower(trim($base));
    }
}
if (!function_exists('sr_hawk_payload_hash')) {
    function sr_hawk_payload_hash(string $payload, string $contentType, string $algorithm = 'sha256'): string {
        $normalized = "hawk.1.payload\n" . sr_canonical_content_type($contentType) . "\n" . $payload . "\n";
        $digest = hash($algorithm, $normalized, true);
        return base64_encode($digest);
    }
}
if (!function_exists('sr_hawk_header')) {
    function sr_hawk_header(string $id, string $key, string $method, string $url, ?string $payload = null, string $contentType = 'application/json', string $algorithm = 'sha256'): string {
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
            $hash = sr_hawk_payload_hash($payload, $contentType, $algorithm);
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
}
if (!function_exists('sr_sraps_request')) {
    function sr_sraps_request(string $method, string $pathOrUrl, ?array $body, string $baseRoot, string $acceptVersion, string $hawkId, string $hawkKey): array {
        $isAbsolute = (bool) preg_match('#^https?://#i', $pathOrUrl);
        $url = $isAbsolute ? $pathOrUrl : rtrim($baseRoot, '/') . '/' . ltrim($pathOrUrl, '/');

        $payload = null;
        $contentType = 'application/json';
        if ($body !== null) $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $auth = sr_hawk_header($hawkId, $hawkKey, $method, $url, $payload, $contentType);
        $headersOut = [
            'Authorization: ' . $auth,
            'Accept: application/json; version=' . $acceptVersion,
            'User-Agent: Extensions-SRAPS-Client/1.0',
        ];
        if ($payload !== null) $headersOut[] = 'Content-Type: ' . $contentType;

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headersOut);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 25);
        if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

        $raw = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($errno !== 0) return ['ok'=>false,'code'=>0,'data'=>null,'error'=>"cURL error: {$error}"];

        $decoded = null;
        if (is_string($raw) && $raw !== '') {
            $maybe = json_decode($raw, true);
            if (json_last_error() === JSON_ERROR_NONE) $decoded = $maybe;
        }
        if ($status < 200 || $status >= 300) {
            $msg = is_string($raw) ? $raw : '';
            if (is_array($decoded) && isset($decoded['error'])) {
                $msg = is_string($decoded['error']) ? $decoded['error'] : json_encode($decoded['error']);
            }
            return ['ok'=>false,'code'=>$status,'data'=>$decoded,'error'=>$msg ?: ('HTTP '.$status)];
        }
        return ['ok'=>true,'code'=>$status,'data'=>($decoded ?? $raw),'error'=>null];
    }
}

// Helpers bound to $wiz['sraps']
if (!function_exists('sr_sraps_ready')) {
    function sr_sraps_ready(array $wiz): bool {
        $s = $wiz['sraps'] ?? [];
        return !empty($s['api_base']) && !empty($s['api_version']) && !empty($s['company_id']) && !empty($s['hawk_id']) && !empty($s['hawk_key']);
    }
}
if (!function_exists('sr_sraps_root')) {
    function sr_sraps_root(array $wiz): string {
        $s = $wiz['sraps'];
        return rtrim((string)$s['api_base'],'/').'/'.ltrim((string)$s['api_version'],'/');
    }
}
if (!function_exists('sr_sraps_pick_profile_uuid')) {
    // defaultCategory is which mapping to prefer when model doesn't clearly indicate
    function sr_sraps_pick_profile_uuid(array $wiz, string $model, string $defaultCategory = 'mseries'): ?string {
        $map = $wiz['sraps']['profile_map'] ?? [];
        $m = strtoupper(trim($model));
        if ($m === '') return ($map[$defaultCategory] ?? '') ?: '';
        // Simple mapping: D* => dseries, M500* => m500, M* => mseries, else => defaultCategory
        if (str_starts_with($m,'D'))    return $map['dseries'] ?? '';
        if (str_starts_with($m,'M500')) return $map['m500']    ?? '';
        if (str_starts_with($m,'M'))    return $map['mseries'] ?? '';
        return $map[$defaultCategory] ?? '';
    }
}
if (!function_exists('sr_sraps_assign')) {
    function sr_sraps_assign(array $wiz, string $macUpper, string $profileUuid, string $name = ''): array {
        $mac_lc = strtolower($macUpper);
        $root = sr_sraps_root($wiz);
        $ver  = (string)$wiz['sraps']['api_version'];
        $company = (string)$wiz['sraps']['company_id'];
        $hid  = (string)$wiz['sraps']['hawk_id'];
        $hkey = (string)$wiz['sraps']['hawk_key'];
        $payload = [
            'mac' => $mac_lc,
            'autoprovisioning_enabled' => true,
            'provisioning_profile' => $profileUuid,
        ];
        if ($name !== '') $payload['name'] = $name;
        return sr_sraps_request('PUT', "/companies/{$company}/endpoints/".rawurlencode($mac_lc), $payload, $root, $ver, $hid, $hkey);
    }
}
if (!function_exists('sr_sraps_delete')) {
    function sr_sraps_delete(array $wiz, string $macUpper): array {
        $mac_lc = strtolower($macUpper);
        $root = sr_sraps_root($wiz);
        $ver  = (string)$wiz['sraps']['api_version'];
        $company = (string)$wiz['sraps']['company_id'];
        $hid  = (string)$wiz['sraps']['hawk_id'];
        $hkey = (string)$wiz['sraps']['hawk_key'];
        return sr_sraps_request('DELETE', "/companies/{$company}/endpoints/".rawurlencode($mac_lc), null, $root, $ver, $hid, $hkey);
    }
}