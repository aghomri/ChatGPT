<?php
// ---------------- CONFIG ----------------
ini_set('display_errors', '0');
ini_set('html_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

date_default_timezone_set('Europe/Paris');
$serverTz = new DateTimeZone('Europe/Paris');

$icsUrl = 'https://outlook.office365.com/owa/calendar/e23f869008814fb9ad169eae11628a69@snom.com/4defbc8a22ea477da3c19f48fd900ecc7079756916686865687/calendar.ics';
$cacheDir = __DIR__ . '/cache';
$globalIcsCacheFile = $cacheDir . '/ics_' . md5($icsUrl) . '.ics';
$debugLog = __DIR__ . '/snom_calendar_debug.log';
$globalIcsTtl = 3600;   // 1h
$microCacheTtl = 5;     // 5s

require_once 'vendor/autoload.php';
use Sabre\VObject;

// ---------------- UTILS ----------------
function dbg($m) {
    global $debugLog;
    @file_put_contents($debugLog, "[" . date('Y-m-d H:i:s') . "] $m\n", FILE_APPEND);
}

function xml_escape($s) {
    return htmlspecialchars($s, ENT_XML1 | ENT_COMPAT, 'UTF-8');
}

function self_base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
             (($_SERVER['SERVER_PORT'] ?? '') == '443');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    return $scheme . '://' . $host . ($path ? $path : '');
}

function ensure_cache_dir() {
    global $cacheDir;
    if (!is_dir($cacheDir)) @mkdir($cacheDir, 0755, true);
}

// ---------------- INIT ----------------
$q = isset($_GET['q']) ? trim($_GET['q']) : null;
$ready = isset($_GET['ready']);
$validQ = ($q && preg_match('/^\d{6}$/', $q));
$selfUrl = self_base_url() . '/' . basename(__FILE__);

dbg("Request: {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']} q=" . ($q ?? 'null') . " ready=" . ($ready ? '1' : '0'));

// ---------------- EXIT ACTION ----------------
if (isset($_GET['action']) && $_GET['action'] === 'clear_cache') {
    ensure_cache_dir();
    array_map('unlink', glob($cacheDir . '/*'));
    dbg("Cache cleared via Exit button");
    header('Content-Type: text/xml; charset=utf-8');
    echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";
    ?>
<SnomIPPhoneText>
  <Title>Exiting</Title>
  <Text>Cache cleared. Exiting...</Text>
  <fetch mil="1">snom://mb_exit</fetch>
</SnomIPPhoneText>
<?php
    exit;
}

// ---------------- INPUT SCREEN ----------------
if (!$validQ) {
    header('Content-Type: text/xml; charset=utf-8');
    $today = (new DateTime('now', $serverTz))->format('dmy');
    echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";
    ?>
<SnomIPPhoneInput>
  <Title>Calendar lookup</Title>
  <Prompt>Enter date (DDMMYY)</Prompt>
  <URL><?= xml_escape($selfUrl . '?q=$') ?></URL>

  <InputItem>
    <DisplayName>Date (DDMMYY)</DisplayName>
    <QueryStringParam>q</QueryStringParam>
    <DefaultValue></DefaultValue>
    <InputFlags>n</InputFlags>
  </InputItem>

  <!-- Softkeys -->
  <SoftKeyItem>
    <Name>F1</Name>
    <Label>Today</Label>
    <URL><?= xml_escape($selfUrl . '?q=' . $today . '&ready=1') ?></URL>
    <Action>SoftKey:Submit</Action>
  </SoftKeyItem>

  <SoftKeyItem>
    <Name>F2</Name>
    <Label>Backspace</Label>
    <Action>SoftKey:BackSpace</Action>
  </SoftKeyItem>

  <SoftKeyItem>
    <Name>F3</Name>
    <Label>Clear</Label>
    <Action>SoftKey:ClearInput</Action>
  </SoftKeyItem>

  <SoftKeyItem>
    <Name>F4</Name>
    <Label>Exit</Label>
    <URL><?= xml_escape($selfUrl . '?action=clear_cache') ?></URL>
    <Action>SoftKey:Submit</Action>
  </SoftKeyItem>
</SnomIPPhoneInput>
<?php
    exit;
}

// ---------------- LOADING SCREEN ----------------
if ($validQ && !$ready) {
    header('Content-Type: text/xml; charset=utf-8');
    echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";
    ?>
<SnomIPPhoneText>
  <Title>Loading</Title>
  <Text>Fetching data from server...</Text>
  <fetch mil="100"><?= xml_escape($selfUrl . '?q=' . $q . '&ready=1') ?></fetch>
</SnomIPPhoneText>
<?php
    exit;
}

// ---------------- CACHE ----------------
ensure_cache_dir();
$targetDate = DateTime::createFromFormat('dmy', $q, $serverTz);
$targetYmd = $targetDate->format('Ymd');
$microCacheFile = $cacheDir . '/micro_' . md5($icsUrl . $targetYmd) . '.xml';

if (file_exists($microCacheFile) && (time() - filemtime($microCacheFile)) < $microCacheTtl) {
    dbg("Micro-cache hit for $targetYmd");
    header('Content-Type: text/xml; charset=utf-8');
    readfile($microCacheFile);
    exit;
}

// ---------------- ICS FETCH ----------------
$ics = false;
if (file_exists($globalIcsCacheFile) && (time() - filemtime($globalIcsCacheFile)) < $globalIcsTtl) {
    $ics = @file_get_contents($globalIcsCacheFile);
    dbg("Global ICS cache hit");
}

if ($ics === false || $ics === '') {
    if (function_exists('curl_init')) {
        $ch = curl_init($icsUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'CalendarSnom/1.0 (+PHP)',
        ]);
        $data = curl_exec($ch);
        curl_close($ch);
        if ($data) {
            @file_put_contents($globalIcsCacheFile, $data, LOCK_EX);
            $ics = $data;
            dbg("Fetched ICS via cURL");
        } else {
            dbg("Failed to fetch ICS");
        }
    }
    if (!$ics) {
        header('Content-Type: text/xml; charset=utf-8');
        echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";
        ?>
<SnomIPPhoneText>
  <Title>Error</Title>
  <Text>Cannot fetch calendar.</Text>
  <SoftKeyItem><Name>F3</Name><Label>Retry</Label><URL><?= xml_escape($selfUrl) ?></URL></SoftKeyItem>
</SnomIPPhoneText>
<?php
        exit;
    }
}

// ---------------- PARSE EVENTS ----------------
$events = [];
try {
    $vcal = VObject\Reader::read($ics);
    $rangeStart = new DateTime('now', $serverTz);
    $rangeEnd = (clone $rangeStart)->modify('+1 year');

    foreach ($vcal->VEVENT as $ve) {
        $rrule = $ve->RRULE ?? null;
        $dtstart = $ve->DTSTART->getDateTime();
        $dtend = isset($ve->DTEND) ? $ve->DTEND->getDateTime() : null;
        if ($rrule) {
            $it = new VObject\Recur\EventIterator($vcal, (string)$ve->UID);
            $it->fastForward($rangeStart);
            while ($it->valid() && $it->getDTStart() <= $rangeEnd) {
                $start = $it->getDTStart();
                $end = $it->getDTEnd() ?? $start;
                $events[] = [
                    'ymd' => $start->format('Ymd'),
                    'time' => $start->format('H:i') . '-' . $end->format('H:i'),
                    'summary' => (string)$ve->SUMMARY,
                ];
                $it->next();
            }
        } else {
            $start = $dtstart;
            $end = $dtend ?? $start;
            $events[] = [
                'ymd' => $start->format('Ymd'),
                'time' => $start->format('H:i') . '-' . $end->format('H:i'),
                'summary' => (string)$ve->SUMMARY,
            ];
        }
    }
} catch (Exception $e) {
    dbg("ICS parse error: " . $e->getMessage());
}

// ---------------- OUTPUT ----------------
$found = array_filter($events, fn($e) => $e['ymd'] === $targetYmd);
header('Content-Type: text/xml; charset=utf-8');
ob_start();
echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";

if (empty($found)) {
    ?>
<SnomIPPhoneText>
  <Title><?= xml_escape("Calendar " . $targetDate->format('Y-m-d')) ?></Title>
  <Text>No events found.</Text>
  <SoftKeyItem><Name>F1</Name><Label>Previous</Label><URL><?= xml_escape($selfUrl . '?q=' . $targetDate->modify('-1 day')->format('dmy') . '&ready=1') ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F2</Name><Label>Next</Label><URL><?= xml_escape($selfUrl . '?q=' . $targetDate->modify('+2 day')->format('dmy') . '&ready=1') ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F3</Name><Label>Enter Date</Label><URL><?= xml_escape($selfUrl) ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F4</Name><Label>Exit</Label><URL><?= xml_escape($selfUrl . '?action=clear_cache') ?></URL></SoftKeyItem>
</SnomIPPhoneText>
<?php
} else {
    ?>
<SnomIPPhoneMenu>
  <Title><?= xml_escape("Calendar " . $targetDate->format('Y-m-d')) ?></Title>
  <?php foreach ($found as $e): ?>
  <MenuItem><Name><?= xml_escape($e['time'] . ' ' . $e['summary']) ?></Name></MenuItem>
  <?php endforeach; ?>
  <SoftKeyItem><Name>F1</Name><Label>Previous</Label><URL><?= xml_escape($selfUrl . '?q=' . $targetDate->modify('-1 day')->format('dmy') . '&ready=1') ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F2</Name><Label>Next</Label><URL><?= xml_escape($selfUrl . '?q=' . $targetDate->modify('+2 day')->format('dmy') . '&ready=1') ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F3</Name><Label>Enter Date</Label><URL><?= xml_escape($selfUrl) ?></URL></SoftKeyItem>
  <SoftKeyItem><Name>F4</Name><Label>Exit</Label><URL><?= xml_escape($selfUrl . '?action=clear_cache') ?></URL></SoftKeyItem>
</SnomIPPhoneMenu>
<?php
}
$output = ob_get_clean();
echo $output;
@file_put_contents($microCacheFile, $output, LOCK_EX);

dbg("Finished request for q=$q");
?>