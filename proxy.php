<?php
/**
 * Minimal HLS-aware reverse proxy.
 *
 * Why this exists: some IPTV/CDN sources refuse direct browser requests —
 * they check the Referer/Origin header, or just don't send CORS headers at
 * all, so hls.js/JW Player can load the stream everywhere except a page on
 * a different domain. Other IPTV sites that "just work" are almost always
 * doing exactly this: fetching the stream server-side and re-serving it,
 * so the browser only ever talks to their own domain.
 *
 * This proxy fetches the target URL from the server (with a normal browser
 * User-Agent and a same-origin Referer), and if it's an HLS playlist,
 * rewrites every segment/sub-playlist URI to route back through this same
 * proxy — so the player never has to reach the original CDN directly.
 *
 * Usage: proxy.php?url=<base64url-encoded target URL>
 */

header("Access-Control-Allow-Origin: *");

function proxy_encode($url) {
    return rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
}
function proxy_decode($str) {
    $str = strtr($str, '-_', '+/');
    $padding = 4 - (strlen($str) % 4);
    if ($padding !== 4) {
        $str .= str_repeat('=', $padding);
    }
    return base64_decode($str);
}
function resolve_url($base, $rel) {
    if (preg_match('#^https?://#i', $rel)) return $rel;
    $parts = parse_url($base);
    $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'https';
    $host = isset($parts['host']) ? $parts['host'] : '';
    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    if (substr($rel, 0, 1) === '/') {
        return "$scheme://$host$port$rel";
    }
    $path = isset($parts['path']) ? $parts['path'] : '/';
    $dir = substr($path, 0, strrpos($path, '/') + 1);
    return "$scheme://$host$port$dir$rel";
}

$target = isset($_GET['url']) ? proxy_decode($_GET['url']) : '';
if (!$target || !preg_match('#^https?://#i', $target)) {
    http_response_code(400);
    echo "Invalid target URL";
    exit;
}

// Basic SSRF guard — don't let this be used to reach internal/private hosts.
$hostCheck = parse_url($target, PHP_URL_HOST);
if (!$hostCheck || preg_match('/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/i', $hostCheck)) {
    http_response_code(400);
    echo "Blocked target host";
    exit;
}

if (!function_exists('curl_init') && !ini_get('allow_url_fopen')) {
    http_response_code(500);
    echo "Proxy unavailable on this server (no cURL or allow_url_fopen)";
    exit;
}

$originHeader = parse_url($target, PHP_URL_SCHEME) . '://' . parse_url($target, PHP_URL_HOST);
$body = false;
$httpCode = 0;
$contentType = '';
$curlErr = '';

if (function_exists('curl_init')) {
    $ch = curl_init($target);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => 6,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        CURLOPT_HTTPHEADER => ['Referer: ' . $originHeader . '/']
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $curlErr = curl_error($ch);
    curl_close($ch);
} elseif (ini_get('allow_url_fopen')) {
    $opts = [
        'http' => [
            'timeout' => 15,
            'header' => "Referer: " . $originHeader . "/
" .
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
"
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ];
    $body = @file_get_contents($target, false, stream_context_create($opts));
    if ($body !== false) {
        $httpCode = 200;
    }
}

if ($body === false || $httpCode >= 400 || $httpCode === 0) {
    http_response_code(502);
    $msg = "Upstream error";
    if ($httpCode == 404) $msg = "Stream not found (404) — channel offline or URL changed";
    elseif ($httpCode == 403) $msg = "Access denied (403) — stream blocks proxy";
    elseif ($httpCode == 0) $msg = "Cannot connect to stream server";
    echo $msg . ($curlErr ? ": $curlErr" : " (HTTP $httpCode)");
    exit;
}

$isPlaylist = (stripos((string)$contentType, 'mpegurl') !== false) || (strpos(ltrim($body), '#EXTM3U') === 0);

if ($isPlaylist) {
    header('Content-Type: application/vnd.apple.mpegurl');
    header('Cache-Control: no-cache');
    $lines = explode("\n", str_replace("\r\n", "\n", $body));
    $out = [];
    foreach ($lines as $line) {
        $trimmed = rtrim($line, "\r");
        if ($trimmed === '') { $out[] = $trimmed; continue; }
        if ($trimmed[0] === '#') {
            // Rewrite EXT-X-KEY / EXT-X-MAP URI="..." attributes too.
            if (preg_match('/URI="([^"]+)"/', $trimmed, $m)) {
                $abs = resolve_url($target, $m[1]);
                $trimmed = str_replace($m[1], 'proxy.php?url=' . proxy_encode($abs), $trimmed);
            }
            $out[] = $trimmed;
        } else {
            $abs = resolve_url($target, $trimmed);
            $out[] = 'proxy.php?url=' . proxy_encode($abs);
        }
    }
    echo implode("\n", $out);
} else {
    header('Content-Type: ' . ($contentType ?: 'video/MP2T'));
    header('Cache-Control: no-cache');
    header('Content-Length: ' . strlen($body));
    echo $body;
}
