<?php
/**
 * SECURITY NOTES (read before deploying):
 * 1. Update $ALLOWED_ORIGINS below to your real domain(s).
 * 2. Make sure data.json and login_attempts.json are NOT web-readable
 *    (the provided .htaccess blocks them — deploy it to the same folder).
 * 3. The old client-only "login" is gone. Real login now happens here,
 *    server-side, using a PHP session. The API key is kept only as a
 *    light extra check for the public read endpoint — it is NOT a
 *    substitute for the session check on anything that writes data.
 */

// Harden the session cookie itself: JS can't read it (HttpOnly), it isn't
// sent on cross-site requests except top-level navigation (SameSite=Lax,
// standard CSRF mitigation for this kind of same-site admin panel), and it
// only travels over HTTPS once the site is actually served over HTTPS.
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

$API_KEY = "MySecureKey2026"; // consider rotating this since it was previously exposed in page source
$DATA_FILE = __DIR__ . "/data.json";
$ATTEMPTS_FILE = __DIR__ . "/login_attempts.json";

// TODO: replace with your real domain(s). Needed because credentialed
// requests (the admin login/session cookie) cannot use "*".
$ALLOWED_ORIGINS = [
    "https://aswattv.vercel.app",
    "aswattv.vercel.app",
];

$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if (in_array($origin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
} else {
    // Fallback for the public, read-only channel list (no cookies involved).
    header("Access-Control-Allow-Origin: *");
}
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-API-Key");
header("Content-Type: application/json");

if ($_SERVER["REQUEST_METHOD"] == "OPTIONS") {
    exit(0);
}

function is_admin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

function check_api_key($API_KEY) {
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $key = isset($headers['X-Api-Key']) ? $headers['X-Api-Key'] : (isset($headers['X-API-Key']) ? $headers['X-API-Key'] : '');
    if ($key === '' && isset($_SERVER['HTTP_X_API_KEY'])) $key = $_SERVER['HTTP_X_API_KEY'];
    $key = (string)$key;
    if (function_exists('hash_equals')) {
        return hash_equals($API_KEY, $key);
    }
    // Fallback for PHP < 5.6, which doesn't have hash_equals().
    return $API_KEY === $key;
}

function load_data($DATA_FILE) {
    if (file_exists($DATA_FILE)) {
        $raw = file_get_contents($DATA_FILE);
        $data = json_decode($raw, true);
        if (is_array($data)) return $data;
    }
    return [
        "channels" => [],
        "username" => "admin",
        "password" => password_hash("changeme", PASSWORD_DEFAULT),
        "noticeText" => "Welcome to LiveTV!",
        "categories" => ["Uncategorized", "News", "Sports", "Entertainment"],
        "noticeActive" => true,
        "top20Channels" => [],
        "categoryVisibility" => [],
        "adEnabled" => ["banner" => true, "sidebar" => true, "instream" => true, "popunder" => true, "interstitial" => true, "native" => true],
        "telegramLink" => ""
    ];
}

function save_data($DATA_FILE, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT);
    return file_put_contents($DATA_FILE, $json, LOCK_EX) !== false;
}

// One-time migration: if password is still stored in plain text, hash it.
function ensure_password_hashed(&$data, $DATA_FILE) {
    if (isset($data['password']) && !preg_match('/^\$2[axy]\$/', $data['password'])) {
        $data['password'] = password_hash($data['password'], PASSWORD_DEFAULT);
        save_data($DATA_FILE, $data);
    }
}

// --- very small login rate limiter (per IP) ---
function too_many_attempts($ip, $ATTEMPTS_FILE) {
    $attempts = [];
    if (file_exists($ATTEMPTS_FILE)) {
        $attempts = json_decode(file_get_contents($ATTEMPTS_FILE), true) ?: [];
    }
    $now = time();
    if (isset($attempts[$ip])) {
        $entry = $attempts[$ip];
        if ($entry['count'] >= 5 && ($now - $entry['last']) < 900) { // 15 min lockout
            return true;
        }
        if (($now - $entry['last']) >= 900) {
            unset($attempts[$ip]); // window expired
            file_put_contents($ATTEMPTS_FILE, json_encode($attempts), LOCK_EX);
        }
    }
    return false;
}

function record_failed_attempt($ip, $ATTEMPTS_FILE) {
    $attempts = [];
    if (file_exists($ATTEMPTS_FILE)) {
        $attempts = json_decode(file_get_contents($ATTEMPTS_FILE), true) ?: [];
    }
    $now = time();
    if (!isset($attempts[$ip])) $attempts[$ip] = ['count' => 0, 'last' => $now];
    $attempts[$ip]['count'] += 1;
    $attempts[$ip]['last'] = $now;
    file_put_contents($ATTEMPTS_FILE, json_encode($attempts), LOCK_EX);
}

function clear_attempts($ip, $ATTEMPTS_FILE) {
    if (!file_exists($ATTEMPTS_FILE)) return;
    $attempts = json_decode(file_get_contents($ATTEMPTS_FILE), true) ?: [];
    unset($attempts[$ip]);
    file_put_contents($ATTEMPTS_FILE, json_encode($attempts), LOCK_EX);
}

$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
$method = $_SERVER["REQUEST_METHOD"];
$action = isset($_GET['action']) ? $_GET['action'] : null;

if (!check_api_key($API_KEY)) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid API Key"]);
    exit();
}

// ---------- LOGIN ----------
if ($method === "POST" && $action === "login") {
    if (too_many_attempts($ip, $ATTEMPTS_FILE)) {
        http_response_code(429);
        echo json_encode(["error" => "Too many attempts. Try again later."]);
        exit();
    }
    $input = json_decode(file_get_contents("php://input"), true);
    $username = isset($input['username']) ? trim($input['username']) : '';
    $password = isset($input['password']) ? (string)$input['password'] : '';

    $data = load_data($DATA_FILE);
    ensure_password_hashed($data, $DATA_FILE);

    if ($username !== '' && $username === $data['username'] && password_verify($password, $data['password'])) {
        clear_attempts($ip, $ATTEMPTS_FILE);
        session_regenerate_id(true);
        $_SESSION['is_admin'] = true;
        $_SESSION['username'] = $username;
        echo json_encode(["success" => true]);
    } else {
        record_failed_attempt($ip, $ATTEMPTS_FILE);
        http_response_code(401);
        echo json_encode(["error" => "Invalid username or password"]);
    }
    exit();
}

// ---------- LOGOUT ----------
if ($method === "POST" && $action === "logout") {
    $_SESSION = [];
    session_destroy();
    echo json_encode(["success" => true]);
    exit();
}

// ---------- SESSION CHECK ----------
if ($method === "GET" && $action === "session") {
    echo json_encode(["loggedIn" => is_admin()]);
    exit();
}

// ---------- PUBLIC READ (used by index.html — no credentials) ----------
if ($method === "GET" && $action === null) {
    // Legacy header-based key check kept as a light extra gate, but no
    // longer the only thing standing between a visitor and admin data:
    // this branch never returns username/password.
    $data = load_data($DATA_FILE);
    unset($data['username'], $data['password']);
    echo json_encode($data);
    exit();
}

// ---------- ADMIN READ (full data, requires real login) ----------
if ($method === "GET" && $action === "admin_data") {
    if (!is_admin()) {
        http_response_code(401);
        echo json_encode(["error" => "Not authenticated"]);
        exit();
    }
    $data = load_data($DATA_FILE);
    unset($data['password']); // never send the hash back to the browser
    echo json_encode($data);
    exit();
}

// ---------- SAVE (requires real login) ----------
// This endpoint NEVER changes the password, even if a "password" field is
// present in the payload — that closes the door on any accidental/autofill
// password field ending up here. Password changes only happen through
// action=change_password below, which verifies the current password first.
if ($method === "POST" && $action === "save") {
    if (!is_admin()) {
        http_response_code(401);
        echo json_encode(["error" => "Not authenticated"]);
        exit();
    }
    $rawBody = file_get_contents("php://input");
    if (strlen($rawBody) > 8 * 1024 * 1024) { // 8MB sanity cap
        http_response_code(413);
        echo json_encode(["error" => "Payload too large"]);
        exit();
    }
    $input = json_decode($rawBody, true);
    if (!$input || !isset($input["channels"]) || !is_array($input["channels"])) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid data"]);
        exit();
    }
    if (count($input["channels"]) > 20000) {
        http_response_code(400);
        echo json_encode(["error" => "Too many channels in one save"]);
        exit();
    }

    $existing = load_data($DATA_FILE);
    ensure_password_hashed($existing, $DATA_FILE);

    $newUsername = !empty($input['username']) ? trim($input['username']) : $existing['username'];

    $toSave = $input;
    unset($toSave['password']); // never accepted here, regardless of payload
    $toSave['username'] = $newUsername;
    $toSave['password'] = $existing['password'];

    if (save_data($DATA_FILE, $toSave)) {
        $_SESSION['username'] = $newUsername; // keep session in sync if username changed
        echo json_encode(["success" => true, "message" => "Data saved!"]);
    } else {
        http_response_code(500);
        echo json_encode(["error" => "Failed to save"]);
    }
    exit();
}

// ---------- CHANGE PASSWORD ----------
// Temporarily disabled: password changes go through the developer/manual
// process (data.json edited directly) until the cause of unexpected
// password changes on this device is fully resolved.
if ($method === "POST" && $action === "change_password") {
    http_response_code(403);
    echo json_encode(["error" => "Password changes are temporarily disabled. Contact support."]);
    exit();
}

// ---------- CHECK STREAM (requires login — verifies a channel URL is reachable) ----------
if ($method === "POST" && $action === "check_stream") {
    if (!is_admin()) {
        http_response_code(401);
        echo json_encode(["error" => "Not authenticated"]);
        exit();
    }
    $input = json_decode(file_get_contents("php://input"), true);
    $url = isset($input['url']) ? trim($input['url']) : '';
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        echo json_encode(["online" => false, "reason" => "invalid_url"]);
        exit();
    }

    $online = false;
    $reason = '';

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY => true,          // HEAD-style request — we only need the status code
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; StreamChecker/1.0)'
        ]);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($code >= 200 && $code < 400) {
            $online = true;
        } else if ($code === 0) {
            // Some IPTV/CDN servers reject HEAD requests outright — retry with a
            // partial GET before concluding the stream is actually down.
            $ch2 = curl_init($url);
            curl_setopt_array($ch2, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 8,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_RANGE => '0-2047',
                CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; StreamChecker/1.0)'
            ]);
            $body = curl_exec($ch2);
            $code2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
            $err = curl_error($ch2);
            curl_close($ch2);
            if (($code2 >= 200 && $code2 < 400) || (is_string($body) && strlen($body) > 0)) {
                $online = true;
            } else {
                $reason = $err ?: ('http_' . $code2);
            }
        } else {
            $reason = $err ?: ('http_' . $code);
        }
    } else {
        // cURL unavailable on this host — fall back to get_headers(), which
        // still needs allow_url_fopen enabled.
        if (ini_get('allow_url_fopen')) {
            $context = stream_context_create(['http' => ['timeout' => 6, 'method' => 'GET', 'header' => "Range: bytes=0-2047\r\n"]]);
            $headers = @get_headers($url, 0, $context);
            if ($headers && preg_match('#^HTTP/\S+\s+(\d+)#', $headers[0], $m)) {
                $code = (int)$m[1];
                $online = ($code >= 200 && $code < 400);
                if (!$online) $reason = 'http_' . $code;
            } else {
                $reason = 'unreachable';
            }
        } else {
            // This host allows neither cURL nor url fopen wrappers for outbound
            // requests — we genuinely cannot verify the stream from the server.
            // Report "unknown" rather than a false "offline".
            echo json_encode(["online" => null, "reason" => "outbound_requests_disabled_on_host"]);
            exit();
        }
    }

    echo json_encode(["online" => $online, "reason" => $reason]);
    exit();
}

// ---------- FETCH M3U (requires login — proxies an external playlist so the ----------
// ---------- browser doesn't hit CORS trying to fetch it directly) ----------
if ($method === "POST" && $action === "fetch_m3u") {
    if (!is_admin()) {
        http_response_code(401);
        echo json_encode(["error" => "Not authenticated"]);
        exit();
    }
    $input = json_decode(file_get_contents("php://input"), true);
    $url = isset($input['url']) ? trim($input['url']) : '';
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        echo json_encode(["success" => false, "error" => "Invalid URL"]);
        exit();
    }

    $content = false;
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; PlaylistImporter/1.0)'
        ]);
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($content === false || $code < 200 || $code >= 400) {
            echo json_encode(["success" => false, "error" => "Could not fetch that URL (HTTP $code)"]);
            exit();
        }
    } else if (ini_get('allow_url_fopen')) {
        $context = stream_context_create(['http' => ['timeout' => 15]]);
        $content = @file_get_contents($url, false, $context);
        if ($content === false) {
            echo json_encode(["success" => false, "error" => "Could not fetch that URL"]);
            exit();
        }
    } else {
        echo json_encode(["success" => false, "error" => "This server can't make outbound requests — paste the playlist text instead"]);
        exit();
    }

    if (strlen($content) > 6 * 1024 * 1024) {
        echo json_encode(["success" => false, "error" => "Playlist too large"]);
        exit();
    }

    echo json_encode(["success" => true, "content" => $content]);
    exit();
}

http_response_code(405);
echo json_encode(["error" => "Method not allowed"]);
