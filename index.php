<?php

declare(strict_types=1);
session_start();

require_once 'db.php';
$routes = [
    'GET' => [],
    'POST' => [],
    'PUT' => [],
    'DELETE' => [],
];

function get(string $path, callable $handler): void
{
    global $routes;
    $routes['GET'][$path] = $handler;
}

function post(string $path, callable $handler): void
{
    global $routes;
    $routes['POST'][$path] = $handler;
}

function dispatch(string $url, string $method): void
{
    global $routes;

    if (!isset($routes[$method])) {
        http_response_code(405);
        echo "Method $method Not Allowed";
        return;
    }

    foreach ($routes[$method] as $path => $handler) {
        if (preg_match("#^$path$#", $url, $matches)) {
            array_shift($matches);
            call_user_func_array($handler, $matches);
            return;
        }
    }

    http_response_code(404);
    handleNotFound();
}

function handleNotFound(): void
{
    echo "404 Not Found";
}

function generateCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function listen(): void
{
    $url = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'];

    get('/', 'home');
    post('/shorten', 'shortenUrl');
    get('/([a-zA-Z0-9]+)', 'redirectUrl');
    post('/v', 'middleware');

    dispatch($url, $method);
}

function home(): void
{
    middleware();
    $csrfToken = generateCsrfToken();
    echo '<form method="POST" action="/shorten">
            <input type="text" name="url" placeholder="Enter your URL" required>
            <input type="text" name="desired_short" placeholder="Enter custom short URL (optional)">
            <input type="hidden" name="csrf_token" value="' . htmlspecialchars($csrfToken) . '">
            <button type="submit">Shorten</button>
          </form>';
}

function shortenUrl(): void
{
    middleware();
    global $conn;

    $longUrl = $_POST['url'] ?? '';
    $desiredShort = $_POST['desired_short'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!validateCsrfToken($csrfToken)) {
        http_response_code(403);
        echo "Invalid CSRF token!";
        return;
    }

    if (empty($longUrl)) {
        echo "URL cannot be empty!";
        return;
    }

    if (!empty($desiredShort)) {
        if (checkIfShortExists($desiredShort)) {
            echo "Custom short URL already in use. Please choose another!";
            return;
        } else {
            $shortKey = $desiredShort;
        }
    } else {
        $shortKey = generateShortKey();
    }

    $stmt = $conn->prepare("INSERT INTO urls (original_url, short_key) VALUES (?, ?)");
    $stmt->bind_param("ss", $longUrl, $shortKey);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https://" : "http://";
        $host = $_SERVER['HTTP_HOST'];
        $shortenedUrl = $protocol . $host . "/$shortKey";
        
        echo "Shortened URL: <a href='$shortenedUrl'>$shortenedUrl</a>";
    } else {
        echo "Failed to shorten URL!";
    }

    $stmt->close();
}

function redirectUrl(string $shortKey): void
{
    global $conn;

    $stmt = $conn->prepare("SELECT original_url FROM urls WHERE short_key = ?");
    $stmt->bind_param("s", $shortKey);
    $stmt->execute();
    $stmt->bind_result($originalUrl);
    $stmt->fetch();
    $stmt->close();

    if ($originalUrl) {
        header("Location: " . $originalUrl);
        exit;
    } else {
        echo "URL not found!";
    }
}

function generateShortKey(): string
{
    return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 6);
}

function checkIfShortExists(string $shortKey): bool
{
    global $conn;

    $stmt = $conn->prepare("SELECT COUNT(*) FROM urls WHERE short_key = ?");
    $stmt->bind_param("s", $shortKey);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    return $count > 0;
}

function middleware()
{
    $hashed_password = '$2y$10$A5XBobk5O4dzipZSEIDEkeZggwzM/YaaqAuDP9mLAWjqQ6DM0kVIu';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_SESSION['original_password'])) {
        if (password_verify($_POST['password'], $hashed_password)) {
            $_SESSION['original_password'] = $_POST['password'];
            header('Location: /');
            exit;
        } else {
            echo 'Invalid password. Please try again.';
        }
    }

    if (!isset($_SESSION['original_password']) || !password_verify($_SESSION['original_password'], $hashed_password)) {
        echo '<form action="/v" method="post">
            <input type="password" name="password" id="password" placeholder="Password">
            <button type="submit">Unlock</button>
          </form>';
        exit;
    }
}


listen();
