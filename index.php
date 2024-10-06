<?php

declare(strict_types=1);

// Start the session to use session variables
session_start();

// Database connection
$servername = "localhost";
$username = "skibidi";
$password = "skibidi";
$dbname = "skibidi";
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize the routes
$routes = [
    'GET' => [],
    'POST' => [],
    'PUT' => [],
    'DELETE' => [],
];

// Add a route for a specific HTTP method
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

// Match the request URL and method, then handle it
function dispatch(string $url, string $method): void
{
    global $routes;

    if (!isset($routes[$method])) {
        http_response_code(405); // Method Not Allowed
        echo "Method $method Not Allowed";
        return;
    }

    foreach ($routes[$method] as $path => $handler) {
        if (preg_match("#^$path$#", $url, $matches)) {
            array_shift($matches); // Remove full match
            call_user_func_array($handler, $matches);
            return;
        }
    }

    http_response_code(404);
    handleNotFound();
}

// Default 404 handler
function handleNotFound(): void
{
    echo "404 Not Found";
}

// Generate a CSRF token and store it in the session
function generateCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate the CSRF token from the request
function validateCsrfToken(string $token): bool
{
    // Check if the CSRF token exists in the session before comparing
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Register all routes and handle the current request
function listen(): void
{
    $url = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'];

    // Define routes
    get('/', 'home');
    post('/shorten', 'shortenUrl');
    get('/([a-zA-Z0-9]+)', 'redirectUrl'); // Short URL handler

    // Dispatch the request
    dispatch($url, $method);
}

// Example handlers
function home(): void
{
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
    global $conn;

    $longUrl = $_POST['url'] ?? '';
    $desiredShort = $_POST['desired_short'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    // Validate CSRF token
    if (!validateCsrfToken($csrfToken)) {
        http_response_code(403);
        echo "Invalid CSRF token!";
        return;
    }

    if (empty($longUrl)) {
        echo "URL cannot be empty!";
        return;
    }

    // Validate the custom short key if provided
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

    // Save to database
    $stmt = $conn->prepare("INSERT INTO urls (original_url, short_key) VALUES (?, ?)");
    $stmt->bind_param("ss", $longUrl, $shortKey);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        // Construct the shortened URL
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https://" : "http://";
        $host = $_SERVER['HTTP_HOST'];
        $shortenedUrl = $protocol . $host . "/$shortKey";
        
        echo "Shortened URL: <a href='$shortenedUrl'>$shortenedUrl</a>";
    } else {
        echo "Failed to shorten URL!";
    }

    $stmt->close();
}

// Redirect from short URL to the original URL
function redirectUrl(string $shortKey): void
{
    global $conn;

    // Retrieve the original URL from the database
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

// Generate a short key (6 characters)
function generateShortKey(): string
{
    return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 6);
}

// Check if the custom short key already exists in the database
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

// Start listening for incoming requests
listen();
