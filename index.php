<?php

class UrlShortener
{
    private string $api = 'http://localhost/urls-api/';

    public function handleRequest()
    {
        if (isset($_GET['page'])) {
            $page = $_GET['page'];
            switch ($page) {
                case 'home':
                    $this->homepage($this->api);
                    break;
                case 'register':
                    $this->registerPage();
                    break;
                case 'login':
                    $this->loginPage();
                    break;
                case 'logout':
                    $this->userLogoutHandle();
                    break;
                case 'userLoginHandle':
                    $this->userLoginHandle($this->api);
                    break;
                case 'addUrlsHandle':
                    $this->addUrlsHandle($this->api);
                    break;
                case 'add':
                    $this->addUrlsPage();
                    break;
                case 'edit':
                    $this->editUrlsPage($this->api);
                    break;
                case 'delete':
                    $this->deleteUrlsHandle($this->api);
                    break;
                case 'update':
                    $this->updateUrlsHandle($this->api);
                    break;
                case 'userRegisterHandle':
                    $this->userRegisterHandle($this->api);
                default:
                    $this->redirect($this->api, $page);
                    break;
            }
        } else {
            $this->homepage($this->api);
        }
    }

    public function retrunHome()
    {
        header("Location: home");
        exit();
    }

    public function navbar()
    {
?>
        <nav class="navbar navbar-expand-lg bg-body-tertiary">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">Navbar</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link active" aria-current="page" href="home">Home</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="add">Add</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="logout">Logout</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    <?php
    }

    public function bootstrapHead($title)
    {
    ?>
        <!doctype html>
        <html lang="en">

        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo $title; ?></title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
        </head>

        <body>

        <?php
    }

    public function bootstrapFoot()
    {
        ?>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
        </body>

        </html>
        <?php

    }

    private function redirect($api, $short)
    {
        $apiUrl = $api . 'url/' . $short;
        $response = @file_get_contents($apiUrl);
        $error = error_get_last();
        if ($error !== null && $error['type'] === E_WARNING) {
            $this->nf404Page();
            exit;
        }
        $data = json_decode($response, true);
        if (isset($data['orurl'])) {
            $originalUrl = $data['orurl'];
            header("Location: $originalUrl");
            exit;
        } else {
            echo "Error: Unable to retrieve original URL.";
        }
    }

    private function nf404Page()
    {
        echo "Not Found";
    }

    private function homepage($api)
    {
        session_start();
        if (isset($_SESSION['user_token'])) {
            $token = $_SESSION['user_token'];
            $url = $api . "/home/index.php?token=" . urlencode($token);
            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            $json_response = curl_exec($curl);
            if ($json_response === false) {
                echo "Error fetching JSON: " . curl_error($curl);
            } else {
                $decoded_data = json_decode($json_response, true);

                if ($decoded_data === null) {
                    echo "Error decoding JSON: " . json_last_error_msg();
                } else {
                    if (isset($decoded_data['error']) && $decoded_data['error'] === 'User not found') {
                        echo 'No data found <a href="add">add</a>!';
                    } else {
                        $this->bootstrapHead("Home");
                        $this->navbar();
        ?> <table class="table">
                            <tr>
                                <th>ID</th>
                                <th>Original URL</th>
                                <th>Short URL</th>
                                <th>Edit</th>
                                <th>Delete</th>
                            </tr>
                            <?php
                            foreach ($decoded_data as $record) {
                            ?>
                                <td><?php echo $record['id'] ?></td>
                                <td><?php echo $record['orurl'] ?></td>
                                <td><?php echo $record['shurl'] ?></td>
                                <td><a class="btn btn-dark" href='edit&id=<?php echo $record['id'] ?>'>Edit</a></td>
                                <td>
                                    <form action='delete' method='post'>
                                        <input type='hidden' name='id' value='<?php echo $record['id'] ?>'>
                                        <input class="btn btn-danger" type='submit' value='Delete'>
                                    </form>
                                </td>
                                </tr>
                <?php
                            }

                            echo "</table>";
                            $this->bootstrapFoot();
                        }
                    }
                }

                curl_close($curl);
            } else {
                $this->bootstrapHead("Home");
                ?>
                <p>Please <a href="login">Login</a> or <a href="register">Register</a> First. </p>
            <?php
                $this->bootstrapFoot();
            }
        }


        private function registerPage()
        {
            $this->bootstrapHead("Register");
            ?>
            <div class="container">
                <h2 class="pt-4">Register</h2>
                <form action="userRegisterHandle" method="post">
                    <label for="username">Username:</label>
                    <br>
                    <input class="form-control" type="text" id="username" name="username" required>
                    <br>
                    <label for="email">Email:</label>
                    <br>
                    <input class="form-control" type="email" id="email" name="email" required>
                    <br>
                    <label for="password">Password:</label>
                    <br>
                    <input class="form-control" type="password" id="password" name="password" required>
                    <br>
                    <input type="submit" class="btn btn-dark" value="Register">
                </form>
            </div>
        <?php
            $this->bootstrapFoot();
        }

        private function userRegisterHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $email = $_POST['email'];
                $username = $_POST['username'];
                $password = $_POST['password'];
                $postData = array(
                    'email' => $email,
                    'username' => $username,
                    'password' => $password
                );
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . 'register/');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function loginPage()
        {
            $this->bootstrapHead("Login");
        ?>
            <div class="container">
                <h2 class="pt-4">Login</h2>
                <form id="loginForm" action="userLoginHandle" method="post">
                    <label for="email">Email:</label><br>
                    <input class="form-control" type="email" id="email" name="email" required><br>
                    <label for="password">Password:</label><br>
                    <input class="form-control" type="password" id="password" name="password" required><br>
                    <input type="submit" class="btn btn-dark" value="Login">
                </form>
            </div>
        <?php
            $this->bootstrapFoot();
        }

        private function userLoginHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $email = $_POST['email'];
                $password = $_POST['password'];
                $postData = array(
                    'email' => $email,
                    'password' => $password
                );
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . 'mytoken/');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    session_start();
                    $_SESSION['user_token'] = $responseData['user_token'];
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function userLogoutHandle()
        {
            session_start();
            session_destroy();
            $this->retrunHome();
        }

        private function addUrlsPage()
        {
            $this->bootstrapHead("Add URL");
            $this->navbar();
        ?>
            <div class="container">
                <h2 class="pt-4">Add URL</h2>
                <form action="addUrlsHandle" method="post">
                    <label for="email">Original URL:</label><br>
                    <input class="form-control" type="text" id="original_url" name="original_url" required><br>
                    <label for="password">Short URL:</label><br>
                    <input class="form-control" type="text" id="short_url" name="short_url" required><br>
                    <input class="btn btn-dark" type="submit" value="Add">
                </form>
            </div>
            <?php
        }

        private function addUrlsHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                session_start();
                $token = $_SESSION['user_token'];
                $original_url = $_POST['original_url'];
                $short_url = $_POST['short_url'];
                $postData = array(
                    'token' => $token,
                    'original_url' => $original_url,
                    'short_url' => $short_url
                );
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . 'create/');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function editUrlsPage($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'GET') {
                session_start();
                $id = $_GET['id'];
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . "detail/?id=$id");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    $original_url = $responseData['orurl'];
                    $short_url = $responseData['shurl'];
                    $this->bootstrapHead("Edit URL");
                    $this->navbar();
            ?>

                    <div class="container">
                        <h2 class="pt-4">Edit Page</h2>
                        <form action="update" method="post">
                            <label for="orurl">Original URL:</label>
                            <input type="hidden" id="id" name="id" value="<?php echo $id; ?>" required><br>
                            <input class="form-control" type="text" id="orurl" name="orurl" value="<?php echo $original_url; ?>" required><br>
                            <label for="shurl">Short URL:</label><br>
                            <input class="form-control" type="text" id="shurl" name="shurl" value="<?php echo $short_url; ?>" required><br>
                            <input class="btn btn-dark" type="submit" value="Update">
                        </form>
                    </div>
    <?php
                    $this->bootstrapFoot();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function updateUrlsHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                session_start();
                $token = $_SESSION['user_token'];
                $id = $_POST['id'];
                $original_url = $_POST['orurl'];
                $short_url = $_POST['shurl'];
                $postData = array(
                    'token' => $token,
                    'id' => $id,
                    'orurl' => $original_url,
                    'shurl' => $short_url
                );
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . 'update/');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function deleteUrlsHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                session_start();
                $token = $_SESSION['user_token'];
                $id = $_POST['id'];
                $postData = array(
                    'token' => $token,
                    'id' => $id,
                );
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $api . 'delete/');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $response = curl_exec($ch);
                curl_close($ch);
                $responseData = json_decode($response, true);
                if ($responseData !== null) {
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }
    }

    $urlManager = new UrlShortener();
    $urlManager->handleRequest();
