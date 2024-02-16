<?php

class UrlShortener
{
    private string $api = 'http://localhost/urls-api/';

    public function __construct()
    {
        session_start();
    }

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
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark p-3">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">URLS</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>

                <div class=" collapse navbar-collapse" id="navbarNavDropdown">
                    <ul class="navbar-nav ms-auto ">
                        <li class="nav-item">
                            <a class="nav-link mx-2 active" aria-current="page" href="/">Home</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link mx-2" href="add">Add</a>
                        </li>
                        <li class="nav-item dropdown">
                            <a class="nav-link mx-2 dropdown-toggle" href="#" id="navbarDropdownMenuLink" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <?php echo $_SESSION['user_name'] ?>
                            </a>
                            <ul class="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                                <li><a class="dropdown-item" href="logout">Logout</a></li>
                            </ul>
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
                                <td><a href="<?php echo $record['orurl'] ?>"><?php echo $record['orurl'] ?></a></td>
                                <td><?php echo 'urls.baguswinaksono.my.id/' . $record['shurl'] ?></td>
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

            <div class="container d-flex justify-content-center align-items-center vh-100">
                <form action="userRegisterHandle" method="post" class="mx-auto" style="width: 500px;">
                    <div class="mb-3">
                        <label for="fullname" class="form-label">
                            Username </label>
                        <input type="text" name="username" class="form-control">
                    </div>
                    <div class="mb-3">
                        <label for="username" class="form-label">
                            Email Address </label>
                        <input type="email" name="mail" class="form-control">
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">
                            Password </label>
                        <input type="password" name="password" class="form-control">
                    </div>
                    <button type="submit" class="btn btn-dark">Submit</button>
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

            <div class="container d-flex justify-content-center align-items-center vh-100">
                <form action="userLoginHandle" method="post" class="mx-auto" style="width: 500px;">

                    <div class="mb-3">
                        <label for="username" class="form-label">
                            Email Address </label>
                        <input type="email" name="email" class="form-control" id="email">
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">
                            Password </label>
                        <input type="password" name="password" class="form-control" id="password">
                    </div>
                    <button type="submit" class="btn btn-dark">Submit</button>
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
                    $_SESSION['user_token'] = $responseData['user_token'];
                    $_SESSION['user_name'] = $responseData['user_name'];
                    $this->retrunHome();
                } else {
                    $this->retrunHome();
                }
            }
        }

        private function userLogoutHandle()
        {
            session_destroy();
            $this->retrunHome();
        }

        private function addUrlsPage()
        {
            $this->bootstrapHead("Add URL");
            $this->navbar();
        ?>
            <div class="container d-flex justify-content-center align-items-center" style="height: 80vh">
                <form action="addUrlsHandle" method="post" class="mx-auto" style="width: 500px;">

                    <div class="mb-3">
                        <label for="original_url" class="form-label">
                            Original Url </label>
                        <input type="text" name="original_url" class="form-control" id="original_url">
                    </div>
                    <div class="mb-3">
                        <label for="short_url" class="form-label">
                            Short Url </label>
                        <input type="text" name="short_url" class="form-control" id="short_url">
                    </div>
                    <button type="submit" class="btn btn-dark">Submit</button>
                </form>
            </div>
            <?php
        }

        private function addUrlsHandle($api)
        {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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
                    <div class="container d-flex justify-content-center align-items-center" style="height: 80vh">
                        <form action="update" method="post" class="mx-auto" style="width: 500px;">
                            <input type="hidden" id="id" name="id" value="<?php echo $id; ?>" required>
                            <div class="mb-3">
                                <label for="orurl" class="form-label">
                                    Original Url </label>
                                <input type="text" name="orurl" class="form-control" id="orurl" value="<?php echo $original_url; ?>">
                            </div>
                            <div class="mb-3">
                                <label for="shurl" class="form-label">
                                    Short Url </label>
                                <input type="text" name="shurl" class="form-control" id="shurl" value="<?php echo $short_url; ?>">
                            </div>
                            <button type="submit" class="btn btn-dark">Submit</button>
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
