<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$host = "localhost";
$username = "root";
$password = "";
$database = "ITUM_MYSQL";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$error_message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST["username"] ?? '');
    $password = $_POST["password"] ?? '';

    if (empty($username) || empty($password)) {
        $error_message = "Username and Password are required.";
    } else {
        $query = "SELECT password FROM participants WHERE username = ?";
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            die("Error preparing statement: " . $conn->error);
        }

        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        echo "Rows found: " . $stmt->num_rows . "<br>";

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();

            echo "Hashed password from DB: $hashed_password<br>";

            if (password_verify($password, $hashed_password)) {
                session_start();
                $_SESSION["username"] = $username;

                echo "<script>
                        alert('Login successful! Redirecting to the home page.');
                        window.location.href = 'HOMEPAGE.html';
                      </script>";
                exit();
            } else {
                $error_message = "Username or Password is incorrect.";
            }
        } else {
            $error_message = "Username or Password is incorrect.";
        }

        $stmt->close();
    }
}

$conn->close();
?>
