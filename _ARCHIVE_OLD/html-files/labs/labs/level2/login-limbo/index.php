<?php
$db = new PDO('sqlite::memory:');
$db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, flag TEXT)");
$db->exec("INSERT INTO users (username, password, flag) VALUES ('admin', 'super_secret_p@ss_2026', 'AG{SQL_Inj3ct10n_M4st3r}')");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    $query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = $db->query($query);
    if ($result && $result->fetch()) {
        echo "<h1>Logged in as Admin!</h1><p>Flag: AG{SQL_Inj3ct10n_M4st3r}</p>";
        exit;
    } else {
        echo "<p style='color:red;'>Login Failed!</p>";
    }
}
?>
<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <button type="submit">Login</button>
</form>
