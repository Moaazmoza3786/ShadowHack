<?php
$db = new PDO('sqlite:database.db');
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, flag TEXT)");

// Check if data exists
$res = $db->query("SELECT COUNT(*) FROM secrets");
if ($res->fetchColumn() == 0) {
    $db->exec("INSERT INTO users (username, password) VALUES ('admin', 'p4ssw0rd123')");
    $db->exec("INSERT INTO secrets (flag) VALUES ('AG{bl1nd_sql_m4st3ry}')");
}

$message = "";
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    
    // Vulnerable query (Boolean/Time based)
    // We'll simulate a delay in PHP if a certain condition is met to make it "Time-based"
    $query = "SELECT username FROM users WHERE id = " . $id;
    
    $start = microtime(true);
    try {
        $result = $db->query($query);
        $fetch = $result ? $result->fetch() : null;
        
        // Let's add an explicit SLEEP simulation for 'Blind' excitement
        // If the user uses something like '1 AND (SELECT 1 FROM secrets WHERE flag LIKE "A%")'
        // But since SQLite doesn't have SLEEP, the user might use heavy queries.
        // We will assist by checking for a specific pattern in the input to simulate the lag.
        if (strpos($id, 'WAITFOR') !== false || strpos($id, 'SLEEP') !== false) {
             usleep(2000000); // 2 seconds delay
        }
        
        if ($fetch) {
            $message = "User exists in the database.";
        } else {
            $message = "User not found.";
        }
    } catch (Exception $e) {
        $message = "Database Error.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>SecureGate - User Portal</title>
    <style>
        body { background: #050505; color: #00ff00; font-family: 'Courier New', monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .terminal { border: 1px solid #00ff00; padding: 40px; box-shadow: 0 0 20px #00ff0033; background: #000; width: 500px; }
        h1 { border-bottom: 1px solid #00ff00; padding-bottom: 10px; margin-bottom: 30px; font-size: 1.5em; }
        input { background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 10px; width: 100%; box-sizing: border-box; margin-bottom: 20px; outline: none; }
        button { background: #00ff00; color: #000; border: none; padding: 10px 20px; cursor: pointer; font-weight: bold; width: 100%; transition: 0.3s; }
        button:hover { background: #00cc00; }
        .result { margin-top: 20px; padding: 15px; border-top: 1px solid #333; min-height: 20px; }
    </style>
</head>
<body>
    <div class="terminal">
        <h1>SECURE-GATE v3.1</h1>
        <p>Enter User ID to verify existence:</p>
        <form method="GET">
            <input type="text" name="id" placeholder="User ID (e.g. 1)" value="<?php echo htmlspecialchars($_GET['id'] ?? ''); ?>">
            <button type="submit">QUERY DATABASE</button>
        </form>
        <div class="result">
            <?php echo $message; ?>
        </div>
        <p style="font-size: 0.7em; color: #555; margin-top: 30px;">
            [SYSTEM WARNING] All queries are logged for security audits.
        </p>
    </div>
</body>
</html>
