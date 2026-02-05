<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Avatar Upload - Gravity Finance</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
        }
        .container {
            background: rgba(255,255,255,0.05);
            padding: 40px;
            border-radius: 20px;
            width: 400px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            color: #3b82f6;
        }
        .subtitle {
            text-align: center;
            color: #9ca3af;
            margin-bottom: 30px;
        }
        .upload-area {
            border: 2px dashed #3b82f6;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-bottom: 20px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .upload-area:hover {
            background: rgba(59, 130, 246, 0.1);
        }
        .upload-area i {
            font-size: 50px;
            color: #3b82f6;
            margin-bottom: 15px;
        }
        input[type="file"] {
            display: none;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }
        .allowed {
            text-align: center;
            color: #6b7280;
            font-size: 12px;
            margin-top: 15px;
        }
        .message {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .error { background: rgba(239, 68, 68, 0.2); color: #f87171; }
        .success { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📸 Avatar Upload</h1>
        <p class="subtitle">Upload your employee photo</p>
        
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
            $target_dir = "uploads/";
            $file_name = basename($_FILES["avatar"]["name"]);
            $target_file = $target_dir . $file_name;
            
            // VULNERABLE: Only checks Content-Type header (easily bypassable)
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            $file_type = $_FILES["avatar"]["type"];
            
            // VULNERABLE: Simple extension check that can be bypassed
            $extension = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
            
            // Check if extension is in allowed list (can be bypassed with double extension)
            if (!in_array($extension, $allowed_extensions)) {
                echo '<div class="message error">❌ Error: Only jpg, png, gif files are allowed!</div>';
            } else {
                // VULNERABLE: No proper validation, allows shell.php.jpg
                if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
                    echo '<div class="message success">✅ File uploaded successfully to: ' . htmlspecialchars($target_file) . '</div>';
                } else {
                    echo '<div class="message error">❌ Error uploading file.</div>';
                }
            }
        }
        ?>
        
        <form method="POST" enctype="multipart/form-data">
            <div class="upload-area" onclick="document.getElementById('avatar').click()">
                <div style="font-size: 50px; margin-bottom: 15px;">📤</div>
                <p>Click to select your photo</p>
                <input type="file" name="avatar" id="avatar" accept="image/*">
            </div>
            <button type="submit" class="btn">Upload Avatar</button>
        </form>
        
        <p class="allowed">Allowed formats: jpg, png, gif</p>
    </div>
    
    <script>
        document.getElementById('avatar').addEventListener('change', function(e) {
            if (e.target.files[0]) {
                document.querySelector('.upload-area p').textContent = e.target.files[0].name;
            }
        });
    </script>
</body>
</html>
