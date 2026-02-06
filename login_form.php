<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="login-page">
    <div class="login-container white-bg">
        <div class="logo">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <p>Secure File Transfer System</p>
        </div>
        
        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('user')">User Login</div>
            <div class="tab" onclick="switchTab('code')">Access Code</div>
        </div>
        
        <div id="user-tab" class="tab-content active">
            <form method="POST" action="login.php">
                <input type="hidden" name="login_type" value="user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn">Login</button>
            </form>
        </div>
        
        <div id="code-tab" class="tab-content">
            <form method="POST" action="login.php">
                <input type="hidden" name="login_type" value="code">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-group">
                    <label for="access_code">Access Code</label>
                    <input type="text" id="access_code" name="access_code" required>
                </div>
                
                <button type="submit" class="btn">Access</button>
            </form>
        </div>
        
        <div class="back-link">
            <a href="public.php">← Browse Public Files</a>
        </div>
    </div>
    
    <script>
        function switchTab(tab) {
            // Update tabs
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            
            if (tab === 'user') {
                document.querySelectorAll('.tab')[0].classList.add('active');
                document.getElementById('user-tab').classList.add('active');
            } else {
                document.querySelectorAll('.tab')[1].classList.add('active');
                document.getElementById('code-tab').classList.add('active');
            }
        }
    </script>
    
    <?php include 'footer.php'; ?>
</body>
</html>
