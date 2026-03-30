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

        <?php if (isset($message)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <?php if (isset($pendingMfa) && $pendingMfa): ?>
            <div class="settings-section" style="margin-bottom: 1rem;">
                <h3>Multi-Factor Authentication</h3>
                <p style="color: var(--color-muted); margin-bottom: 1rem;">Enter a 6-digit verification code to finish signing in.</p>
            </div>

            <form method="POST" action="login.php">
                <input type="hidden" name="action" value="verify_mfa">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">

                <div class="form-group">
                    <label for="mfa_method">Verification Method</label>
                    <select id="mfa_method" name="mfa_method" onchange="toggleMfaResend()" required>
                        <?php if (!empty($mfaMethods['totp'])): ?>
                            <option value="totp">Authenticator App (TOTP)</option>
                        <?php endif; ?>
                        <?php if (!empty($mfaMethods['email'])): ?>
                            <option value="email">Email Code</option>
                        <?php endif; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label for="mfa_code">6-Digit Code</label>
                    <input type="text" id="mfa_code" name="mfa_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus>
                </div>

                <button type="submit" class="btn">Verify & Login</button>
            </form>

            <?php if (!empty($mfaMethods['email'])): ?>
                <form method="POST" action="login.php" id="resend-mfa-form" style="margin-top: 0.75rem; display: none;">
                    <input type="hidden" name="action" value="resend_mfa_email_code">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <button type="submit" class="btn btn-secondary">Resend Email Code</button>
                </form>
            <?php endif; ?>
        <?php else: ?>
        
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
            <div style="text-align: center; margin-top: 0.75rem;">
                <a href="forgot_password.php" style="color: var(--color-muted); font-size: 0.85rem;">Forgot password?</a>
            </div>
        </div>
        
        <div id="code-tab" class="tab-content">
            <form method="POST" action="login.php">
                <input type="hidden" name="login_type" value="code">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-group">
                    <label for="access_code">Access Code</label>
                    <input type="text" id="access_code" name="access_code" required maxlength="7" minlength="7" pattern="[A-Za-z0-9]{7}" placeholder="ABC1234" style="text-transform: uppercase;" oninput="this.value = this.value.toUpperCase()">
                </div>
                
                <button type="submit" class="btn">Access</button>
            </form>
        </div>
        
        <div class="back-link">
            <a href="public.php">← Browse Public Files</a>
        </div>
        <?php endif; ?>
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

        function toggleMfaResend() {
            const methodSelect = document.getElementById('mfa_method');
            const resendForm = document.getElementById('resend-mfa-form');

            if (!methodSelect || !resendForm) {
                return;
            }

            resendForm.style.display = methodSelect.value === 'email' ? 'block' : 'none';
        }

        toggleMfaResend();
    </script>
    
    <?php include 'footer.php'; ?>
</body>
</html>
