<?php
// Settings page (User & Admin Settings)
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'users.php';
require_once 'files.php';
require_once 'rbac.php';
require_once 'app_settings.php';
require_once 'smtp_mailer.php';
require_once 'mfa.php';
require_once 'security_monitor.php';

$db = new Database();
$auth = new Auth($db);
$userManager = new UserManager($db);
$fileManager = new FileManager($db, $auth);
$mfaService = new MFAService($db);
$securityMonitor = new SecurityMonitor($db);

// Check if logged in
if (!$auth->isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Get current user info
$currentUser = $auth->getCurrentUser();
$accessCode = $auth->getCurrentAccessCode();
$isAdmin = RBAC::isAdmin();

$message = null;

function normalizeSecurityEventFilters($source) {
    $severity = trim($source['security_severity'] ?? '');
    if (!in_array($severity, ['', 'info', 'warning', 'critical'], true)) {
        $severity = '';
    }

    $eventType = trim($source['security_event_type'] ?? '');
    $search = trim($source['security_search'] ?? '');
    if (strlen($search) > 100) {
        $search = substr($search, 0, 100);
    }

    $dateFrom = trim($source['security_date_from'] ?? '');
    if ($dateFrom !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateFrom)) {
        $dateFrom = '';
    }

    $dateTo = trim($source['security_date_to'] ?? '');
    if ($dateTo !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateTo)) {
        $dateTo = '';
    }

    return [
        'severity' => $severity,
        'event_type' => $eventType,
        'date_from' => $dateFrom,
        'date_to' => $dateTo,
        'search' => $search
    ];
}

// Handle application settings updates (Admin only)
if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['action'])
    && $isAdmin
    && in_array($_POST['action'], [
        'update_base_url',
        'update_smtp_settings',
        'update_security_thresholds',
        'send_test_smtp_email',
        'export_security_events',
        'create_user',
        'create_access_code',
        'update_user',
        'delete_user',
        'delete_code'
    ], true)
) {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } else {
        if ($_POST['action'] === 'update_base_url') {
            $baseUrl = trim($_POST['base_url']);
            
            // Validate base URL format
            if (!empty($baseUrl)) {
                // Remove trailing slash
                $baseUrl = rtrim($baseUrl, '/');
                
                // Validate URL format
                if (!filter_var($baseUrl, FILTER_VALIDATE_URL)) {
                    $message = ['type' => 'error', 'message' => 'Invalid URL format. Please use format: https://example.com'];
                } else {
                    // Save to database
                    $sql = "INSERT INTO app_settings (setting_key, setting_value, setting_type, description, updated_by) 
                            VALUES (?, ?, ?, ?, ?)
                            ON DUPLICATE KEY UPDATE 
                            setting_value = VALUES(setting_value),
                            updated_at = CURRENT_TIMESTAMP,
                            updated_by = VALUES(updated_by)";
                    
                    $result = $db->query($sql, [
                        'base_url',
                        $baseUrl,
                        'string',
                        'Custom base URL for link generation',
                        $_SESSION['user_id']
                    ]);
                    
                    if ($result) {
                        $message = ['type' => 'success', 'message' => 'Base URL updated successfully!'];
                    } else {
                        $message = ['type' => 'error', 'message' => 'Failed to update base URL.'];
                    }
                }
            } else {
                // Empty = use auto-detection, delete setting
                $sql = "DELETE FROM app_settings WHERE setting_key = ?";
                $db->query($sql, ['base_url']);
                $message = ['type' => 'success', 'message' => 'Base URL cleared. Using auto-detection.'];
            }
        } elseif ($_POST['action'] === 'update_smtp_settings') {
            $appSettings = new AppSettingsManager($db);

            $smtpEnabled = isset($_POST['smtp_enabled']) ? '1' : '0';
            $smtpHost = trim($_POST['smtp_host'] ?? '');
            $smtpPort = intval($_POST['smtp_port'] ?? 587);
            $smtpEncryption = $_POST['smtp_encryption'] ?? 'tls';
            $smtpAuthRequired = isset($_POST['smtp_auth_required']) ? '1' : '0';
            $smtpUsername = trim($_POST['smtp_username'] ?? '');
            $smtpPasswordInput = trim($_POST['smtp_password'] ?? '');
            $smtpFromEmail = trim($_POST['smtp_from_email'] ?? '');
            $smtpFromName = trim($_POST['smtp_from_name'] ?? SITE_NAME);

            if (!in_array($smtpEncryption, ['none', 'tls', 'ssl'], true)) {
                $smtpEncryption = 'tls';
            }

            $existingSmtpPassword = $appSettings->getSmtpPassword();
            $smtpPasswordToStore = $smtpPasswordInput !== '' ? $smtpPasswordInput : $existingSmtpPassword;

            if ($smtpEnabled === '1') {
                if ($smtpHost === '') {
                    $message = ['type' => 'error', 'message' => 'SMTP host is required when SMTP is enabled.'];
                } elseif ($smtpPort < 1 || $smtpPort > 65535) {
                    $message = ['type' => 'error', 'message' => 'SMTP port must be between 1 and 65535.'];
                } elseif (!filter_var($smtpFromEmail, FILTER_VALIDATE_EMAIL)) {
                    $message = ['type' => 'error', 'message' => 'A valid "From Email" address is required.'];
                } elseif ($smtpAuthRequired === '1' && $smtpUsername === '') {
                    $message = ['type' => 'error', 'message' => 'SMTP username is required when authentication is enabled.'];
                } elseif ($smtpAuthRequired === '1' && $smtpPasswordToStore === '') {
                    $message = ['type' => 'error', 'message' => 'SMTP password is required when authentication is enabled.'];
                }
            }

            if (!$message) {
                $settingsToSave = [
                    ['smtp_enabled', $smtpEnabled, 'boolean', 'Enable SMTP email delivery'],
                    ['smtp_host', $smtpHost, 'string', 'SMTP server host'],
                    ['smtp_port', (string)$smtpPort, 'integer', 'SMTP server port'],
                    ['smtp_encryption', $smtpEncryption, 'string', 'SMTP encryption mode (none/tls/ssl)'],
                    ['smtp_auth_required', $smtpAuthRequired, 'boolean', 'Require SMTP authentication'],
                    ['smtp_username', $smtpUsername, 'string', 'SMTP authentication username'],
                    ['smtp_from_email', $smtpFromEmail, 'string', 'Default sender email address'],
                    ['smtp_from_name', $smtpFromName, 'string', 'Default sender display name']
                ];

                $allSaved = true;
                foreach ($settingsToSave as $setting) {
                    $saved = $appSettings->set(
                        $setting[0],
                        $setting[1],
                        $setting[2],
                        $setting[3],
                        $_SESSION['user_id']
                    );

                    if (!$saved) {
                        $allSaved = false;
                        break;
                    }
                }

                if ($allSaved) {
                    $allSaved = $appSettings->setSmtpPassword($smtpPasswordToStore, $_SESSION['user_id']);
                }

                if ($allSaved) {
                    $message = ['type' => 'success', 'message' => 'SMTP settings updated successfully!'];
                } else {
                    $message = ['type' => 'error', 'message' => 'Failed to save SMTP settings.'];
                }
            }
        } elseif ($_POST['action'] === 'update_security_thresholds') {
            $appSettings = new AppSettingsManager($db);

            $thresholdDefinitions = [
                'security_max_download_requests_window' => ['min' => 1, 'max' => 10000, 'label' => 'Max download requests per window'],
                'security_download_request_window_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Download request window seconds'],
                'security_download_request_lockout_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Download request lockout seconds'],

                'security_max_download_failure_attempts' => ['min' => 1, 'max' => 10000, 'label' => 'Max download failure attempts'],
                'security_download_failure_window_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Download failure window seconds'],
                'security_download_failure_lockout_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Download failure lockout seconds'],

                'security_max_share_token_failure_attempts' => ['min' => 1, 'max' => 10000, 'label' => 'Max share token failure attempts'],
                'security_share_token_failure_window_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share token failure window seconds'],
                'security_share_token_failure_lockout_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share token failure lockout seconds'],

                'security_max_share_password_failure_attempts' => ['min' => 1, 'max' => 10000, 'label' => 'Max share password failure attempts'],
                'security_share_password_failure_window_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share password failure window seconds'],
                'security_share_password_failure_lockout_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share password failure lockout seconds'],

                'security_max_share_requests_window' => ['min' => 1, 'max' => 10000, 'label' => 'Max share requests per window'],
                'security_share_request_window_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share request window seconds'],
                'security_share_request_lockout_seconds' => ['min' => 1, 'max' => 86400, 'label' => 'Share request lockout seconds']
            ];

            $allSaved = true;
            foreach ($thresholdDefinitions as $key => $definition) {
                $rawValue = $_POST[$key] ?? null;
                if (!is_numeric($rawValue)) {
                    $message = ['type' => 'error', 'message' => 'Invalid numeric value for: ' . $definition['label']];
                    $allSaved = false;
                    break;
                }

                $value = intval($rawValue);
                if ($value < $definition['min'] || $value > $definition['max']) {
                    $message = ['type' => 'error', 'message' => $definition['label'] . ' must be between ' . $definition['min'] . ' and ' . $definition['max'] . '.'];
                    $allSaved = false;
                    break;
                }

                $saved = $appSettings->set(
                    $key,
                    (string)$value,
                    'integer',
                    'Security threshold setting',
                    $_SESSION['user_id']
                );

                if (!$saved) {
                    $allSaved = false;
                    break;
                }
            }

            if ($allSaved) {
                $message = ['type' => 'success', 'message' => 'Security threshold settings updated successfully!'];
            } elseif (!$message) {
                $message = ['type' => 'error', 'message' => 'Failed to save security threshold settings.'];
            }
        } elseif ($_POST['action'] === 'send_test_smtp_email') {
            $testRecipientEmail = trim($_POST['test_recipient_email'] ?? '');

            if (!filter_var($testRecipientEmail, FILTER_VALIDATE_EMAIL)) {
                $message = ['type' => 'error', 'message' => 'Please enter a valid test recipient email address.'];
            } else {
                $smtpMailer = new SMTPMailer($db);
                $result = $smtpMailer->send(
                    $testRecipientEmail,
                    'SMTP Test Email - ' . SITE_NAME,
                    '<p>This is a test email from <strong>' . htmlspecialchars(SITE_NAME) . '</strong>.</p><p>If you received this message, your SMTP configuration is working.</p>',
                    'This is a test email from ' . SITE_NAME . '. If you received this message, your SMTP configuration is working.'
                );

                if ($result['success']) {
                    $message = ['type' => 'success', 'message' => 'Test email sent successfully to ' . $testRecipientEmail . '.'];
                } else {
                    $message = ['type' => 'error', 'message' => 'Failed to send test email: ' . $result['error']];
                }
            }
        } elseif ($_POST['action'] === 'export_security_events') {
            $filters = normalizeSecurityEventFilters($_POST);
            $events = $securityMonitor->getFilteredEvents($filters, 10000);

            header('Content-Type: text/csv; charset=UTF-8');
            header('Content-Disposition: attachment; filename="security-events-' . date('Ymd-His') . '.csv"');

            $out = fopen('php://output', 'w');
            fputcsv($out, ['timestamp', 'severity', 'event_type', 'user', 'ip_address', 'identifier', 'context_json']);

            foreach ($events as $event) {
                fputcsv($out, [
                    $event['created_at'] ?? '',
                    $event['severity'] ?? '',
                    $event['event_type'] ?? '',
                    $event['username'] ?? 'System',
                    $event['ip_address'] ?? '',
                    $event['identifier'] ?? '',
                    $event['context_json'] ?? ''
                ]);
            }

            fclose($out);
            exit;
        } elseif ($_POST['action'] === 'create_user') {
            $isTemporary = isset($_POST['is_temporary']);
            $expiryDate = $isTemporary && !empty($_POST['expiry_date']) ? $_POST['expiry_date'] : null;
            $role = $_POST['role'] ?? 'user';
            
            // Convert MB to bytes
            $uploadQuotaMB = floatval($_POST['upload_quota']);
            $uploadQuotaBytes = intval($uploadQuotaMB * 1024 * 1024);
            
            $result = $userManager->createUser(
                $_POST['username'],
                $_POST['password'],
                $_POST['email'],
                $role,
                $uploadQuotaBytes,
                $isTemporary,
                $expiryDate
            );
            
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'User created successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'create_access_code') {
            $expiryDate = !empty($_POST['expiry_date']) ? $_POST['expiry_date'] : null;
            $maxUses = intval($_POST['max_uses'] ?? 0);

            if ($maxUses < 1 || $maxUses > 10000) {
                $message = ['type' => 'error', 'message' => 'Max Uses must be between 1 and 10000.'];
            }
            
            // Convert MB to bytes
            $uploadQuotaMB = floatval($_POST['upload_quota']);
            $uploadQuotaBytes = intval($uploadQuotaMB * 1024 * 1024);

            if (!$message && $uploadQuotaBytes < 1) {
                $message = ['type' => 'error', 'message' => 'Upload quota must be greater than 0 MB.'];
            }
            
            if (!$message) {
                $result = $userManager->createAccessCode(
                    $maxUses,
                    $uploadQuotaBytes,
                    $expiryDate,
                    $_SESSION['user_id']
                );
            
                if ($result['success']) {
                    $message = ['type' => 'success', 'message' => 'Access code created: ' . $result['code']];
                } else {
                    $message = ['type' => 'error', 'message' => $result['error']];
                }
            }
        } elseif ($_POST['action'] === 'update_user') {
            $targetUserId = intval($_POST['user_id'] ?? 0);
            $targetUser = $targetUserId > 0 ? $userManager->getUser($targetUserId) : null;

            if (!$targetUser) {
                $message = ['type' => 'error', 'message' => 'User not found.'];
            } else {
                $username = trim($_POST['edit_username'] ?? '');
                $email = trim($_POST['edit_email'] ?? '');
                $newPassword = trim($_POST['edit_password'] ?? '');
                $quotaMb = floatval($_POST['edit_upload_quota'] ?? 0);
                $quotaBytes = intval($quotaMb * 1024 * 1024);
                $role = isset($_POST['edit_is_admin']) ? 'admin' : 'user';
                $clearMfa = isset($_POST['clear_mfa']);

                if ($username === '') {
                    $message = ['type' => 'error', 'message' => 'Username is required.'];
                } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $message = ['type' => 'error', 'message' => 'Please enter a valid email address.'];
                } elseif ($quotaBytes < 1) {
                    $message = ['type' => 'error', 'message' => 'Upload quota must be at least 1 MB.'];
                } elseif (!in_array($role, ['admin', 'user'], true)) {
                    $message = ['type' => 'error', 'message' => 'Invalid user role.'];
                } elseif ($newPassword !== '' && strlen($newPassword) < 8) {
                    $message = ['type' => 'error', 'message' => 'New password must be at least 8 characters long.'];
                }

                if (!$message) {
                    $updateData = [
                        'username' => $username,
                        'email' => $email,
                        'upload_quota' => $quotaBytes,
                        'role' => $role
                    ];

                    if ($newPassword !== '') {
                        $updateData['password'] = $newPassword;
                    }

                    $result = $userManager->updateUser($targetUserId, $updateData);
                    if (!$result['success']) {
                        $message = ['type' => 'error', 'message' => $result['error']];
                    } else {
                        $mfaCleared = true;
                        if ($clearMfa) {
                            $mfaCleared = $mfaService->disableTotpForUser($targetUserId)
                                && $mfaService->disableEmailForUser($targetUserId)
                                && $db->query("DELETE FROM mfa_email_codes WHERE user_id = ?", [$targetUserId]);
                        }

                        if ($clearMfa && !$mfaCleared) {
                            $message = ['type' => 'warning', 'message' => 'User updated, but MFA clearing did not fully complete.'];
                        } else {
                            $message = ['type' => 'success', 'message' => 'User updated successfully!'];
                        }
                    }
                }
            }
        } elseif ($_POST['action'] === 'delete_user') {
            $result = $userManager->deleteUser($_POST['user_id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'User deleted successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'delete_code') {
            $result = $userManager->deleteAccessCode($_POST['code_id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Access code deleted successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        }
    }
}

// Handle password change (for all authenticated users)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'change_password') {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif ($currentUser) {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $message = ['type' => 'error', 'message' => 'All fields are required.'];
        } elseif ($newPassword !== $confirmPassword) {
            $message = ['type' => 'error', 'message' => 'New passwords do not match.'];
        } elseif (strlen($newPassword) < 8) {
            $message = ['type' => 'error', 'message' => 'Password must be at least 8 characters long.'];
        } else {
            // Verify current password
            if (password_verify($currentPassword, $currentUser['password'])) {
                $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $currentUser['id']]);
                $message = ['type' => 'success', 'message' => 'Password changed successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => 'Current password is incorrect.'];
            }
        }
    }
}

// Handle MFA settings (for authenticated user accounts only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && in_array($_POST['action'], [
    'enable_totp_mfa',
    'disable_totp_mfa',
    'enable_email_mfa',
    'disable_email_mfa'
], true)) {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (!$currentUser) {
        $message = ['type' => 'error', 'message' => 'MFA settings are only available for user accounts.'];
    } else {
        if ($_POST['action'] === 'enable_totp_mfa') {
            $result = $mfaService->enableTotpForUser($currentUser['id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'TOTP MFA enabled. Add the secret to your authenticator app.'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'disable_totp_mfa') {
            $result = $mfaService->disableTotpForUser($currentUser['id']);
            if ($result) {
                $message = ['type' => 'success', 'message' => 'TOTP MFA disabled.'];
            } else {
                $message = ['type' => 'error', 'message' => 'Failed to disable TOTP MFA.'];
            }
        } elseif ($_POST['action'] === 'enable_email_mfa') {
            $result = $mfaService->enableEmailForUser($currentUser['id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Email MFA enabled.'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'disable_email_mfa') {
            $result = $mfaService->disableEmailForUser($currentUser['id']);
            if ($result) {
                $message = ['type' => 'success', 'message' => 'Email MFA disabled.'];
            } else {
                $message = ['type' => 'error', 'message' => 'Failed to disable Email MFA.'];
            }
        }
    }
}

// Get admin data if user is admin
$users = [];
$accessCodes = [];
$customBaseUrl = '';
$autoDetectedBaseUrl = '';
$smtpSettings = [
    'enabled' => false,
    'host' => '',
    'port' => 587,
    'encryption' => 'tls',
    'username' => '',
    'auth_required' => true,
    'from_email' => '',
    'from_name' => SITE_NAME
];
$hasSmtpPassword = false;
$mfaSettings = null;
$mfaMethods = ['totp' => false, 'email' => false];
$totpProvisioningUri = '';
$securityEvents = [];
$securityEventTypes = [];
$securityThresholdSettings = [
    'max_download_requests_window' => MAX_DOWNLOAD_REQUESTS_WINDOW,
    'download_request_window_seconds' => DOWNLOAD_REQUEST_WINDOW_SECONDS,
    'download_request_lockout_seconds' => DOWNLOAD_REQUEST_LOCKOUT_SECONDS,
    'max_download_failure_attempts' => MAX_DOWNLOAD_FAILURE_ATTEMPTS,
    'download_failure_window_seconds' => DOWNLOAD_FAILURE_WINDOW_SECONDS,
    'download_failure_lockout_seconds' => DOWNLOAD_FAILURE_LOCKOUT_SECONDS,
    'max_share_token_failure_attempts' => MAX_SHARE_TOKEN_FAILURE_ATTEMPTS,
    'share_token_failure_window_seconds' => SHARE_TOKEN_FAILURE_WINDOW_SECONDS,
    'share_token_failure_lockout_seconds' => SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS,
    'max_share_password_failure_attempts' => MAX_SHARE_PASSWORD_FAILURE_ATTEMPTS,
    'share_password_failure_window_seconds' => SHARE_PASSWORD_FAILURE_WINDOW_SECONDS,
    'share_password_failure_lockout_seconds' => SHARE_PASSWORD_FAILURE_LOCKOUT_SECONDS,
    'max_share_requests_window' => MAX_SHARE_REQUESTS_WINDOW,
    'share_request_window_seconds' => SHARE_REQUEST_WINDOW_SECONDS,
    'share_request_lockout_seconds' => SHARE_REQUEST_LOCKOUT_SECONDS
];
$securityEventFilters = [
    'severity' => '',
    'event_type' => '',
    'date_from' => '',
    'date_to' => '',
    'search' => ''
];

if ($currentUser) {
    $mfaSettings = $mfaService->getUserMfaSettings($currentUser['id']);
    if ($mfaSettings) {
        $mfaMethods = $mfaService->getAvailableMethods($mfaSettings);
        if (!empty($mfaSettings['totp_secret'])) {
            $totpProvisioningUri = $mfaService->getTotpProvisioningUri($currentUser['username'], $mfaSettings['totp_secret']);
        }
    }
}

if ($isAdmin) {
    $users = $userManager->getAllUsers();
    $accessCodes = $userManager->getAllAccessCodes();
    
    // Get current application settings
    $sql = "SELECT * FROM app_settings WHERE setting_key = ?";
    $baseUrlSetting = $db->fetch($sql, ['base_url']);
    $customBaseUrl = $baseUrlSetting ? $baseUrlSetting['setting_value'] : '';
    
    // Get auto-detected base URL for comparison
    $autoDetectedBaseUrl = getBaseUrl();

    // Get current SMTP settings
    $appSettings = new AppSettingsManager($db);
    $smtpSettings = $appSettings->getSmtpSettings();
    $hasSmtpPassword = !empty($smtpSettings['password']);
    $securityThresholdSettings = $appSettings->getSecurityThresholds();

    $securityEventFilters = normalizeSecurityEventFilters($_GET);
    $securityEventTypes = $securityMonitor->getDistinctEventTypes(500);

    if (
        $securityEventFilters['event_type'] !== ''
        && !in_array($securityEventFilters['event_type'], $securityEventTypes, true)
    ) {
        $securityEventFilters['event_type'] = '';
    }

    $securityEvents = $securityMonitor->getFilteredEvents($securityEventFilters, 250);
}

// Generate CSRF token
$csrfToken = $auth->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Settings</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page">
    <?php include 'header.php'; ?>
    
    <div class="container<?php echo $isAdmin ? ' admin-container' : ''; ?>">
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($message['message']); ?>
            </div>
        <?php endif; ?>

        <?php if ($isAdmin): ?>
            <div class="settings-tabs">
                <button type="button" class="settings-tab-button active" data-settings-tab="user-settings" onclick="switchSettingsTab('user-settings')">User Settings</button>
                <button type="button" class="settings-tab-button" data-settings-tab="user-management" onclick="switchSettingsTab('user-management')">User Management</button>
                <button type="button" class="settings-tab-button" data-settings-tab="site-settings" onclick="switchSettingsTab('site-settings')">Site Settings</button>
                <button type="button" class="settings-tab-button" data-settings-tab="security-events" onclick="switchSettingsTab('security-events')">Security Events</button>
            </div>
        <?php endif; ?>

        <div class="settings-tab-panel active" data-settings-panel="user-settings">
        
        <div class="card">
            <div class="card-header">
                <h2>⚙️ Account Settings</h2>
            </div>
            <div class="card-body">
                <div class="settings-section">
                    <h3>Account Information</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Username:</label>
                            <span><strong><?php echo $currentUser ? htmlspecialchars($currentUser['username']) : 'Access Code User'; ?></strong></span>
                        </div>
                        <?php if ($currentUser): ?>
                            <div class="info-item">
                                <label>Account Type:</label>
                                <span class="badge <?php echo $isAdmin ? 'badge-warning' : 'badge-success'; ?>">
                                    <?php echo $isAdmin ? 'Administrator' : 'User'; ?>
                                </span>
                            </div>
                            <div class="info-item">
                                <label>Created:</label>
                                <span><?php echo date('F j, Y', strtotime($currentUser['created_at'])); ?></span>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <?php if ($currentUser): ?>
                    <hr style="border-color: var(--color-border); margin: 2rem 0;">
                    
                    <div class="settings-section">
                        <h3>Change Password</h3>
                        <form method="POST" class="form-group">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            <input type="hidden" name="action" value="change_password">
                            
                            <div class="form-group">
                                <label for="current_password">Current Password:</label>
                                <input type="password" id="current_password" name="current_password" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="new_password">New Password:</label>
                                <input type="password" id="new_password" name="new_password" required minlength="8">
                                <small style="color: var(--color-muted);">Must be at least 8 characters long</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="confirm_password">Confirm New Password:</label>
                                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
                            </div>
                            
                            <button type="submit" class="btn">Change Password</button>
                        </form>
                    </div>

                    <hr style="border-color: var(--color-border); margin: 2rem 0;">

                    <div class="settings-section">
                        <h3>Multi-Factor Authentication (MFA)</h3>

                        <div class="info-grid" style="margin-bottom: 1rem;">
                            <div class="info-item">
                                <label>TOTP Authenticator:</label>
                                <span>
                                    <?php if (!empty($mfaMethods['totp'])): ?>
                                        <span class="badge badge-success">Enabled</span>
                                    <?php else: ?>
                                        <span class="badge badge-warning">Disabled</span>
                                    <?php endif; ?>
                                </span>
                            </div>
                            <div class="info-item">
                                <label>Email Codes:</label>
                                <span>
                                    <?php if (!empty($mfaMethods['email'])): ?>
                                        <span class="badge badge-success">Enabled</span>
                                    <?php else: ?>
                                        <span class="badge badge-warning">Disabled</span>
                                    <?php endif; ?>
                                </span>
                            </div>
                        </div>

                        <div class="btn-row" style="margin-bottom: 1rem;">
                            <?php if (!empty($mfaMethods['totp'])): ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="disable_totp_mfa">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                    <button type="submit" class="btn btn-danger">Disable TOTP</button>
                                </form>
                            <?php else: ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="enable_totp_mfa">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                    <button type="submit" class="btn btn-primary">Enable TOTP</button>
                                </form>
                            <?php endif; ?>

                            <?php if (!empty($mfaMethods['email'])): ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="disable_email_mfa">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                    <button type="submit" class="btn btn-danger">Disable Email MFA</button>
                                </form>
                            <?php else: ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="enable_email_mfa">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                                    <button type="submit" class="btn btn-secondary">Enable Email MFA</button>
                                </form>
                            <?php endif; ?>
                        </div>

                        <?php if (!empty($mfaMethods['totp']) && !empty($mfaSettings) && !empty($mfaSettings['totp_secret'])): ?>
                            <div class="hash-info">
                                <strong>TOTP Setup Secret:</strong><br>
                                <span class="hash-display"><?php echo htmlspecialchars($mfaSettings['totp_secret']); ?></span>
                                <small style="display: block; margin-top: 0.5rem; color: var(--color-muted);">
                                    Add this secret manually in your authenticator app, or use this provisioning URI:
                                </small>
                                <span class="hash-display" style="display: block; margin-top: 0.5rem;"><?php echo htmlspecialchars($totpProvisioningUri); ?></span>
                            </div>
                        <?php endif; ?>

                        <small style="display: block; margin-top: 0.75rem; color: var(--color-muted);">
                            You can enable either one method or both. During login, you can use any enabled method.
                        </small>
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">
                        <strong>Note:</strong> You are logged in with an access code. Password changes are only available for registered users.
                    </div>
                <?php endif; ?>
            </div>
        </div>
        </div>
        
        <?php if ($isAdmin): ?>
        <!-- Application Settings Section (Admin Only) -->
        <div class="settings-tab-panel" data-settings-panel="site-settings">
        <div class="card">
            <div class="card-header">
                <h2>⚙️ Application Settings</h2>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="update_base_url">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="form-group">
                        <label for="base_url">Base URL for Link Generation</label>
                        <input type="url" 
                               id="base_url" 
                               name="base_url" 
                               value="<?php echo htmlspecialchars($customBaseUrl); ?>"
                               placeholder="https://example.com">
                        <small style="display: block; margin-top: 0.5rem; color: var(--color-muted);">
                            <strong>Current Mode:</strong> 
                            <?php if (!empty($customBaseUrl)): ?>
                                Custom URL: <code style="color: var(--color-secondary);"><?php echo htmlspecialchars($customBaseUrl); ?></code>
                            <?php else: ?>
                                Auto-Detection: <code style="color: var(--color-secondary);"><?php echo htmlspecialchars($autoDetectedBaseUrl); ?></code>
                            <?php endif; ?>
                        </small>
                        <small style="display: block; margin-top: 0.25rem; color: var(--color-muted);">
                            Set a custom base URL for share links and other generated URLs. Leave empty to use automatic detection based on HTTP headers (recommended for reverse proxy setups).
                        </small>
                        <small style="display: block; margin-top: 0.25rem; color: var(--color-gold);">
                            💡 <strong>Tip:</strong> Use automatic detection if you're behind a reverse proxy with proper X-Forwarded-* headers configured.
                        </small>
                    </div>
                    
                    <div class="btn-row">
                        <button type="submit" class="btn btn-primary">Save Settings</button>
                        <?php if (!empty($customBaseUrl)): ?>
                            <button type="button" class="btn btn-secondary" onclick="clearBaseUrl()">Use Auto-Detection</button>
                        <?php endif; ?>
                    </div>
                </form>

                <hr style="border-color: var(--color-border); margin: 2rem 0;">

                <h3>SMTP Email Settings</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="update_smtp_settings">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">

                    <div class="checkbox-group" style="margin-bottom: 1rem;">
                        <input type="checkbox" id="smtp_enabled" name="smtp_enabled" value="1" <?php echo $smtpSettings['enabled'] ? 'checked' : ''; ?>>
                        <label for="smtp_enabled" style="margin: 0">Enable SMTP Email Delivery</label>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="smtp_host">SMTP Host</label>
                            <input type="text" id="smtp_host" name="smtp_host" value="<?php echo htmlspecialchars($smtpSettings['host']); ?>" placeholder="smtp.example.com">
                        </div>

                        <div class="form-group">
                            <label for="smtp_port">SMTP Port</label>
                            <input type="number" id="smtp_port" name="smtp_port" value="<?php echo intval($smtpSettings['port']); ?>" min="1" max="65535">
                        </div>

                        <div class="form-group">
                            <label for="smtp_encryption">Encryption</label>
                            <select id="smtp_encryption" name="smtp_encryption">
                                <option value="none" <?php echo $smtpSettings['encryption'] === 'none' ? 'selected' : ''; ?>>None</option>
                                <option value="tls" <?php echo $smtpSettings['encryption'] === 'tls' ? 'selected' : ''; ?>>STARTTLS (TLS)</option>
                                <option value="ssl" <?php echo $smtpSettings['encryption'] === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                            </select>
                        </div>
                    </div>

                    <div class="checkbox-group" style="margin-bottom: 1rem;">
                        <input type="checkbox" id="smtp_auth_required" name="smtp_auth_required" value="1" <?php echo $smtpSettings['auth_required'] ? 'checked' : ''; ?> onchange="toggleSmtpAuthFields()">
                        <label for="smtp_auth_required" style="margin: 0">SMTP Authentication Required</label>
                    </div>

                    <div class="form-grid" id="smtp_auth_fields">
                        <div class="form-group">
                            <label for="smtp_username">SMTP Username</label>
                            <input type="text" id="smtp_username" name="smtp_username" value="<?php echo htmlspecialchars($smtpSettings['username']); ?>">
                        </div>

                        <div class="form-group">
                            <label for="smtp_password">SMTP Password</label>
                            <input type="password" id="smtp_password" name="smtp_password" placeholder="<?php echo $hasSmtpPassword ? 'Saved (leave blank to keep current)' : 'Enter SMTP password'; ?>">
                            <small style="display: block; margin-top: 0.25rem; color: var(--color-muted);">
                                <?php echo $hasSmtpPassword ? 'A password is already saved.' : 'No password is currently saved.'; ?>
                            </small>
                        </div>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="smtp_from_email">From Email</label>
                            <input type="email" id="smtp_from_email" name="smtp_from_email" value="<?php echo htmlspecialchars($smtpSettings['from_email']); ?>" placeholder="noreply@example.com">
                        </div>

                        <div class="form-group">
                            <label for="smtp_from_name">From Name</label>
                            <input type="text" id="smtp_from_name" name="smtp_from_name" value="<?php echo htmlspecialchars($smtpSettings['from_name']); ?>" placeholder="<?php echo htmlspecialchars(SITE_NAME); ?>">
                        </div>
                    </div>

                    <div class="btn-row">
                        <button type="submit" class="btn btn-primary">Save SMTP Settings</button>
                    </div>
                </form>

                <form method="POST" style="margin-top: 1rem;">
                    <input type="hidden" name="action" value="send_test_smtp_email">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">

                    <div class="form-group">
                        <label for="test_recipient_email">Send Test Email To</label>
                        <input type="email" id="test_recipient_email" name="test_recipient_email" placeholder="admin@example.com" required>
                        <small style="display: block; margin-top: 0.25rem; color: var(--color-muted);">
                            Uses the currently saved SMTP settings.
                        </small>
                    </div>

                    <div class="btn-row">
                        <button type="submit" class="btn btn-secondary">Send Test Email</button>
                    </div>
                </form>

                <hr style="border-color: var(--color-border); margin: 2rem 0;">

                <h3>Security Thresholds (Brute-Force Protection)</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="update_security_thresholds">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="security_max_download_requests_window">Max Download Requests / Window</label>
                            <input type="number" id="security_max_download_requests_window" name="security_max_download_requests_window" min="1" max="10000" value="<?php echo intval($securityThresholdSettings['max_download_requests_window']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_download_request_window_seconds">Download Request Window (seconds)</label>
                            <input type="number" id="security_download_request_window_seconds" name="security_download_request_window_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['download_request_window_seconds']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_download_request_lockout_seconds">Download Request Lockout (seconds)</label>
                            <input type="number" id="security_download_request_lockout_seconds" name="security_download_request_lockout_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['download_request_lockout_seconds']); ?>" required>
                        </div>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="security_max_download_failure_attempts">Max Download Failure Attempts</label>
                            <input type="number" id="security_max_download_failure_attempts" name="security_max_download_failure_attempts" min="1" max="10000" value="<?php echo intval($securityThresholdSettings['max_download_failure_attempts']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_download_failure_window_seconds">Download Failure Window (seconds)</label>
                            <input type="number" id="security_download_failure_window_seconds" name="security_download_failure_window_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['download_failure_window_seconds']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_download_failure_lockout_seconds">Download Failure Lockout (seconds)</label>
                            <input type="number" id="security_download_failure_lockout_seconds" name="security_download_failure_lockout_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['download_failure_lockout_seconds']); ?>" required>
                        </div>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="security_max_share_requests_window">Max Share Requests / Window</label>
                            <input type="number" id="security_max_share_requests_window" name="security_max_share_requests_window" min="1" max="10000" value="<?php echo intval($securityThresholdSettings['max_share_requests_window']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_request_window_seconds">Share Request Window (seconds)</label>
                            <input type="number" id="security_share_request_window_seconds" name="security_share_request_window_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_request_window_seconds']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_request_lockout_seconds">Share Request Lockout (seconds)</label>
                            <input type="number" id="security_share_request_lockout_seconds" name="security_share_request_lockout_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_request_lockout_seconds']); ?>" required>
                        </div>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="security_max_share_token_failure_attempts">Max Share Token Failure Attempts</label>
                            <input type="number" id="security_max_share_token_failure_attempts" name="security_max_share_token_failure_attempts" min="1" max="10000" value="<?php echo intval($securityThresholdSettings['max_share_token_failure_attempts']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_token_failure_window_seconds">Share Token Failure Window (seconds)</label>
                            <input type="number" id="security_share_token_failure_window_seconds" name="security_share_token_failure_window_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_token_failure_window_seconds']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_token_failure_lockout_seconds">Share Token Failure Lockout (seconds)</label>
                            <input type="number" id="security_share_token_failure_lockout_seconds" name="security_share_token_failure_lockout_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_token_failure_lockout_seconds']); ?>" required>
                        </div>
                    </div>

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="security_max_share_password_failure_attempts">Max Share Password Failure Attempts</label>
                            <input type="number" id="security_max_share_password_failure_attempts" name="security_max_share_password_failure_attempts" min="1" max="10000" value="<?php echo intval($securityThresholdSettings['max_share_password_failure_attempts']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_password_failure_window_seconds">Share Password Failure Window (seconds)</label>
                            <input type="number" id="security_share_password_failure_window_seconds" name="security_share_password_failure_window_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_password_failure_window_seconds']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="security_share_password_failure_lockout_seconds">Share Password Failure Lockout (seconds)</label>
                            <input type="number" id="security_share_password_failure_lockout_seconds" name="security_share_password_failure_lockout_seconds" min="1" max="86400" value="<?php echo intval($securityThresholdSettings['share_password_failure_lockout_seconds']); ?>" required>
                        </div>
                    </div>

                    <div class="btn-row">
                        <button type="submit" class="btn btn-primary">Save Security Thresholds</button>
                    </div>
                </form>
                
                <!-- Detection Info -->
                <div class="hash-info" style="margin-top: 1.5rem;">
                    <strong>🔍 Current Detection Info:</strong><br>
                    <small>
                        <strong>Protocol:</strong> <?php echo htmlspecialchars(getProtocol()); ?><br>
                        <strong>Host:</strong> <?php echo htmlspecialchars(getHost()); ?><br>
                        <strong>Auto-Detected URL:</strong> <?php echo htmlspecialchars($autoDetectedBaseUrl); ?><br>
                        <strong>Active Base URL:</strong> <?php echo htmlspecialchars(getBaseUrl()); ?><br>
                        <?php if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])): ?>
                            <strong>Behind Proxy:</strong> Yes (X-Forwarded-Proto: <?php echo htmlspecialchars($_SERVER['HTTP_X_FORWARDED_PROTO']); ?>)<br>
                        <?php endif; ?>
                        <?php if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])): ?>
                            <strong>Forwarded Host:</strong> <?php echo htmlspecialchars($_SERVER['HTTP_X_FORWARDED_HOST']); ?><br>
                        <?php endif; ?>
                    </small>
                </div>
            </div>
        </div>
        </div>
        
        <!-- User Management Section -->
        <div class="settings-tab-panel" data-settings-panel="user-management">
        <div class="card">
            <div class="card-header">
                <h2>👥 Create New User</h2>
            </div>
            <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="username">Username *</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password *</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email">
                    </div>
                    
                    <div class="form-group">
                        <label for="upload_quota">Upload Quota (MB)</label>
                        <input type="number" id="upload_quota" name="upload_quota" value="1024" step="1" min="1" required>
                        <small>Default: 1024 MB (1 GB)</small>
                    </div>
                </div>
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="role">User Role</label>
                        <select id="role" name="role">
                            <option value="user" selected>User - Can manage own files</option>
                            <option value="admin">Admin - Full system access</option>
                        </select>
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="is_temporary" name="is_temporary" onchange="toggleExpiryDate()">
                        <label for="is_temporary" style="margin: 0">Temporary User</label>
                    </div>
                    
                    <div class="form-group" id="expiry_date_group" style="display: none;">
                        <label for="expiry_date">Expiry Date</label>
                        <input type="datetime-local" id="expiry_date" name="expiry_date">
                    </div>
                </div>
                
                <button type="submit" class="btn">Create User</button>
            </form>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>🔑 Create Access Code</h2>
            </div>
            <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create_access_code">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="max_uses">Max Uses</label>
                        <input type="number" id="max_uses" name="max_uses" value="1" min="1" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_upload_quota">Upload Quota (MB)</label>
                        <input type="number" id="code_upload_quota" name="upload_quota" value="1024" step="1" min="1" required>
                        <small>Default: 1024 MB (1 GB)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_expiry_date">Expiry Date (optional)</label>
                        <input type="datetime-local" id="code_expiry_date" name="expiry_date">
                    </div>
                </div>
                
                <button type="submit" class="btn">Create Access Code</button>
            </form>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>👥 Manage Users</h2>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Type</th>
                        <th>Quota</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td>
                                <?php 
                                $userRole = isset($user['role']) && !empty($user['role']) ? $user['role'] : ($user['is_admin'] ? 'admin' : 'user');
                                if ($userRole === 'admin'): ?>
                                    <span class="badge badge-danger">Admin</span>
                                <?php else: ?>
                                    <span class="badge badge-info">User</span>
                                <?php endif; ?>
                                <?php if ($user['is_temporary']): ?>
                                    <span class="badge badge-warning">Temporary</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php echo $fileManager->formatBytes($user['used_quota']); ?> / 
                                <?php echo $fileManager->formatBytes($user['upload_quota']); ?>
                            </td>
                            <td>
                                <?php if ($user['is_active']): ?>
                                    <span class="badge badge-success">Active</span>
                                <?php else: ?>
                                    <span class="badge badge-danger">Inactive</span>
                                <?php endif; ?>
                                <?php if ($user['is_temporary'] && $user['expiry_date']): ?>
                                    <br><small>Expires: <?php echo date('Y-m-d H:i', strtotime($user['expiry_date'])); ?></small>
                                <?php endif; ?>
                            </td>
                            <td><?php echo $user['last_login'] ? date('Y-m-d H:i', strtotime($user['last_login'])) : 'Never'; ?></td>
                            <td>
                                <?php $userQuotaMb = round(((float)$user['upload_quota']) / 1024 / 1024, 2); ?>
                                <button
                                    type="button"
                                    class="btn btn-small"
                                    onclick="openUserEditModal(this)"
                                    data-user-id="<?php echo (int)$user['id']; ?>"
                                    data-username="<?php echo htmlspecialchars($user['username']); ?>"
                                    data-email="<?php echo htmlspecialchars($user['email'] ?? ''); ?>"
                                    data-upload-quota="<?php echo htmlspecialchars((string)$userQuotaMb); ?>"
                                    data-role="<?php echo htmlspecialchars($userRole); ?>"
                                >Edit</button>
                                <?php if ($user['username'] !== 'admin'): ?>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure?')">
                                        <input type="hidden" name="action" value="delete_user">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                        <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="user-edit-modal" class="modal" aria-hidden="true">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>✏️ Edit User</h3>
                    <button type="button" class="btn-close" onclick="closeUserEditModal()">&times;</button>
                </div>
                <form method="POST">
                    <input type="hidden" name="action" value="update_user">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" id="edit_user_id" name="user_id" value="">

                    <div class="form-group">
                        <label for="edit_username">Username</label>
                        <input type="text" id="edit_username" name="edit_username" required>
                    </div>

                    <div class="form-group">
                        <label for="edit_email">Email</label>
                        <input type="email" id="edit_email" name="edit_email">
                    </div>

                    <div class="form-group">
                        <label for="edit_password">Reset Password</label>
                        <input type="password" id="edit_password" name="edit_password" minlength="8" placeholder="Leave empty to keep current password">
                    </div>

                    <div class="form-group">
                        <label for="edit_upload_quota">Upload Quota (MB)</label>
                        <input type="number" id="edit_upload_quota" name="edit_upload_quota" min="1" step="0.01" required>
                    </div>

                    <div class="form-group role-toggle">
                        <label for="edit_is_admin" style="margin: 0;">Account Type</label>
                        <label class="switch">
                            <input type="checkbox" id="edit_is_admin" name="edit_is_admin" value="1" onchange="updateRoleLabel()">
                            <span class="slider"></span>
                        </label>
                        <span id="edit_role_label" class="badge badge-info">User</span>
                    </div>

                    <div class="checkbox-group">
                        <input type="checkbox" id="clear_mfa" name="clear_mfa" value="1">
                        <label for="clear_mfa" style="margin: 0;">Clear MFA (TOTP + Email)</label>
                    </div>

                    <div class="modal-actions">
                        <button type="button" class="btn btn-secondary" onclick="closeUserEditModal()">Cancel</button>
                        <button type="submit" class="btn">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>🔑 Manage Access Codes</h2>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                <thead>
                    <tr>
                        <th>Code</th>
                        <th>Uses</th>
                        <th>Quota</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($accessCodes)): ?>
                        <tr>
                            <td colspan="6">No access codes created yet.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($accessCodes as $code): ?>
                            <tr>
                                <td class="code-display"><?php echo htmlspecialchars($code['code']); ?></td>
                                <td><?php echo $code['current_uses']; ?> / <?php echo $code['max_uses']; ?></td>
                                <td>
                                    <?php echo $fileManager->formatBytes($code['used_quota']); ?> / 
                                    <?php echo $fileManager->formatBytes($code['upload_quota']); ?>
                                </td>
                                <td>
                                    <?php if ($code['is_active'] && $code['current_uses'] < $code['max_uses']): ?>
                                        <span class="badge badge-success">Active</span>
                                    <?php else: ?>
                                        <span class="badge badge-danger">Inactive</span>
                                    <?php endif; ?>
                                    <?php if ($code['expiry_date']): ?>
                                        <br><small>Expires: <?php echo date('Y-m-d H:i', strtotime($code['expiry_date'])); ?></small>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($code['created_at'])); ?></td>
                                <td>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure?')">
                                        <input type="hidden" name="action" value="delete_code">
                                        <input type="hidden" name="code_id" value="<?php echo $code['id']; ?>">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                        <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
                    </table>
                </div>
            </div>
        </div>
        </div>

        <div class="settings-tab-panel" data-settings-panel="security-events">
            <div class="card">
                <div class="card-header">
                    <h2>🛡️ Security Events</h2>
                </div>
                <div class="card-body">
                    <form method="GET" class="form-group" style="margin-bottom: 1.25rem;">
                        <input type="hidden" name="settings_tab" value="security-events">

                        <div class="form-grid">
                            <div class="form-group">
                                <label for="security_severity">Severity</label>
                                <select id="security_severity" name="security_severity">
                                    <option value="" <?php echo $securityEventFilters['severity'] === '' ? 'selected' : ''; ?>>All</option>
                                    <option value="info" <?php echo $securityEventFilters['severity'] === 'info' ? 'selected' : ''; ?>>Info</option>
                                    <option value="warning" <?php echo $securityEventFilters['severity'] === 'warning' ? 'selected' : ''; ?>>Warning</option>
                                    <option value="critical" <?php echo $securityEventFilters['severity'] === 'critical' ? 'selected' : ''; ?>>Critical</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label for="security_event_type">Event Type</label>
                                <select id="security_event_type" name="security_event_type">
                                    <option value="" <?php echo $securityEventFilters['event_type'] === '' ? 'selected' : ''; ?>>All</option>
                                    <?php foreach ($securityEventTypes as $eventTypeOption): ?>
                                        <option value="<?php echo htmlspecialchars($eventTypeOption); ?>" <?php echo $securityEventFilters['event_type'] === $eventTypeOption ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($eventTypeOption); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="form-group">
                                <label for="security_date_from">Date From</label>
                                <input type="date" id="security_date_from" name="security_date_from" value="<?php echo htmlspecialchars($securityEventFilters['date_from']); ?>">
                            </div>

                            <div class="form-group">
                                <label for="security_date_to">Date To</label>
                                <input type="date" id="security_date_to" name="security_date_to" value="<?php echo htmlspecialchars($securityEventFilters['date_to']); ?>">
                            </div>
                        </div>

                        <div class="form-grid">
                            <div class="form-group">
                                <label for="security_search">Search</label>
                                <input type="text" id="security_search" name="security_search" value="<?php echo htmlspecialchars($securityEventFilters['search']); ?>" placeholder="Event, username, IP, identifier, context">
                            </div>
                        </div>

                        <div class="btn-row">
                            <button type="submit" class="btn btn-primary">Apply Filters</button>
                            <a href="settings.php?settings_tab=security-events" class="btn btn-secondary">Clear Filters</a>
                        </div>
                    </form>

                    <form method="POST" style="margin-bottom: 1.25rem;">
                        <input type="hidden" name="action" value="export_security_events">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        <input type="hidden" name="security_severity" value="<?php echo htmlspecialchars($securityEventFilters['severity']); ?>">
                        <input type="hidden" name="security_event_type" value="<?php echo htmlspecialchars($securityEventFilters['event_type']); ?>">
                        <input type="hidden" name="security_date_from" value="<?php echo htmlspecialchars($securityEventFilters['date_from']); ?>">
                        <input type="hidden" name="security_date_to" value="<?php echo htmlspecialchars($securityEventFilters['date_to']); ?>">
                        <input type="hidden" name="security_search" value="<?php echo htmlspecialchars($securityEventFilters['search']); ?>">
                        <div class="btn-row">
                            <button type="submit" class="btn btn-secondary">Export CSV</button>
                        </div>
                    </form>

                    <?php if (empty($securityEvents)): ?>
                        <div class="alert alert-info">No security events recorded yet.</div>
                    <?php else: ?>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Severity</th>
                                        <th>Event</th>
                                        <th>User</th>
                                        <th>IP</th>
                                        <th>Identifier</th>
                                        <th>Context</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($securityEvents as $event): ?>
                                        <tr>
                                            <td><?php echo date('Y-m-d H:i:s', strtotime($event['created_at'])); ?></td>
                                            <td>
                                                <?php if ($event['severity'] === 'critical'): ?>
                                                    <span class="badge badge-danger">Critical</span>
                                                <?php elseif ($event['severity'] === 'warning'): ?>
                                                    <span class="badge badge-warning">Warning</span>
                                                <?php else: ?>
                                                    <span class="badge badge-info">Info</span>
                                                <?php endif; ?>
                                            </td>
                                            <td><?php echo htmlspecialchars($event['event_type']); ?></td>
                                            <td><?php echo htmlspecialchars($event['username'] ?? 'System'); ?></td>
                                            <td><?php echo htmlspecialchars($event['ip_address']); ?></td>
                                            <td><?php echo htmlspecialchars($event['identifier']); ?></td>
                                            <td>
                                                <small class="event-context" title="<?php echo htmlspecialchars($event['context_json'] ?? ''); ?>">
                                                    <?php
                                                        $contextPreview = $event['context_json'] ?? '';
                                                        if (strlen($contextPreview) > 80) {
                                                            $contextPreview = substr($contextPreview, 0, 77) . '...';
                                                        }
                                                        echo htmlspecialchars($contextPreview === '' ? '-' : $contextPreview);
                                                    ?>
                                                </small>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <script>
            const validSettingsTabs = ['user-settings', 'user-management', 'site-settings', 'security-events'];

            function switchSettingsTab(tabName) {
                if (!validSettingsTabs.includes(tabName)) {
                    tabName = 'user-settings';
                }

                const tabButtons = document.querySelectorAll('.settings-tab-button');
                const tabPanels = document.querySelectorAll('.settings-tab-panel');
                let hasActivePanel = false;

                tabButtons.forEach((btn) => {
                    const isActive = btn.getAttribute('data-settings-tab') === tabName;
                    btn.classList.toggle('active', isActive);
                });

                tabPanels.forEach((panel) => {
                    const isActive = panel.getAttribute('data-settings-panel') === tabName;
                    panel.classList.toggle('active', isActive);
                    if (isActive) {
                        hasActivePanel = true;
                    }
                });

                if (!hasActivePanel && tabName !== 'user-settings') {
                    switchSettingsTab('user-settings');
                    return;
                }

                try {
                    localStorage.setItem('settings_active_tab', tabName);
                } catch (error) {
                }
            }

            function toggleExpiryDate() {
                const checkbox = document.getElementById('is_temporary');
                const expiryGroup = document.getElementById('expiry_date_group');
                expiryGroup.style.display = checkbox.checked ? 'flex' : 'none';
            }

            function toggleSmtpAuthFields() {
                const authCheckbox = document.getElementById('smtp_auth_required');
                const authFields = document.getElementById('smtp_auth_fields');

                if (!authCheckbox || !authFields) {
                    return;
                }

                authFields.style.display = authCheckbox.checked ? 'grid' : 'none';
            }
            
            function clearBaseUrl() {
                document.getElementById('base_url').value = '';
                document.getElementById('base_url').closest('form').submit();
            }

            function updateRoleLabel() {
                const roleToggle = document.getElementById('edit_is_admin');
                const roleLabel = document.getElementById('edit_role_label');

                if (!roleToggle || !roleLabel) {
                    return;
                }

                if (roleToggle.checked) {
                    roleLabel.textContent = 'Admin';
                    roleLabel.classList.remove('badge-info');
                    roleLabel.classList.add('badge-danger');
                } else {
                    roleLabel.textContent = 'User';
                    roleLabel.classList.remove('badge-danger');
                    roleLabel.classList.add('badge-info');
                }
            }

            function openUserEditModal(button) {
                const modal = document.getElementById('user-edit-modal');
                if (!modal) {
                    return;
                }

                document.getElementById('edit_user_id').value = button.dataset.userId || '';
                document.getElementById('edit_username').value = button.dataset.username || '';
                document.getElementById('edit_email').value = button.dataset.email || '';
                document.getElementById('edit_upload_quota').value = button.dataset.uploadQuota || '1024';
                document.getElementById('edit_password').value = '';
                document.getElementById('clear_mfa').checked = false;

                const role = (button.dataset.role || 'user').toLowerCase();
                document.getElementById('edit_is_admin').checked = role === 'admin';
                updateRoleLabel();

                modal.style.display = 'flex';
                modal.setAttribute('aria-hidden', 'false');
            }

            function closeUserEditModal() {
                const modal = document.getElementById('user-edit-modal');
                if (!modal) {
                    return;
                }

                modal.style.display = 'none';
                modal.setAttribute('aria-hidden', 'true');
            }

            window.addEventListener('click', function (event) {
                const modal = document.getElementById('user-edit-modal');
                if (modal && event.target === modal) {
                    closeUserEditModal();
                }
            });

            const hasSettingsTabs = document.querySelector('.settings-tab-button') !== null;
            if (hasSettingsTabs) {
                let initialTab = '<?php echo (isset($_GET['settings_tab']) && in_array($_GET['settings_tab'], ['user-settings', 'user-management', 'site-settings', 'security-events'], true)) ? htmlspecialchars($_GET['settings_tab']) : 'user-settings'; ?>';
                try {
                    const storedTab = localStorage.getItem('settings_active_tab');
                    if (storedTab && initialTab === 'user-settings') {
                        initialTab = storedTab;
                    }
                } catch (error) {
                }

                if (!validSettingsTabs.includes(initialTab)) {
                    initialTab = 'user-settings';
                }

                switchSettingsTab(initialTab);
            }

            toggleSmtpAuthFields();
            updateRoleLabel();
        </script>
        <?php endif; ?>
    </div>
    
    <?php include 'footer.php'; ?>
</body>
</html>
