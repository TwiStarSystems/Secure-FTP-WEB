<?php
// File download handler
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'files.php';
require_once 'security_monitor.php';

$db = new Database();
$auth = new Auth($db);
$fileManager = new FileManager($db, $auth);
$securityMonitor = new SecurityMonitor($db);
$securityMonitor->cleanupOldData();

// Check if logged in
if (!$auth->isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Get file ID
$fileId = $_GET['id'] ?? null;

$currentUser = $auth->getCurrentUser();
$accessCode = $auth->getCurrentAccessCode();
$actorId = $currentUser ? 'user_' . $currentUser['id'] : ($accessCode ? 'code_' . $accessCode['id'] : 'unknown');
$clientIp = $securityMonitor->getClientIp();
$requestIdentifier = 'download:' . $actorId . ':' . $clientIp;

$requestRate = $securityMonitor->registerRequest(
    'download_request',
    $requestIdentifier,
    MAX_DOWNLOAD_REQUESTS_WINDOW,
    DOWNLOAD_REQUEST_WINDOW_SECONDS,
    DOWNLOAD_REQUEST_LOCKOUT_SECONDS
);

if (!$requestRate['allowed']) {
    $securityMonitor->logEvent('download_rate_limited', 'warning', $currentUser['id'] ?? null, $requestIdentifier, [
        'retry_after' => $requestRate['retry_after']
    ]);
    http_response_code(429);
    die('Too many download requests. Please try again later.');
}

$failureLock = $securityMonitor->getLockStatus('download_failure', $requestIdentifier);
if ($failureLock['locked']) {
    $securityMonitor->logEvent('download_failure_lockout_active', 'warning', $currentUser['id'] ?? null, $requestIdentifier, [
        'retry_after' => $failureLock['retry_after']
    ]);
    http_response_code(429);
    die('Too many failed download attempts. Please try again later.');
}

if (!$fileId) {
    $securityMonitor->registerFailure(
        'download_failure',
        $requestIdentifier,
        MAX_DOWNLOAD_FAILURE_ATTEMPTS,
        DOWNLOAD_FAILURE_WINDOW_SECONDS,
        DOWNLOAD_FAILURE_LOCKOUT_SECONDS
    );
    $securityMonitor->logEvent('download_invalid_request', 'warning', $currentUser['id'] ?? null, $requestIdentifier, [
        'reason' => 'missing_file_id'
    ]);
    die('Invalid file ID');
}

if (!ctype_digit((string)$fileId)) {
    $securityMonitor->registerFailure(
        'download_failure',
        $requestIdentifier,
        MAX_DOWNLOAD_FAILURE_ATTEMPTS,
        DOWNLOAD_FAILURE_WINDOW_SECONDS,
        DOWNLOAD_FAILURE_LOCKOUT_SECONDS
    );
    $securityMonitor->logEvent('download_invalid_request', 'warning', $currentUser['id'] ?? null, $requestIdentifier, [
        'reason' => 'non_numeric_file_id',
        'file_id' => (string)$fileId
    ]);
    die('Invalid file ID');
}

// Download file
$result = $fileManager->downloadFile($fileId);

if (!$result['success']) {
    $lockState = $securityMonitor->registerFailure(
        'download_failure',
        $requestIdentifier,
        MAX_DOWNLOAD_FAILURE_ATTEMPTS,
        DOWNLOAD_FAILURE_WINDOW_SECONDS,
        DOWNLOAD_FAILURE_LOCKOUT_SECONDS
    );

    $securityMonitor->logEvent('download_denied', 'warning', $currentUser['id'] ?? null, $requestIdentifier, [
        'file_id' => intval($fileId),
        'error' => $result['error'],
        'locked' => $lockState['locked']
    ]);

    if ($lockState['locked']) {
        http_response_code(429);
        die('Too many failed download attempts. Please try again later.');
    }

    die('Error: ' . $result['error']);
}

$securityMonitor->clearCounter('download_failure', $requestIdentifier);

// Sanitize filename to prevent header injection - replace spaces with underscores
$safeFilename = str_replace(' ', '_', $result['filename']);
$safeFilename = preg_replace('/[^\w\-\.]/', '_', $safeFilename);
$safeFilename = str_replace(["\r", "\n", "\0"], '', $safeFilename);

// Set headers for file download
header('Content-Type: ' . $result['mime_type']);
header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
header('Content-Length: ' . filesize($result['filepath']));
header('Cache-Control: no-cache, must-revalidate');
header('Pragma: public');

// Output file
readfile($result['filepath']);
exit;
?>
