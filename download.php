<?php
// File download handler
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'files.php';

$db = new Database();
$auth = new Auth($db);
$fileManager = new FileManager($db, $auth);

// Check if logged in
if (!$auth->isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Get file ID
$fileId = $_GET['id'] ?? null;

if (!$fileId) {
    die('Invalid file ID');
}

// Download file
$result = $fileManager->downloadFile($fileId);

if (!$result['success']) {
    die('Error: ' . $result['error']);
}

// Sanitize filename to prevent header injection
$safeFilename = preg_replace('/[^\w\-\.]/', '_', $result['filename']);
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
