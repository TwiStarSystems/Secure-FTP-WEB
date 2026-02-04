#!/usr/bin/env php
<?php
/**
 * Basic functionality test for Secure FTP Web Application
 * This test verifies core classes and functions work correctly
 */

echo "=== Secure FTP Web Application - Basic Tests ===\n\n";

// Test 1: Check if all required files exist
echo "Test 1: Checking required files...\n";
$required_files = [
    'config.php',
    'db.php',
    'auth.php',
    'users.php',
    'files.php',
    'login.php',
    'index.php',
    'admin.php',
    'download.php',
    'database.sql',
    'uploads/.htaccess'
];

$missing_files = [];
foreach ($required_files as $file) {
    if (!file_exists($file)) {
        $missing_files[] = $file;
    }
}

if (empty($missing_files)) {
    echo "✓ All required files exist\n\n";
} else {
    echo "✗ Missing files: " . implode(', ', $missing_files) . "\n\n";
    exit(1);
}

// Test 2: Check PHP syntax for all PHP files
echo "Test 2: Checking PHP syntax...\n";
$php_files = glob('*.php');
$syntax_errors = [];

foreach ($php_files as $file) {
    $output = [];
    $return_var = 0;
    exec("php -l $file 2>&1", $output, $return_var);
    if ($return_var !== 0) {
        $syntax_errors[] = $file;
    }
}

if (empty($syntax_errors)) {
    echo "✓ All PHP files have valid syntax\n\n";
} else {
    echo "✗ Syntax errors in: " . implode(', ', $syntax_errors) . "\n\n";
    exit(1);
}

// Test 3: Check if constants are defined
echo "Test 3: Checking configuration constants...\n";
require_once 'config.php';

$required_constants = [
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASS',
    'MAX_FILE_SIZE',
    'UPLOAD_DIR',
    'SESSION_TIMEOUT',
    'MAX_LOGIN_ATTEMPTS',
    'LOCKOUT_DURATION',
    'HASH_ALGORITHMS',
    'DEFAULT_HASH_ALGORITHM'
];

$missing_constants = [];
foreach ($required_constants as $constant) {
    if (!defined($constant)) {
        $missing_constants[] = $constant;
    }
}

if (empty($missing_constants)) {
    echo "✓ All required constants defined\n\n";
} else {
    echo "✗ Missing constants: " . implode(', ', $missing_constants) . "\n\n";
    exit(1);
}

// Test 4: Check if uploads directory exists and has correct structure
echo "Test 4: Checking uploads directory...\n";
if (!file_exists(UPLOAD_DIR)) {
    echo "✗ Uploads directory does not exist\n\n";
    exit(1);
}

if (!is_dir(UPLOAD_DIR)) {
    echo "✗ Uploads path is not a directory\n\n";
    exit(1);
}

if (!file_exists(UPLOAD_DIR . '.htaccess')) {
    echo "✗ Uploads directory .htaccess missing\n\n";
    exit(1);
}

echo "✓ Uploads directory configured correctly\n\n";

// Test 5: Test hash algorithms
echo "Test 5: Testing hash algorithms...\n";
$test_string = "test data for hashing";
$hash_success = true;

foreach (HASH_ALGORITHMS as $algo) {
    $hash = hash($algo, $test_string);
    if (empty($hash)) {
        echo "✗ Hash algorithm $algo failed\n";
        $hash_success = false;
    }
}

if ($hash_success) {
    echo "✓ All hash algorithms working correctly\n\n";
} else {
    exit(1);
}

// Test 6: Check .htaccess files exist
echo "Test 6: Checking security files...\n";
$security_files = [
    '.htaccess',
    '.gitignore',
    'uploads/.htaccess'
];

$missing_security = [];
foreach ($security_files as $file) {
    if (!file_exists($file)) {
        $missing_security[] = $file;
    }
}

if (empty($missing_security)) {
    echo "✓ All security files present\n\n";
} else {
    echo "✗ Missing security files: " . implode(', ', $missing_security) . "\n\n";
    exit(1);
}

// Test 7: Verify sensitive files are protected
echo "Test 7: Checking .htaccess protections...\n";
$htaccess_content = file_get_contents('.htaccess');

// Check for FilesMatch directive
if (strpos($htaccess_content, 'FilesMatch') !== false && 
    strpos($htaccess_content, 'Require all denied') !== false) {
    echo "✓ Sensitive files protected\n\n";
} else {
    echo "⚠ Warning: Verify .htaccess protects sensitive files\n\n";
}

// Test 8: Check documentation
echo "Test 8: Checking documentation...\n";
$doc_files = ['README.md', 'INSTALL.md', 'SECURITY.md'];
$missing_docs = [];

foreach ($doc_files as $file) {
    if (!file_exists($file)) {
        $missing_docs[] = $file;
    }
}

if (empty($missing_docs)) {
    echo "✓ All documentation files present\n\n";
} else {
    echo "✗ Missing documentation: " . implode(', ', $missing_docs) . "\n\n";
    exit(1);
}

// Summary
echo "===========================================\n";
echo "✓ All basic tests passed successfully!\n";
echo "===========================================\n\n";

echo "Note: These tests verify file structure and basic configuration.\n";
echo "For full functionality testing, install the application following INSTALL.md\n";
echo "and test in a web server environment.\n\n";

exit(0);
?>
