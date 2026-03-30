<?php
// Bootstrap file for Secure FTP Web Application
// Defines base path constants used throughout the application

if (!defined('APP_BASE')) {
    define('APP_BASE', dirname(__DIR__));
}

if (!defined('APP_DIR')) {
    define('APP_DIR', __DIR__);
}

require_once APP_DIR . '/src/core/config.php';
