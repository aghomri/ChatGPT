<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

echo "<h3>Testing includes</h3>";

include 'db.php';
include 'sraps.php';
include 'extensions.php';

echo "<p>Everything loaded without fatal error.</p>";
