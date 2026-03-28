<?php
/**
 * Nova-1 Observatory - Alignment Log Viewer v1.0.2
 */
$page = $_GET['view'] ?? '';

if ($page) {
    // VULNERABLE LINE: Including user-controlled input without sanitization
    // The developer only intended for files inside logs/ to be read.
    include("logs/" . $page); 
} else {
    echo "<h1>[ NOVA-1 OBSERVATORY ]</h1>";
    echo "<p>Welcome to the historical log viewer. Please select a transmission to analyze.</p>";
}
?>

<div style="margin-top: 50px; font-family: 'Share Tech Mono', monospace; border: 1px solid #00ff00; padding: 20px; color: #00ff00; background: #000;">
    <h3>Log System Inventory:</h3>
    <ul>
        <li><a href="?view=alignment_2023.log" style="color: #00ff00;">alignment_2023.log</a></li>
        <li><a href="?view=solar_event_01.log" style="color: #00ff00;">solar_event_01.log</a></li>
        <li><a href="?view=calibration.txt" style="color: #00ff00;">calibration.txt</a></li>
    </ul>
</div>
