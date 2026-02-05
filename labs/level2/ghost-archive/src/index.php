<?php
$file = $_GET['doc'] ?? 'welcome.txt';
if ($file) {
    include($file);
}
?>
<hr>
<ul>
    <li><a href="?doc=welcome.txt">Welcome</a></li>
    <li><a href="?doc=policy.txt">Policy</a></li>
    <li><a href="?doc=credits.txt">Credits</a></li>
</ul>
