<?php
$fname=$_GET['file'];
echo file_get_contents("./".$fname);
?>
