<?php
$fname=$_GET['file'];

## this one's recurrent and expected to fail when dealing with mix of no-encoding+double encoding (with only nix slashes in use)
while(stripos($fname,"../"!=FALSE))
{
	$fname=str_replace('../','',$fname);
}
$fname=urldecode($fname);
echo file_get_contents('./'.$fname);
?>
