<?php
$fname=$_GET['file'].".txt";

## this one's recurrent and expected to fail when dealing with mix of no-encoding+double encoding (with only nix slashes in use)

$fnames=explode(" ",$fname);
foreach($fnames as $f)
{
	echo file_get_contents("../".$fname);
}
?>
