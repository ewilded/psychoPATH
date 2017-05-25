<?php

if(isset($_GET['file']))
{
	$file=str_replace('..','',$_GET['file']);
	$file=str_replace(' ','',$file); // removing white spaces
	echo @file_get_contents('./'.$file);
}
#removing .. then white spaces
?>

