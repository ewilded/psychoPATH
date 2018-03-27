<?php

if(isset($_GET['file']))
{
	$file=str_replace('../','',$_GET['file']);
	$file=str_replace('./','',$file);
	echo @file_get_contents('./'.$file);
}
#removing ../ then ./
?>

