#!/usr/bin/perl
#############################################################################
#
# Virus Scanner
# Last Change: Wed Feb 13 10:35:32 WET 2002
# Copyright (c) 2002 Henrique Dias <hdias@esb.ucp.pt>
#
#############################################################################
use strict;
use File::Scan;
use Getopt::Long();

my $VERSION = "0.01";

my $infected = 0;
my $objects = 0;

my $EXTENSION = "";
my $CP_DIR = "";
my $MV_DIR = "";
my $DELETE = 0;

die(short_usage()) unless(scalar(@ARGV));

my $opt = {};
Getopt::Long::GetOptions($opt,
	"help" => \&usage,
	"ext"  => \$EXTENSION,
	"cp"   => \$CP_DIR,
	"mv"   => \$MV_DIR,
	"del"  => sub { $DELETE = 1; },
) or die(short_usage());

&main();

#---main---------------------------------------------------------------------

sub main {

	my $ti = time();
	&check_path(\@ARGV);
	my $tf = time() - $ti;

	print <<ENDREPORT;

Results of virus scanning:
--------------------------
Objects scanned: $objects 
       Infected: $infected
Scan Time (sec): $tf

ENDREPORT

        exit(0);
}

#---display_msg-------------------------------------------------------------

sub display_msg {
	my $file = shift;
	my $virus = shift;

	$objects++;
	if($virus) {
		$infected++;
		print "$file Infection: $virus\n";
	}
	return();
}

#---check_path--------------------------------------------------------------

sub check_path {
	my $args = shift;

	my $fs = File::Scan->new(
		extension => $EXTENSION,
		copy      => $CP_DIR,
		move      => $MV_DIR,
		delete    => $DELETE);
	for my $p (@{$args}) {
		if(-d $p) {
			$p =~ s{\/+$}{}g;
			&dir_handle($fs, $p);
		} elsif(-e $p) {
			my $res = $fs->scan($p);
			if(my $e = $fs->error) { print"$e\n"; }
			&display_msg($p, $res);
		} else {
			print "No such file or directory: $p\n";
			exit(0);
		}
	}
	return();
}

#---dir_handle--------------------------------------------------------------

sub dir_handle {
	my $fs = shift;
	my $dir_path = shift;

	opendir(DIRHANDLE, $dir_path) or die("can't opendir $dir_path: $!");
	for my $item (readdir(DIRHANDLE)) {
		next if($item =~ /^\./);
		my $f = "$dir_path/$item";
		if(-d $f) {
			&dir_handle($fs, $f);
		} else {
			my $res = $fs->scan($f);
			if(my $e = $fs->error) { print"$e\n"; }
			&display_msg($f, $res);
		}
	}
	closedir(DIRHANDLE);
	return();
}

#---short_usage-------------------------------------------------------------

sub short_usage {

	return(<<"EOUSAGE");
usage: $0 [options] file|directory

  --ext=string_extension
  --cp=/path/to/dir
  --mv=/path/to/dir
  --del
  --help
        
EOUSAGE

}

#---usage-------------------------------------------------------------------

sub usage {
	print STDERR <<"USAGE";
Usage: $0 [options] file|directory

Possible options are:

  --ext=<string> add the specified extension to the infected file

  --mv=<dir>     move the infected file to the specified directory

  --cp=<dir>     copy the infected file to the specified directory

  --del          delete the infected file

  --help         Print this message and exit

USAGE
	exit 1;
}

#---end---------------------------------------------------------------------
