#!/usr/bin/perl
#############################################################################
#
# Virus Scanner
# Last Change: Sat Mar  2 18:01:25 WET 2002
# Copyright (c) 2002 Henrique Dias <hdias@esb.ucp.pt>
#
#############################################################################
use strict;
use File::Scan;
use Getopt::Long();
use Benchmark;

my $VERSION = "0.07";

my $infected = 0;
my $objects = 0;
my $skipped = 0;

my $EXTENSION = "";
my $CP_DIR = "";
my $MV_DIR = "";
my $MK_DIR = 0;
my $DELETE = 0;
my $FOLLOW = 0;
my $MAXTXTSIZE = 0;
my $MAXBINSIZE = 0;

my %skipcodes = (
	1 => "file not vulnerable",
	2 => "file has zero size",
	3 => "the size of file is small",
	4 => "file size exceed the maximum text size",
	5 => "file size exceed the maximum binary size",
);

die(short_usage()) unless(scalar(@ARGV));

my $opt = {};
Getopt::Long::GetOptions($opt,
	"help"         => \&usage,
	"version"      => \&print_version,
	"ext=s"        => \$EXTENSION,
	"cp=s"         => \$CP_DIR,
	"mv=s"         => \$MV_DIR,
	"mkdir=s"      => \$MK_DIR,
	"del"          => sub { $DELETE = 1; },
	"follow"       => sub { $FOLLOW = 1; },
	"maxtxtsize=i" => \$MAXTXTSIZE,
	"maxbinsize=i" => \$MAXBINSIZE,
) or die(short_usage());

&main();

#---main---------------------------------------------------------------------

sub main {

	my $start = new Benchmark;
	&check_path(\@ARGV);
	my $finish = new Benchmark;
	my $diff = timediff($finish, $start);
	my $strtime = timestr($diff);

	print <<ENDREPORT;

Results of virus scanning:
--------------------------
Objects scanned: $objects 
        Skipped: $skipped
       Infected: $infected
      Scan Time: $strtime

ENDREPORT

        exit(0);
}

#---display_msg-------------------------------------------------------------

sub display_msg {
	my $file = shift;
	my $virus = shift;

	$objects++;
	my $string = "No viruses were found";
	if($virus) {
		$infected++;
		$string = "Infection: $virus";
	}
	print "$file $string\n";
	return();
}

#---check_path--------------------------------------------------------------

sub check_path {
	my $args = shift;

	my @args = ();
	push(@args, "max_txt_size", $MAXTXTSIZE) if($MAXTXTSIZE);
	push(@args, "max_bin_size", $MAXBINSIZE) if($MAXBINSIZE);

	my $fs = File::Scan->new(
		extension => $EXTENSION,
		copy      => $CP_DIR,
		mkdir     => oct($MK_DIR),
		move      => $MV_DIR,
		delete    => $DELETE,
		@args);
	for my $p (@{$args}) {
		if(-d $p) {
			$p =~ s{\/+$}{}g;
			&dir_handle($fs, $p);
		} elsif(-e $p) {
			my $res = $fs->scan($p);
			if(my $e = $fs->error) { print"$e\n"; }
			elsif(my $c = $fs->skipped) {
				$skipped++;
				print "$p File Skipped (" . $skipcodes{$c} . ")\n";
			} else { &display_msg($p, $res); }
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

	unless(-r $dir_path) {
		print "Permission denied at $dir_path\n";
		return();
	}
	opendir(DIRHANDLE, $dir_path) or die("can't opendir $dir_path: $!");
	for my $item (readdir(DIRHANDLE)) {
		next if($item =~ /^\./);
		my $f = "$dir_path/$item";
		next if(!$FOLLOW && (-l $f));
		if(-d $f) {
			&dir_handle($fs, $f);
		} else {
			my $res = $fs->scan($f);
			if(my $e = $fs->error) { print"$e\n"; }
			elsif(my $c = $fs->skipped) {
				$skipped++;
				print "$f File Skipped (" . $skipcodes{$c} . ")\n";
			} else { &display_msg($f, $res); }
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
  --mkdir=octal_number
  --del
  --follow
  --maxtxtsize=size
  --maxbinsize=size
  --version
  --help
        
EOUSAGE

}

#---print_version-----------------------------------------------------------

sub print_version {
	print STDERR <<"VERSION";

version $VERSION

Copyright 2002, Henrique Dias

VERSION
	exit 1;
}

#---usage-------------------------------------------------------------------

sub usage {
	print STDERR <<"USAGE";
Usage: $0 [options] file|directory

Possible options are:

  --ext=<string>        add the specified extension to the infected file

  --mv=<dir>            move the infected file to the specified directory

  --cp=<dir>            copy the infected file to the specified directory

  --mkdir=octal_number  make the specified directories (ex: 0755)

  --del                 delete the infected file

  --follow              follow symbolic links

  --maxtxtsize=<size>   scan only the text file if the file size is less
                        then maxtxtsize (size in kbytes)
 
  --maxbinsize=<size>   scan only the binary file if the file size is less
                        then maxbinsize (size in kbytes)

  --version             print version number

  --help                print this message and exit

USAGE
	exit 1;
}

#---end---------------------------------------------------------------------
