#
# Scan.pm
# Last Modification: Mon May 27 12:04:13 WEST 2002
#
# Copyright (c) 2002 Henrique Dias <hdias@esb.ucp.pt>. All rights reserved.
# This module is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.
#
#
package File::Scan;

require 5;
use strict;

require Exporter;
use File::Copy;
use SelfLoader;

use vars qw($VERSION @ISA @EXPORT $ERROR $SKIPPED $SUSPICIOUS);

@ISA = qw(Exporter);
$VERSION = '0.28';

$ERROR = "";
$SKIPPED = 0;
$SUSPICIOUS = 0;

SelfLoader->load_stubs();

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self  = {
		extension    => "",
		delete       => 0,
		move         => "",
		copy         => "",
		mkdir        => 0,
		max_txt_size => 5120,
		max_bin_size => 10240,
		@_,
	};
	bless ($self, $class);
	return($self);
}

sub scan {
	my $self = shift;
	my $file = shift;

	&set_error();
	&set_skip();
	&set_suspicious();
	return(&set_error("No such file or directory: $file")) unless(-e $file);
	my $fsize = -s $file;
	return(&set_skip(2)) unless($fsize);
	my $res = "";
	if(-f $file && -T $file) {
		return(&set_skip(3)) if($fsize < 23);
		return(&set_skip(4))
			if($self->{'max_txt_size'} && ($fsize > $self->{'max_txt_size'} * 1024));
		$res = &scan_text($file);
	} else {
		return(&set_skip(5))
			if($self->{'max_bin_size'} && ($fsize > $self->{'max_bin_size'} * 1024));
		$res = &scan_binary($file);
	}
	if($res) {
		if($self->{'extension'} && $file !~ /\.$self->{'extension'}$/o) {
			my $newname = "$file\." . $self->{'extension'};
			if(move($file, $newname)) { $file = $newname; }
			else { &set_error("Failed to move '$file' to $newname"); }
		}
		if($self->{'copy'}) {
			if(!(-d $self->{'copy'}) && $self->{'mkdir'}) {
				mkdir($self->{'copy'}, $self->{'mkdir'}) or &set_error("Failed to create directory '" . $self->{'copy'} . "' $!");
			}
			my ($f) = ($file =~ /([^\/]+)$/o);
			my $cpdir = $self->{'copy'} . "/$f";
			copy($file, $cpdir) or &set_error("Failed to copy '$file' to $cpdir");
		}
		if($self->{'move'}) {
			if(!(-d $self->{'move'}) && $self->{'mkdir'}) {
				mkdir($self->{'move'}, $self->{'mkdir'}) or &set_error("Failed to create directory '" . $self->{'move'} . "' $!");
			}
			my ($f) = ($file =~ /([^\/]+)$/o);
			my $mvfile = $self->{'move'} . "/$f";
			if(move($file, $mvfile)) { $file = $mvfile; }
			else { &set_error("Failed to move '$file' to $mvfile"); }
		}
		if($self->{'delete'}) {
			if($file =~ /^(.+)$/s) {
				unlink($1) or &set_error("Could not delete $1: $!");
			}
		}
	}
	return($res);
}

sub set_error {
	$ERROR = shift || "";  
	return();
}

sub set_skip {
	$SKIPPED = shift || 0;
	return();
}

sub set_suspicious {
	$SUSPICIOUS = shift || 0;
	return();
}

sub error { $ERROR; }
sub skipped { $SKIPPED; }
sub suspicious { $SUSPICIOUS; }

1;

__DATA__
# generated in: 2002/05/27 12:06:41

sub get_app_sign {
	$_ = pop;
	/^\x49\x54\x53\x46/o and return($_[0] = 1);
	/^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1/o and return($_[0] = 2);
	/^\x47\x45\x54/o and return($_[0] = 3);
	/^\xe9/o and return($_[0] = 4);
	/^\x4d\x5a/o and $_[0] = 5;
	/^\x4d\x5a\x00\x00\x02/o and return($_[1] = 1);
	/^\x4d\x5a\x42\x00\x02/o and return($_[1] = 2);
	/^\x4d\x5a\x50\x00\x02/o and return($_[1] = 3);
	/^\x4d\x5a\x90\x00\x03/o and return($_[1] = 4);
	/^\x7f\x45\x4c\x46/o and return($_[0] = 6);
	return(0);
}

sub exception {
	$_ = shift;
	return(/^%PDF-/o ? 1 : 0);
}

sub scan_text {
	my $file = shift;

	my $buff = "";
	my $save = "";
	my $skip = 0;
	my $virus = "";
	my $script = "";
	my $size = 1024;
	open(FILE, "<$file") or return(&set_error("$!"));
	LINE: while(read(FILE, $buff, $size)) {
		unless($save) { last LINE if($skip = &exception($buff)); }
		study;
		$save .= $buff;
		unless($script) {
			$_ = lc($save);
			/< *script[^>]+language *=["' ]*vbscript["']*[^>]*>/os and $script = "HTMLVBS";
			/< *script[^>]+language *=["' ]*javascript["']*[^>]*>/os and $script = "HTMLJS";
		}
		$_ = $save;
		if($script) {
			if($script eq "HTMLVBS") {
				/\x4d\x73\x65\x6e\x64\x20\x28\x6d\x6d\x61\x69\x6c\x29.+\x45\x6e\x64\x20\x49\x66.+\x45\x6e\x64\x20\x53\x75\x62.+\x46\x75\x6e\x63\x74\x69\x6f\x6e\x20\x53\x63\x28\x53\x29.+\x6d\x4e\x20\x3d\x20.+\x52\x65\x6d\x20\x49\x20\x61\x6d\x20\x73\x6f\x72\x72\x79\x21\x20\x68\x61\x70\x70\x79\x20\x74\x69\x6d\x65.+/s and $virus = "VBS/Haptime.a\@MM", last LINE;
			}
		} else {
			/\x58\x35\x4f\x21\x50\x25\x40\x41\x50\x5b\x34\x5c\x50\x5a\x58\x35\x34\x28\x50\x5e\x29\x37\x43\x43\x29\x37\x7d\x24\x45\x49\x43\x41\x52\x2d\x53\x54\x41\x4e\x44\x41\x52\x44\x2d\x41\x4e\x54\x49\x56\x49\x52\x55\x53\x2d\x54\x45\x53\x54\x2d\x46\x49\x4c\x45\x21\x24\x48\x2b\x48\x2a/s and $virus = "EICAR-Test-File", last LINE;
			/\x50\x72\x69\x6e\x7a\x20\x43\x68\x61\x72\x6c\x65\x73\x20\x41\x72\x65\x20\x44\x69\x65.+\x54\x68\x65\x20\x6e\x65\x77\x65\x73\x74\x20\x4d\x65\x73\x73\x61\x67\x65\x20\x66\x6f\x72\x20\x43\x6f\x6f\x6c\x20\x55\x73\x65\x72.+\x76\x62\x63\x72\x6c\x66.+\x4c\x75\x63\x6b\x79\x32\x30\x30\x30.+\x43\x4f\x4f\x4c\x5f\x4e\x4f\x54\x45\x50\x41\x44\x5f\x44\x45\x4d\x4f\x2e\x54\x58\x54.\x76\x62\x73/s and $virus = "VBS/CoolNote.worm", last LINE;
			/\x57\x65\x62\x53\x65\x72\x76\x69\x63\x65\x2c\x76\x4c\x69\x73\x74\x2c\x69\x74\x65\x6d\x2c\x76\x46\x6f\x75\x6e\x64\x2c\x76\x53\x75\x62\x44\x61\x6e\x2c\x44\x61\x6e\x67\x65\x72\x2c\x76\x4e\x65\x77\x43\x6f\x75\x6e\x74\x2c\x46\x6f\x75\x6e\x64\x53\x74\x72\x69\x6e\x67.+\x46\x75\x6e\x63\x74\x69\x6f\x6e\x20\x46\x69\x6e\x64\x4d\x61\x70\x70\x65\x72.+\x46\x6f\x75\x6e\x64.+\x53\x74\x72\x31.+\x43\x68\x72.+\x44\x65\x6c\x4d\x61\x70\x70\x65\x72.+\x44\x61\x6e\x67\x65\x72.+\x41\x72\x72\x61\x79.+\x53\x63\x72\x69\x70\x74\x4d\x61\x70\x73/s and $virus = "W32/CodeBlue.worm", last LINE;
			/\x57\x53\x48\x53\x68\x65\x6c\x6c.+\x57\x53\x63\x72\x69\x70\x74\x2e\x53\x68\x65\x6c\x6c.+\x48\x4b\x45\x59\x5f\x4c\x4f\x43\x41\x4c\x5f\x4d\x41\x43\x48\x49\x4e\x45.+\x65\x78\x65\x66\x69\x6c\x65.+\x5c\x63\x6f\x6e\x5c\x63\x6f\x6e.+\x57\x65\x6c\x63\x6f\x6d\x65.+\x69\x6e\x74\x44\x6f\x49\x74.+\x76\x62\x43\x61\x6e\x63\x65\x6c.+\x57\x53\x63\x72\x69\x70\x74\x2e\x51\x75\x69\x74/s and $virus = "VBS/Concon.gen", last LINE;
			/\x49\x52\x43\x2d\x57\x6f\x72\x6d\x2e\w+\x20+\x54\x68\x65\x6d\x65\x20\x57\x6f\x72\x6d\x20+\x42\x79/s and $virus = "IRC/Theme.worm.dr", last LINE;
			/\x4d\x61\x64\x6f\x6e\x6e\x61.+\x4a\x61\x64\x72\x61\x71\x75\x65\x72\x20\x4b\x69\x6c\x6c\x65\x72/s and $virus = "VBS/Madonna", last LINE;
			/\x43\x68\x72\x28[^\x29]+\x29.+\x4e\x65\x78\x74.+\x45\x6e\x64.+\x46\x75\x6e\x63\x74\x69\x6f\x6e.+\x56\x62\x73\x77\x67\x20\d+\x2e\d+\x2e?\x20\x5b\x4b\x5d\x41\x6c\x61\x6d\x61\x72/s and $virus = "VBS/SST\@MM", last LINE;
			/\x45\x72\x61\x73\x65\x46\x69\x6c\x65\x73.+\x46\x75\x6e\x63\x74\x69\x6f\x6e.+\x46\x69\x6c\x65\x54\x6f\x45\x72\x61\x73\x65.+\x46\x69\x6c\x65\x54\x6f\x45\x72\x61\x73\x65\x2e\x70\x61\x74\x68.+\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e.+\x54\x58\x54.+\x44\x4f\x43/s and $virus = "VBS/Eraser.A", last LINE;
			/\x46\x75\x6e\x63\x74\x69\x6f\x6e.+\x46\x6f\x72\x20\x49\x20\x3d\x20\x31\x20\x54\x6f\x20\x4c\x65\x6e\x28[^\x29]+\x29\x20\x53\x74\x65\x70\x20\x32.+\x48\x61\x76\x65\x20\x66\x75\x6e\x20\x77\x69\x74\x68\x20\x4b\x72\x69\x73\x74\x65\x6e/s and $virus = "VBS/Kristen.A\@MM", last LINE;
			/\x65\x63\x68\x6f\x20\x2e\x42\x41\x54\x20\x76\x69\x72\x75\x73\x20\x27\x40\x40\x27\x20\x76\d+\x2e\d+.+\x4f\x52\x20\x43\x58\x2c\x43\x58.+\x4a\x5a\x20\x31\x30\x42.+\x4d\x4f\x56\x20\x44\x58\x2c\x31\x30\x43.+\x4d\x4f\x56\x20\x41\x48\x2c\x34\x31.+\x49\x4e\x54\x20\x32\x31.+\x49\x4e\x54\x20\x33.+\x44\x42.+\x66\x69\x6e\x64.+\x64\x65\x62\x75\x67.+\x65\x78\x69\x73\x74.+\x63\x6f\x70\x79.+\x66\x69\x6e\x64.+\x64\x6f\x20\x63\x61\x6c\x6c.+\x64\x65\x6c/s and $virus = "BAT/Double_At.B", last LINE;
			/[\x20\x5c]\x73\x65\x72\x76\x69\x63\x65\x73\x2e\x65\x78\x65.+[\x20\x5c].+\x73\x71\x6c\x65\x78\x65\x63\x2e\x6a\x73.+[\x20\x5c]\x63\x6c\x65\x6d\x61\x69\x6c\x2e\x65\x78\x65.+[\x20\x5c]\x73\x71\x6c\x70\x72\x6f\x63\x65\x73\x73\x2e\x6a\x73.+[\x20\x5c]\x73\x71\x6c\x69\x6e\x73\x74\x61\x6c\x6c\x2e\x62\x61\x74.+[\x20\x5c]\x73\x71\x6c\x64\x69\x72\x2e\x6a\x73.+\x72\x75\x6e\x2e\x6a\x73.+[\x20\x5c]\x74\x69\x6d\x65\x72\x2e\x64\x6c\x6c.+[\x20\x5c]\x73\x61\x6d\x64\x75\x6d\x70\x2e\x64\x6c\x6c.+[\x20\x5c]\x70\x77\x64\x75\x6d\x70\x32\x2e\x65\x78\x65/s and $virus = "JS/SQL.Spida.worm.b", last LINE;
		}
		unless($script eq "HTMLJS") {
			/\x73\x75\x62\x20\x73\x70\x72\x65\x61\x64\x74\x6f\x65\x6d\x61\x69\x6c\x28\x29.+\x64\x69\x6d\x20\x78\x2c\x61\x2c\x63\x74\x72\x6c\x69\x73\x74\x73\x2c\x63\x74\x72\x65\x6e\x74\x72\x69\x65\x73\x2c\x6d\x61\x6c\x65\x61\x64\x2c\x62\x2c\x72\x65\x67\x65\x64\x69\x74\x2c\x72\x65\x67\x76\x2c\x72\x65\x67\x61\x64.+\x72\x65\x67\x76\x3d\x72\x65\x67\x65\x64\x69\x74\x2e\x52\x65\x67\x52\x65\x61\x64\x28\x22\x48\x4b\x45\x59\x5f\x43\x55\x52\x52\x45\x4e\x54\x5f\x55\x53\x45\x52\x5c\x53\x6f\x66\x74\x77\x61\x72\x65\x5c\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x5c\x57\x41\x42\x5c\x22\x26\x61\x29/s and $virus = "VBS/LoveLetter\@MM", last LINE;
		}
		$save = substr($buff, (length($buff)/2));
	}
	close(FILE);
	&set_skip($skip) if($skip);
	return($virus);
}

sub scan_binary {
	my $file = shift;

	my $skip = 0;
	my $suspicious = 0;
	my $type = 0;
	my $subtype = 0;
	my $virus = "";
	my $buff = "";
	my $save = "";
	my $total = 0;
	my $size = 1024;
	open(FILE, "<$file") or return(&set_error("$!"));
	binmode(FILE);
	LINE: while(read(FILE, $buff, $size)) {
		$total += length($buff);
		unless($save) {
			my $begin = substr($buff, 0, 8, "");
			unless(length($begin) >= 8) { $skip = 3; last LINE; }
			&get_app_sign($type, $subtype, $begin);
			unless($type) { $skip = 1; last LINE; }
		}
		study;
		$save .= $buff;
		unless($suspicious) {
			$_ = lc($save);
			$suspicious = 1 if(/\x77\x6f\x72\x6d/s ||
						/\x76\x69\x72\x75\x73[^\x70]/s ||
						/\x74\x72\x6f\x6a\x61\x6e/s ||
						/\x5b[^\x5d]+\x5d\x20\x62\x79\x20\w+/s ||
						/\x62\x61\x63\x6b\x64\x6f\x6f\x72/s ||
						/\x70\x61\x72\x61\x73\x69\x74\x65/s ||
						/\w+\x20\x63\x6f\x64\x65\x64\x20\x62\x79\x20\w+/s);
		}
		$_ = $save;
		if($type == 1) {
			if($total==5120) {
				/\x48\x48\x41\x20\x56\x65\x72\x73\x69\x6f\x6e\x20\d\x2e\d\d\x2e\d\d\d\d.+\x42\x72\x69\x74\x6e\x65\x79\x2e\x68\x74\x6d\x6c.+\x42\x72\x69\x74\x6e\x65\x79\x2d\x50\x69\x63.+\x62\x72\x69\x74\x6e\x65\x79\x2d\x70\x69\x63\x73/s and $virus = "VBS/Chick.a\@M", last LINE;
				/\x53\x48\x41\x4b\x49\x52\x41\x20\x48\x65\x6c\x70.+\x73\x68\x61\x6b\x69\x72\x61/s and $virus = "VBS/Chick.c\@M", last LINE;
				/\x48\x48\x41\x20\x56\x65\x72\x73\x69\x6f\x6e\x20\d\x2e\d\d\x2e\d\d\d\d.+\x56\x42\x20\x42\x72\x69\x74\x6e\x65\x79\x20\x64\x2e\x68\x74\x6d\x6c.+\x6f\x63\x6f\x73\x6f\x66\x74/s and $virus = "VBS/Chick.d\@M", last LINE;
			}
		} elsif($type == 2) {
			/\x57.*\x4d\x2e\x53\x70\x69\x72\x6f\x68\x65\x74\x61/s and $virus = "W97M/Generic", last LINE;
			/\x56\x4d\x50\x43\x4b\x20\x76\d+\x2e\d+\w*\x20\x5b[^\x5d]+\x5d/s and $virus = "W97/VMPCK1.gen", last LINE;
			/\x3c\x2d\x20\x74\x68\x69\x73\x20\x69\x73\x20[\w ]+\x20\x6d\x61\x72\x6b\x65\x72\x21/s and $virus = "W97/Marker.gen", last LINE;
			/\x54\x68\x75\x73\x5f\d\d\d/s and $virus = "W97/Thus.gen", last LINE;
			/\x57\x4f\x52\x44\x2f\x4d\x65\x6c\x69\x73\x73\x61\x20\x77\x72\x69\x74\x74\x65\x6e\x20\x62\x79\x20\x4b\x77\x79\x6a\x69\x62\x6f/s and $virus = "W97M/Melissa.a\@MM", last LINE;
			/\x57\x39\x37\x2e\x4e\x69\x74\x72\x6f\x67\x65\x6e/s and $virus = "W97M/Nitrogen.intd", last LINE;
			/\x6b\x69\x6c\x6c\x65\x72\x00\x6b\x00\x69\x00\x6c\x00\x6c\x00\x65\x00\x72/s and $virus = "X97M/Oblivion", last LINE;
			/\x57\x6f\x72\x64\x32\x30\x30\x30\x2e\x47\x61\x72\x47\x6c\x65/s and $virus = "W97M/Hope.gen", last LINE;
			/\x54\x68\x65\x20((\x6d\x61\x6c\x65)|(\x66\x65\x6d\x61\x6c\x65))\x20\x73\x74\x61\x67\x65\x73\x20\x6f\x66\x20\x6c\x69\x66\x65/s and $virus = "IRC/Stages.worm", last LINE;
			/\x43\x41\x50.+\x41\x75\x74\x6f\x45\x78\x65\x63.+\x41\x75\x74\x6f\x4f\x70\x65\x6e.+\x46\x69\x6c\x65\x4f\x70\x65\x6e.+\x46\x69\x6c\x65\x53\x61\x76\x65.+\x41\x75\x74\x6f\x43\x6c\x6f\x73\x65.+\x46\x69\x6c\x65\x53\x61\x76\x65\x41\x73.+\x54\x6f\x6f\x6c\x73\x4d\x61\x63\x72\x6f/s and $virus = "WM/Cap", last LINE;
		} elsif($type == 3) {
			/\x48\x4f\x53\x54\x3a\x77\x77\x77\x2e\x77\x6f\x72\x6d\x2e\x63\x6f\x6d\x0a\x20\x41\x63\x63\x65\x70\x74\x3a\x20\x2a\x2f\x2a\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x3a/s and $virus = "W32/CodeRed.a.worm", last LINE;
			/.+\x43\x6f\x64\x65\x52\x65\x64\x49\x49.+/s and $virus = "W32/CodeRed.c.worm", last LINE;
		} elsif($type == 4) {
			/\x5b\x41\x4e\x4e\x41\x5d\x00\x53\x6c\x61\x72\x74\x69\x62\x61\x72\x74\x66\x61\x73\x74\x2c\x20\x41\x52\x43\x56\x20\x4e\x75\x4b\x45\x20\x74\x68\x65\x20\x46\x72\x65\x6e\x63\x68.+\x28\x63\x29\x20\x41\x52\x63\x56\x20\d\d\d\d\x20\x2d\x20\x45\x6e\x67\x6c\x61\x6e\x64\x20\x52\x61\x69\x6e\x69\x6e\x67\x20\x41\x67\x61\x69\x6e/s and $virus = "ARCV.Anna.742", last LINE;
			/\x59\x6f\x75\x20\x63\x61\x6e\x27\x74\x20\x63\x61\x74\x63\x68\x20\x74\x68\x65\x20\x47\x69\x6e\x67\x65\x72\x62\x72\x65\x61\x64\x20\x4d\x61\x6e\x21\x21\x95/s and $virus = "Ginger.mp", last LINE;
		} elsif($type == 5) {
			if($subtype == 1) {
				if($total==1024) {
					/\x69\x77\x6f\x72\x6d\x2e\x61\x78\x6c\x38\x7a\x65/s and $virus = "W32/Aliz\@MM", last LINE;
				}
			} elsif($subtype == 2) {
				/\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x49\x2d\x57\x6f\x72\x6d\x20\x63\x6f\x64\x65\x64\x20\x62\x79\x20\x42\x75\x6d\x62\x6c\x65\x62\x65\x65\x5c\d+.\x21\x0a\x0a\x47\x72\x65\x74\x69\x6e\x67\x7a\x20\x74\x6f\x20\x61\x6c\x6c\x20\d+.\x20\x6d\x65\x6d\x62\x65\x72\x73\x20\x3b\x29/s and $virus = "W32/Gift.b\@MM", last LINE;
				/\x54\x68\x69\x73\x20\x69\x73\x20\x50\x6c\x61\x67\x65\x20\d{4}\x20\x63\x6f\x64\x65\x64\x20\x62\x79\x20\x42\x75\x6d\x62\x6c\x65\x62\x65\x65\x2f\d+.\x2e\x00\x50\x6c\x61\x67\x65\x20\d{4}\x20\x41\x63\x74\x69\x76\x61\x74\x69\x6f\x6e/s and $virus = "W32/Plage.gen\@M", last LINE;
			} elsif($subtype == 3) {
				if($total>184320) {
					/\x4b\x49\x4c\x54\x52\x4f\x20\x2a\x20\x4d\x53\x4e\x57\x48/s and $virus = "W32/Kitro\@MM", last LINE;
				}
				if($total>30720 && $total<32768) {
					/\x77\x61\x72\x67\x61\x6d\x65\x73\x2e\x65\x78\x65/s and $virus = "W32/Warga\@MM", last LINE;
				}
				if($total==3072) {
					/\x56\x69\x72\x75\x73\x20\x2d\x20\x4f\x72\x65\x5a\x52\x61\x74\x53\x20\x5b\x49\x6b\x78\x5d\x20\x28\x43\x29\x20\d\d\d\d/s and $virus = "W32/Orez", last LINE;
				}
				if($total<=2048) {
					/\x49\x2d\x57\x6f\x72\x6d\x2e\x4a\x61\x70\x61\x6e\x69\x7a\x65/s and $virus = "W32/Fbound.c\@MM", last LINE;
				}
				if($total==2048) {
					/\x48\x61\x69\x6b\x75\x20\x47\x65\x6e\x65\x72\x61\x74\x6f\x72/s and $virus = "W32/Haiku\@MM", last LINE;
				}
				if($total==159744) {
					/\x56\x74\x69\x70.+\x57\x69\x74\x7a.+\x62\x6c\x61\x67.+\x4a\x6f\x6b\x65.+\x5a\x61\x72\x74/s and $virus = "W32/Cervivec\@MM", last LINE;
				}
				if($total==6144) {
					/\x49\x2d\x57\x6f\x72\x6d\x20\x45\x6c\x69\x73\x61\x62\x65\x74\x68\x20\x62\x79\x20\x5a\x69\x72\x6b\x6f\x76/s and $virus = "W32/Trilisa\@MM", last LINE;
				}
				if($total==366592) {
					/\x54\x72\x6f\x6a\x61\x6e\x65\x72\x2d\x49\x6e\x66\x6f/s and $virus = "W32/Yarner.gen\@MM", last LINE;
				}
				if($total==129024) {
					/\x00\x00\x00\x00\x90\x60\xe9\x3d\x04\x00\x00\xdb\x95\xad\x0c\x33\x5a\xa9\xb7\x03\x88\xed\x0c\x30\x6c\x82\x91\xe3\x8e\xed\x0c\xb0\x0c\x55\x45\x77\xb1\xa9\x85\xae\x4d\xe0\x48\x33\xbe\x2c\x6a\x30\xb1\xa9\xcb\xb6\x82\x90\x48\x33\xb1\xa9\x0c\x33\x3c\x2c\x08\x79\xf5\xa9\x5c\xcc/s and $virus = "W32/Benjamin.worm", last LINE;
				}
			} elsif($subtype == 4) {
				/\x47\x69\x72\x6c\x73\x00\x5a\x69\x70\x57\x6f\x72\x6d\x00\x00\x7a\x69\x70\x57\x6f\x72\x6d/s and $virus = "IRC/Girls.worm", last LINE;
				if($total<=5120) {
					/\x71\d{6}.+\x00\x61.\x76.\x65.\x73.\x5c.\x50.\x72.\x6f.\x6a.\x65.\x63.\x74.\x56.\x69.\x72.\x75.\x73.\x5c.\x49.\x6e.\x73.\x74.\x61.\x6c.\x6c.\x20.\x50.\x61.\x72.\x74.\x5c.\x71.\d.\d.\d.\d.\d.\d.+/s and $virus = "W32/Gibe\@MM", last LINE;
				}
				if($total==10240) {
					/\x43\x00\x68\x00\x6f\x00\x6b\x00\x65\x00\x20\x00\x2c\x00\x20\x00\x43\x00\x6f\x00\x70\x00\x79\x00\x72\x00\x69\x00\x67\x00\x68\x00\x74\x00\x20\x00\xae\x00\x20\x00\x31\x00\x38\x00\x38\x00\x36/s and $virus = "W32/Choke.gen.worm", last LINE;
				}
				if($total==1024) {
					/\x2e\x74\x65\x78\x74\x00\x00\x00\x00.\x00\x00\x00\x10\x00\x00..\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\xe0\x2e\x72\x64\x61\x74\x61\x00\x00\x00\x10\x00\x00\x00.\x00\x00\x5a\x00\x00\x00\x00.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\xc0/s and $virus = "W32/Hybrys.gen\@MM", last LINE;
				}
				if($total==267264) {
					/\x7a\x68\x61\x6e\x67\x70\x6f\x00\x58\x2d\x4d\x61\x69\x6c\x65\x72/s and $virus = "W32/Zhangpo\@MM", last LINE;
				}
				if($total==21504) {
					/\x53\x7f\xf3\xff\xff\x75\x6e\x4d\x6f\x6e\x54\x75\x65\x57\x65\x64\x54\x68\x75\x46\x72\x69\x53\x61\x74\x4a\x61\x6e\x46\x65\x62\x4d\xff\xb7\x76\xfb\x61\x72\x41\x70\x72\x05\x79\x4a\x26\x02\x6c\x41\x75\x67\x53\x65\x70\x4f\x63\x74\x5b\x81\xfa\xfd\x4e\x6f\x76\x44\x65\x63\x3f\x54\x5a\x1b\x1c\x74\x7b\xb7\xa9\xff\x69\x6d/s and $virus = "W32/Myparty.b\@MM", last LINE;
				}
				if($total==3072) {
					/\x7a\x61\x72\x79\x32\x30+.+\x40\x65\x6d\x61\x69\x6c\x2e\x63\x6f\x6d/s and $virus = "W32/MyLife.e\@MM", last LINE;
				}
				if($total==11264) {
					/\x49\x00\x20\x00\x63\x00\x6f\x00\x6d\x00\x65\x00\x20\x00\x69\x00\x6e\x00\x20\x00\x70\x00\x69\x00\x65\x00\x63\x00\x65\x00\x2e\x00\x20\x00\x20\x00\x20\x00\x4d\x00\x79\x00\x20\x00\x6e\x00\x61\x00\x6d\x00\x65\x00\x20\x00\x69\x00\x73\x00\x20\x00\x4a\x00\x65\x00\x72\x00\x72\x00\x79/s and $virus = "W32/Choke.c.worm", last LINE;
				}
				if($total==2048) {
					/\xff\x01\x06\x00\x53\x48\x41\x52\x4f\x4e\x00\x19\x93\x42\x00\x22/s and $virus = "W32/MyLife.j\@MM", last LINE;
				}
				if($total==14336) {
					/\x47\x00\x6f\x00\x62\x00\x6f\x00.+\x74\x00\x65\x00\x61\x00\x6d\x00\x76\x00\x69\x00\x72\x00\x75\x00\x73.+\x4b\x00\x61\x00\x72\x00\x65\x00\x6e/s and $virus = "W32/Gokar\@MM", last LINE;
				}
				if($total<=4096) {
					/\x70\x65\x6e\x74\x61\x67\x6f\x6e\x65/s and $virus = "W32/Goner\@MM", last LINE;
				}
				if($total==37888) {
					/\x5c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x73\x00\x00\x00\x43\x6f\x6e\x63\x65\x70\x74\x20\x56\x69\x72\x75\x73\x28\x43\x56\x29\x20\x56\x2e\d\x2c\x20\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x28\x43\x29\d\d\d\d.{10,}\x4d\x49\x4d\x45\x2d\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x31\x2e\x30/s and $virus = "W32/Nimda.gen\@MM", last LINE;
				}
				if($total>8192 && $total<=20480) {
					/\x44*\x65\x63.+\x4e*\x6f\x76.+\x4f*\x63\x74.+\x53*\x65\x70.+\x41*\x75\x67.+\x4a*\x75\x6c.+\x4d*\x61\x79.+\x46\x65\x62\x13\x61\x53\x61\x27\x46\x72\x69\x00\x54\x68\x75\x00.\x9d\x5b\xfe\x57\x65\x64\x00\x54\x75\x65\x6f\x17\x2f.+\x32\x75/s and $virus = "W32/BadTrans\@MM", last LINE;
				}
				if($total==22528) {
					/\x57\x00\x49\x00\x4e\x00\x4c\x00\x30\x00\x47\x00\x30\x00\x4e\x00\x2e\x00\x45\x00\x58\x00\x45/s and $virus = "W32/Shoho.gen\@MM", last LINE;
				}
				if($total==35840) {
					/\x73\x6d\x74\x70\x2e\x79\x65\x61\x68\x2e\x6e\x65.+\x2d\x20\x47\x45\x54\x20\x4f\x49\x43\x51/s and $virus = "W32/GOP\@MM", last LINE;
				}
			}
			if($total<=6144) {
				/\x77\x6f\x72\x6d\x49\x77\x69\x6e\x67.+\x57\x69\x6e\x33\x32\x2e\x20\x49\x6d\x65\x6c\x64\x61\x20\x74\x68\x65\x20\x56\x42\x20\x56\x69\x72\x75\x73/s and $virus = "W32/Alcop.gen\@MM", last LINE;
			}
			/\x53\x43\x61\x6d\x33\x32/s and $virus = "W32/SirCam\@MM", last LINE;
			/\x57\x69\x6e\x33\x32\x2e\x48\x4c\x4c\x50\x2e\x5a\x61\x75\x73\x68\x6b\x61\x2e\x57\x6f\x72\x6d\x00\x5a\x61\x75\x73\x68\x6b\x61\x00/s and $virus = "W32/HLLP.32767.a", last LINE;
			/\x76\x65\x6e\x63\x65\x20\x65\x6d\x20.+\x74\x65\x73\x74\x65\x40\x69\x65\x67\x2e\x63\x6f\x6d\x2e\x62\x72.+\x69\x6d\x65\x72/s and $virus = "W32/Enviar.gen\@M", last LINE;
			/\x57\x69\x6e\x33\x32\x2f\x41\x73\x74\x72\x6f\x47\x69\x72\x6c\x20\x41\x73\x74\x72\x6f\x43\x6f\x64\x65\x64\x20\x62\x79\x20\x61\x20\x57\x61\x7a\x65\x78\x00\x59\x6f\x75\x72\x20\x73\x79\x73\x74\x65\x6d\x20\x69\x73\x20\x69\x6e\x66\x65\x63\x74\x65\x64\x20\x62\x79\x20\x57\x69\x6e\x33\x32\x2f\x41\x73\x74\x72\x6f\x47\x69\x72\x6c\x20\x76\d+\x2e\d+.+\x44\x65\x64\x69\x63\x61\x74\x65\x64\x20\x74\x6f\x20\x41\x6e\x69\x74\x61\x20\x61\x6e\x64\x20\x6f\x75\x72\x20\x70\x65\x6e\x67\x2d\x67\x75\x69\x6e\x20\x3b\x29\x0d/s and $virus = "Win32.Asorl", last LINE;
			/\x4b\x52\x45\x41\x54\x49\x56\x49\x54\x59\x20\x46\x4f\x52\x20\x4b\x41\x54\x53/s and $virus = "W32/Javel.512", last LINE;
			/\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x70\x2e\x69\x63\x71\x2e\x63\x6f\x6d\x2f\x73\x63\x72\x69\x70\x74\x73\x2f\x57\x57\x50\x4d\x73\x67\x2e\x64\x6c\x6c\x3f\x66\x72\x6f\x6d\x3d\w+\x26\x66\x72\x6f\x6d\x65\x6d\x61\x69\x6c\x3d\w+\x40\w+\x2e\w+\x26\x73\x75\x62\x6a\x65\x63\x74\x3d\x50\x72\x6f\x67\x72\x61\x6d\x2b\x65\x78\x65\x63\x75\x74\x69\x6f\x6e\x26\x62\x6f\x64\x79\x3d\x54\x68\x65\x2b\x70\x65\x72\x73\x6f\x6e\x2b\x74\x68\x61\x74\x2b\x73\x65\x6e\x74\x2b\x74\x68\x69\x73\x2b\x70\x61\x67\x65\x72\x2c\x2b\x69\x73\x2b\x77\x69\x74\x68\x2b\x61\x2b\x66\x69\x6c\x65\x2b\x67\x65\x6e\x65\x72\x61\x74\x65\x64\x2b\x62\x79\x2b\x4a\x75\x6e\x74\x61\x64\x6f\x72\x26\x74\x6f\x3d\d{6,}\x26\x73\x65\x6e\x64\x3d.+/s and $virus = "MultiDropper-BN", last LINE;
			/\x76\x69\x72\x75\x73\x65\x73.+\x65\x78\x70\x6c\x6f\x69\x74.+\x70\x61\x74\x63\x68\x20\x68\x61\x73\x20\x62\x65\x65\x6e\x20\x73\x75\x70\x70\x6c\x69\x65\x64\x20\x77\x69\x74\x68\x20\x74\x68\x69\x73\x20\x65\x6d\x61\x69\x6c\x20\x61\x6e\x64\x20\x77\x69\x6c\x6c\x20\x66\x69\x78\x20\x74\x68\x65\x20\x73\x65\x63\x75\x72\x69\x74\x79\x20\x68\x6f\x6c\x65.+\x70\x61\x74\x63\x68\x2e\x65\x78\x65/s and $virus = "W32/Heidi\@MM", last LINE;
			/\x59\x61\x70\x21\x20\x57\x68\x61\x74\x20\x63\x6f\x75\x6c\x64\x20\x69\x74\x20\x42\x20\x3f\xa8\x20\x49\x74\x27\x73\x20\x59\x2e\x41\x2e\x50\x2e\x20\x28\x59\x65\x74\x20\x41\x6e\x6f\x74\x68\x65\x72\x20\x50\x61\x72\x61\x73\x69\x74\x65\x29/s and $virus = "HLLP.Yap.8421", last LINE;
			/\x57\x49\x4e\x33\x32\x2e\x50\x49\x4c\x53\x45\x4e\x20\x56\x49\x52\x55\x53\x20\x62\x79\x20\x49\x6e\x74\x31\x33\x68\x2f\x49\x4b\x58\x00\x4d\x61\x44\x65\x20\x69\x4e\x20\x50\x61\x52\x61\x47\x75\x41\x79/s and $virus = "W32/Pilsen.cmp.4096", last LINE;
			/\x5b\x57\x69\x6e[^\x5d]+\x5d\x20\x62\x79\x20\x52\x61\x74\x74\x65\x72\x2f\d+/s and $virus = "W32/Ratter.by", last LINE;
			/\xeb\x5a\x46\x69\x6e\x64\x46\x69\x72\x73\x74\x46\x69\x6c\x65\x41\x00\x46\x69\x6e\x64\x4e\x65\x78\x74\x46\x69\x6c\x65\x41\x00\x43\x72\x65\x61\x74\x65\x46\x69\x6c\x65\x41\x00\x5f\x6c\x63\x6c\x6f\x73\x65\x00\x53\x65\x74\x46\x69\x6c\x65\x50\x6f\x69\x6e\x74\x65\x72\x00\x52\x65\x61\x64\x46\x69\x6c\x65\x00\x57\x72\x69\x74\x65\x46\x69\x6c\x65\x00\x0b\x2a\x2e\x45\x58\x45\x00/s and $virus = "W95/Puma", last LINE;
			/\x5b\x57\x69\x6e\x33\x32\x2e[^\x5d]+\x5d\x20.+\x20\x47\x69\x67\x61\x62\x79\x74\x65\x2f\x4d\x65\x74\x61\x70\x68\x61\x73\x65/s and $virus = "W32/GMetaphase.by\@MM", last LINE;
			/\x5b\x69\x4b\x78\x5d\x20\x28\x63\x29\x20\x31\x39\x39\x39\x20\x61\x6c\x6c\x20\x72\x69\x67\x68\x74\x20\x72\x65\x73\x65\x72\x76\x65\x64\x20\x2d\x20\x70\x72\x65\x73\x65\x6e\x74\x20\x41\x6c\x64\x65\x42\x61\x72\x61\x6e/s and $virus = "W32/Adebar.dr", last LINE;
			/\x2e\x41\x56\x58\x65\x6e\x63\x72/s and $virus = "W32/XTC\@MM", last LINE;
			/\w{6}\x20\x2d\x20\x72\x6f\x79\x20\x67\x20\x62\x69\x76.+/s and $virus = "W32/Chiton.dr", last LINE;
			/\x57\x69\x6e[\x32\x33\x35\x38\x39]{2}\x2e\w+\x2e*\w*\x20\x62\x79\x20\w+.+\x67\x65\x6e\x65\x72\x61*\x74\x69\x6f\x6e\x20\x76\x69\x72\x75\x73\x20/s and $virus = "W32/Blakan", last LINE;
			/\x53\x6f\x66\x74\x77\x61\x72\x65\x20\x70\x72\x6f\x76\x69\x64\x65\x20\x62\x79\x20\x5b\x4d\x41\x54\x52\x69\x58\x5d\x20\x56\x58\x20\x74\x65\x61\x6d/s and $virus = "W32/MTX.gen\@M", last LINE;
			/\x5b\x57\x69\x6e\x33\x32\x2e\x4f\x72\x61\x6e\x67\x65\x20\x62\x79\x20\x45\x62\x6f\x6c\x61\x5d\x00\x44\x65\x64\x69\x63\x61\x74\x65\x64\x20\x74\x6f\x20\x74\x68\x65\x20\x4e\x59\x46\x44\x20\x61\x6e\x64\x20\x4e\x59\x50\x44\x2e/s and $virus = "W32/Awfull", last LINE;
			/\x43\x6f\x64\x65\x64\x20\x62\x79\x20\x47\x72\x69\x59\x6f.+\x32\x39\x41/s and $virus = "W32/GriYo.29A.by", last LINE;
			/\x5b\x57\x69\x6e\x32\x6b\x2e\x4a\x6f\x73\x73\x5d\x20\x62\x79\x20\x52\x61\x74\x74\x65\x72\x2f\d\d\x41/s and $virus = "W32/Joss.919", last LINE;
			/\x57\x49\x4e\x33\x32\x2e\x42\x4f\x52\x47\x45\x53\x20\x56\x49\x52\x55\x53\x20\d+\x2e\d+\x20\x62\x79\x20\x49\x6e\x74\d+\x68\x2f\x49\x4b\x58\x00\x4d\x61\x64\x65\x20\x69\x6e\x20\x50\x61\x72\x61\x67\x75\x61\x79\x2c\x20\x53\x6f\x75\x74\x68\x20\x41\x6d\x65\x72\x69\x63\x61/s and $virus = "W32/Borges.cmp", last LINE;
			/\x14\xff\x56\xb9\x36\xdc\x5a\xbd\x1b\x93\xeb\xea\x5f\x21\xb8\x35\x73\x1b\xfc\xa6\xdc\x6f\x01\x24\x8b\x14\x85\xb8\x6c\x28\x0d\x3b\xd1\x74\x09\x40\xb3\xbb\x95\x4a\x1a\x74\x15\x72\xe5\x1a\x89\x0c\x8b\x00\xcf\xb7\x90\x49\x24\xfe\x81\xc3\x22\x8d\xa5\x68\x7a\xb4/s and $virus = "BackDoor.arsd", last LINE;
			/\x08\xb5\x6d\xea\x46\x82\x32\x67\x62\x42\x2b\x16\x59\x97\xcb\xdb\x40\x1c\x02\xd2\x43\x40\xa0\x99\x65\x20\x99\x2a\x9d\xa1\x21\xa1\xa1\x1d\x55\x05\x19\x01\x57\x55\x32\x8c\x41\xc5\x08\x01\x76\x0a\x43\x0f\x81\x87\xb0\xda\x18\x3d\x42\x28\x28\xa8\x80\xac\xd2\xe9/s and $virus = "W32/Navidad.e\@M", last LINE;
			/\x0d\x0a\x2e\x0d\x0a\x00\x00\x00\x44\x41\x54\x41\x20\x0d\x0a\x00\x48\x45\x4c\x4f\x20\x25\x73\x0d\x0a\x00\x00\x00\x3e\x0d\x0a\x00\x4d\x41\x49\x4c\x20\x46\x52\x4f\x4d\x3a\x20\x3c\x00\x00\x00\x00\x52\x43\x50\x54\x20\x54\x4f\x3a\x3c\x00\x00\x00\x25\x64\x00\x00/s and $virus = "W32/Klez.gen\@MM", last LINE;
			if($total>102400 && $total<=160000) {
				/\x49\x2d\x57\x6f\x72\x6d\x2e\x53\x75\x70\x65\x72\x4e\x6f\x76\x61/s and $virus = "W32/Sintesys\@MM", last LINE;
			}
			if($total==1024) {
				/\x00{2}..\x00{13}[^\x00]\x00\x00.\x2e.{5}\x00\x00\xed[^\x00](\x00|\x01)\x00\x00..\x00\x00.(\x00|\x01)\x00\x00..\x00{13}.\x00\x00[^\x00][^\x2e]/s and $virus = "W32/Magistr.b\@MM", last LINE;
				/\x00{2}..\x00{13}[^\x00]\x00\x00.\x2e.{5}\x00\x00\xec[^\x00](\x00|\x01)\x00\x00..\x00\x00.(\x00|\x01)\x00\x00..\x00{13}.\x00\x00[^\x00][^\x2e]/s and $virus = "W32/Magistr.a\@MM", last LINE;
			}
			if($total>2048) {
				/\x57\x69\x6e\x33\x32\x2e\x4e\x65\x6f\x20\x56\x69\x72\x75\x73\x20\x62\x79\x20\x5b\x54\x69\x50\x69\x61\x58\x2f\x56\x44\x53\x5d\x00\x4d\x69\x61\x6d\x20\x21\x20\x49\x20\x6c\x6f\x76\x65\x20\x50\x45\x20\x66\x69\x6c\x65\x73\x20\x3b\x29/s and $virus = "W95/Miam.dr", last LINE;
				/\x7e\x46\x75\x6e\x20\x4c\x6f\x76\x69\x6e\x67\x20\x43\x72\x69\x6d\x69\x6e\x61\x6c\x7e/s and $virus = "W32/FunLove.4099", last LINE;
			}
			if($total<=4096) {
				/\x49\x2d\x57\x6f\x72\x6d\x2e\x46\x72\x69\x65\x6e\x64\x73\x00\x43\x6f\x64\x65\x64\x20\x62\x79\x20\x50\x65\x74\x69\x4b\x20\x28\x63\x29\x32\x30\x30\x31.+\x54\x6f\x20\x6d\x79\x20\x66\x72\x69\x65\x6e\x64\x73\x20\x4d\x61\x79\x61\x20\x61\x6e\x64\x20\x4c\x61\x75\x72\x65\x6e\x74/s and $virus = "W32/PetTick\@MM", last LINE;
			}
			if($total>=7168 && $total<8192) {
				/\x4a\x54\x4d\x20\x2d\x20\x66\x72\x6f\x6d\x20\x65\x5b\x61\x78\x5d\x20\x74\x6f\x20\x48\x6f\x6d\x65\x72\x20\x54\x68\x61\x20\x50\x69\x6c\x65/s and $virus = "W32/HLL.ow.24590", last LINE;
			}
			if($total>1024) {
				/\x4e\x45\x54\x2e\x64\x6f\x74\x4e\x45\x54\x20\x62\x79\x20\x42\x65\x6e\x6e\x79\x2f\x32\x39\x41/s and $virus = "W32/Donut.dr", last LINE;
				/\x57\x69\x6e\x33\x32\x2e\x47\x69\x72\x69\x67\x61\x74\x20\x69\x73\x20\x6e\x6f\x77\x20\x61\x63\x74\x69\x76\x65\x21/s and $virus = "W32/Giri.dr", last LINE;
				/\x4a\x6f\x6b\x65\x72\d+/s and $virus = "W95/Rekoj.GR", last LINE;
				/\x57\x71\x6b.+\x3d\x75\x73\x65\x72\x58\x75.+\x5c\x65\x78\x70\x6c\x6f\x72\x65\x72/s and $virus = "W95/Elkern.cav.c", last LINE;
			}
		} elsif($type == 6) {
			if($total==4096) {
				/\x2f\x74\x6d\x70\x2f\x76\x69\x72\x75\x73\x2e\x63\x00\x2f\x74\x6d\x70\x2f\x76\x69\x63\x74\x75\x6d/s and $virus = "Linux/Manpage", last LINE;
			}
		}
		$save = substr($buff, (length($buff)/2));
	}
	close(FILE);
	&set_skip($skip) if($skip);
	$suspicious = 0 if($virus);
	&set_suspicious($suspicious) if($suspicious);
	return($virus);
}

__END__

=head1 NAME

File::Scan - Perl extension for Scanning files for Viruses

=head1 SYNOPSIS

  use File::Scan;

  $fs = File::Scan->new([, OPTION ...]);
  $fs->scan([FILE]);
  if(my $e = $fs->error) { print "$e\n"; }
  if(my $c $fs->skipped) { print "file skipped ($c)\n"; }
  if($fs->suspicious) { print "suspicious file\n"; }

=head1 DESCRIPTION

This module is designed to allows users to scan files for known viruses.
The purpose is to provide a perl module to make plataform independent
virus scanners.

=head1 METHODS

=head2 new([, OPTION ...])

This method create a new File::Scan object. The following keys are 
available:

=over 6

=item extension => 'string'

add the specified extension to the infected file

=item move => 'directory'

move the infected file to the specified directory

=item copy => 'directory'

copy the infected file to the specified directory

=item mkdir => octal_number

if the value is set to octal number then make the specified directories
(example: mkdir => 0755).

=item delete => 0 or 1

if the value is set to 1 delete the infected file

=item max_txt_size => 'size in kbytes'

scan only the text file if the file size is less then max_txt_size. The
default value is 5120 kbytes. Set to 0 for no limit.

=item max_bin_size => 'size in kbytes'

scan only the binary file if the file size is less then max_bin_size. The
default value is 10240 kbytes. Set to 0 for no limit.

=back

=head2 scan([FILE])

This method scan a file for viruses and return the name of virus if a
virus is found.

=head2 skipped()

This method return a code number if the file was skipped and 0 if not. The 
following skipped codes are available:

=over 6

=item 0

file not skipped 

=item 1

file is not vulnerable

=item 2

file has zero size

=item 3

the size of file is small

=item 4

the text file size is greater that the 'max_txt_size' argument

=item 5

the binary file size is greater that the 'max_bin_size' argument

=back

=head2 suspicious()

This method return 1 if the file is suspicious and 0 if not.

=head2 error()

This method return a error message if a error happens.

=head1 AUTHOR

Henrique Dias <hdias@esb.ucp.pt>

=head1 CREDITS

Thanks to Rui de Castro, Sergio Castro, Ricardo Oliveira, Antonio
Campelo, Branca Silveira, Helena Gomes and Anita Afonso for the help.

Thanks to Fernando Martins for the personal collection of viruses.

=head1 SEE ALSO

perl(1).

=cut
