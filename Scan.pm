#
# Scan.pm
# Last Modification: Thu Feb 14 12:20:05 WET 2002
#
# Copyright (c) 2001 Henrique Dias <hdias@esb.ucp.pt>. All rights reserved.
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

use vars qw($VERSION @ISA @EXPORT $ERROR $virustxt %keywords);

@ISA = qw(Exporter);
$VERSION = '0.01';

$ERROR = "";

SelfLoader->load_stubs();

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self  = {
		extension => "",
		delete    => 0,
		move      => "",
		copy      => "",
		@_,
	};
	bless ($self, $class);
	&load_txt_signs();
	return($self);
}

sub scan {
	my $self = shift;
	my $file = shift;

	&set_error("");
	return(&set_error("No such file or directory: $file")) unless(-e $file);
	return(&set_error("File has zero size (is empty): $file")) if(-z $file);
	my $res = (-T $file) ? &scan_text($file) : &scan_binary($file);
	if($res) {
		if($self->{'extension'} && $file !~ /\.$self->{'extension'}$/o) {
			my $newname = "$file\." . $self->{'extension'};
			if(move($file, $newname)) { $file = $newname; }
			else { &set_error("Failed to move '$file' to $newname"); }
		}
		if($self->{'copy'}) {
			my ($f) = ($file =~ /([^\/]+)$/o);
			my $cpdir = $self->{'copy'} . "/$f";
			copy($file, $cpdir) or &set_error("Failed to copy '$file' to $cpdir");
		}
		if($self->{'move'}) {
			my ($f) = ($file =~ /([^\/]+)$/o);
			my $mvdir = $self->{'move'} . "/$f";
			if(move($file, $mvdir)) { $file = $mvdir; }
			else { &set_error("Failed to move '$file' to $mvdir"); }
		}
		if($self->{'delete'}) {
			if($file =~ /^(.+)$/s) {
				unlink($1) or &set_error("could not delete $1: $!");
			}
		}
	}
	return($res);
}

sub set_error {
	my $string = shift;
	$ERROR = $string;  
	return();
}
sub error {
	my $self = shift;
	return($ERROR);  
}

1;

__DATA__
# last change: 2002/02/14 12:25:53
sub load_txt_signs() {
	$virustxt = {
		"VBS/Carnival.gen\@MM" => ["Prinz_Charles_Are_Die.TXT.vbs","Prinz_Charles_Are_Die","Lucky2000.ico","CLICK","BLUE","BOTTLE","ICON","DESKTOP","YOUR","HARD","DRIVE","WILL","LOST","VIRUS","DAMAGE","COMPUTER","Prinz","Charles","Cool","Lucky2000","COOL_NOTEPAD_DEMO.TXT.vbs"],
		"W32/CodeBlue.worm" => ["WebService","vList","item","vFound","vSubDan","Danger","vNewCount","FoundString","FindMapper","Str1","Str2","InStr","Found","DelMapper","Array",".ida",".idq",".printer","WebService.GetEx","ScriptMaps","ReDim","Preserve","vNew","vNewCount-1","WebService.PutEx","WebService.SetInfo","W3SVC","GetObject","LocalHost","Root"],
		"VBS/Concon.gen" => ["con","WSHShell.RegWrite","exefile","WScript.CreateObject","Sub","WSHShell","L_Welcome_MsgBox_Title_Text","Software","Welcome","Set","L_Welcome_MsgBox_Message_Text","CLASSES","Then","If","HKEY_LOCAL_MACHINE","MsgBox","WScript.Shell","open","End","shell","vbOKCancel","Dim","intDoIt","WScript.Quit","vbInformation","vbCancel","command"],
		"VBS/LoveLetter\@MM" => ["XXX","dta1","dta2","VBScript","Run","male.Recipients.Add","male","Russian","MicroSUXX","WAB","MustDie","FEAR","MYSTIQUE","regad","Please","malead","www.sexymafia.ru","MystiqueCrash","BEST","www.erogen.ru","kindly","letter","RUSSIAN","LaMER","Best","www.porno.ru"],
		"VBS/Haptime.a\@MM" => ["SCRIPT","language","VBScript","am","sorry","happy","time","CreateObject","Shell.Application","Help.htm","Help.vbs","Help.hta","help.htm","Outlook","HKEY_CURRENT_USER","Untitled.htm"],
	};
	%keywords = ();
	for my $v (values(%{$virustxt})) {
		@keywords{@{$v}} = ();
	}
}

sub scan_text {
	my$file = shift;

	my $pattern = '([\w-\.]{2,})';
	my %hash = ();
	local $/ = " ";
	open(FILE, "<$file") or return(&set_error("$!"));
	while(<FILE>) {
		while(/$pattern/osg) {
			next unless(exists($keywords{$1}));
			$hash{$1} = "";
		}
	}
	close(FILE);
	for my $name (%{$virustxt}) {
		my $found = "";
		for my $sign (@{$virustxt->{$name}}) {
			next unless(exists($hash{$sign}));
			$found = "$name";
		}
		return($found) if($found);
	}
	return();
}

sub scan_binary {
	my $file = shift;

	my $virus = "";
	my $buff = "";
	my $save = "";
	my $total = 0;
	my $size = 256;
	open(FILE, "<$file") or return(&set_error("$!"));
	binmode(FILE);
	LINE: while(read(FILE, $buff, $size)) {
		$total += length($buff);
		unless($save) {
			last LINE unless(length($buff) > 9);
			if($buff =~ /^\xff(\xfa|\xfb)/o) { last LINE; }
			if($buff =~ /^\x00\x05\x16\x00/o) { last LINE; }
			if($buff =~ /^\.snd/o) { last LINE; }
			if($buff =~ /^\x50\x4b\x03\x04/o) { last LINE; }
			if($buff =~ /^\x89PNG/o) { last LINE; }
			if($buff =~ /^\xff\xd8\xff\xe0/o) { last LINE; }
			if($buff =~ /^GIF/o) { last LINE; }
			if($buff =~ /^\x00\x00\x01(\xba\x21)|(\xb3\x16)/o) { last LINE; }
			if($buff =~ /^MM|II/o) { last LINE; }
			if($buff =~ /^%PDF-/o) { last LINE; }
			if($buff =~ /^%!|\004%!/o) { last LINE; }
			if($buff =~ /^\x4d\x5a\x90\x00\x03\x00\x00\x00/o) { $vtype = "2"; }
			if($buff =~ /^\x4d\x5a\x00\x00\x02\x00\x00\x00/o) { $vtype = "3"; }
			if($buff =~ /^\x4d\x5a\x50\x00\x02\x00\x00\x00/o) { $vtype = "4"; }
		}
		$save .= $buff;
		$_ = $save;
		if($vtype eq "2") {
			if($total<=1024) {
				if(/\x00.\x00{3}.(\x00|\x01)\x00{13}\x40\x00\x00(\x40|\xc0)\x2e.{5}\x00\x00\xed[^\x00](\x00|\x01)\x00\x00.(\x00|\x01)\x00\x00.(\x00|\x01)\x00\x00[^\x00](\x00|\x01)\x00{13}\x40\x00\x00(\xc0|\xc2)/so) { $virus = "W32/Magistr.b\@MM"; last LINE; }
				if(/\x00.\x00{3}.(\x00|\x01)\x00{13}\x40\x00\x00(\x40|\xc0)\x2e.{5}\x00\x00\xec[^\x00](\x00|\x01)\x00\x00.(\x00|\x01)\x00\x00.(\x00|\x01)\x00\x00[^\x00](\x00|\x01)\x00{13}\x40\x00\x00(\xc0|\xc2)/so) { $virus = "W32/Magistr.a\@MM"; last LINE; }
			}
			if(/\x48\x59\x42\x52\x49\x53/so) { $virus = "W32/Hybrys.gen\@MM"; last LINE; }
			if(/\x5c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x73\x00\x00\x00\x43\x6f\x6e\x63\x65\x70\x74\x20\x56\x69\x72\x75\x73\x28\x43\x56\x29\x20\x56\x2e\d\x2c\x20\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x28\x43\x29\d{4}.{10,}\x4d\x49\x4d\x45\x2d\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x31\x2e\x30/so) { $virus = "W32/Nimda\@MM"; last LINE; }
			if(/\x70\x65\x6e\x74\x61\x67\x6f\x6e\x65/so) { $virus = "W32/Goner\@MM"; last LINE; }
			if(/\x14\xff\x56\xb9\x36\xdc\x5a\xbd\x1b\x93\xeb\xea\x5f\x21\xb8\x35\x73\x1b\xfc\xa6\xdc\x6f\x01\x24\x8b\x14\x85\xb8\x6c\x28\x0d\x3b\xd1\x74\x09\x40\xb3\xbb\x95\x4a\x1a\x74\x15\x72\xe5\x1a\x89\x0c\x8b\x00\xcf\xb7\x90\x49\x24\xfe\x81\xc3\x22\x8d\xa5\x68\x7a\xb4/so) { $virus = "BackDoor.arsd"; last LINE; }
			if(/\x20\x00\x2d\x00\x20\x00\x23\x00\x74\x00\x65\x00\x61\x00\x6d\x00\x76\x00\x69\x00\x72\x00\x75\x00\x73\x00\x00\x00\x2c\x00\x0c\x00\x01\x00\x50\x00\x72\x00\x6f\x00\x64\x00\x75\x00\x63\x00\x74\x00\x4e\x00\x61\x00\x6d\x00\x65\x00\x00\x00\x00\x00\x4b\x00\x61\x00\x72\x00\x65\x00\x6e\x00\x00\x00\x2c\x00\x0a\x00\x01\x00\x46\x00\x69\x00\x6c\x00\x65\x00\x56\x00\x65\x00\x72\x00\x73\x00\x69\x00\x6f\x00\x6e\x00\x00\x00\x00\x00\x31\x00\x2e\x00\x30\x00\x30\x00/so) { $virus = "W32/Gokar\@MM"; last LINE; }
			if(/\x08\xb5\x6d\xea\x46\x82\x32\x67\x62\x42\x2b\x16\x59\x97\xcb\xdb\x40\x1c\x02\xd2\x43\x40\xa0\x99\x65\x20\x99\x2a\x9d\xa1\x21\xa1\xa1\x1d\x55\x05\x19\x01\x57\x55\x32\x8c\x41\xc5\x08\x01\x76\x0a\x43\x0f\x81\x87\xb0\xda\x18\x3d\x42\x28\x28\xa8\x80\xac\xd2\xe9/so) { $virus = "W32/Navidad.e\@M"; last LINE; }
			if(/\x2f\x48\x6f\x6f\x6b/so) { $virus = "PWS-gen.Hooker"; last LINE; }
			if(/\x53\x7f\xf3\xff\xff\x75\x6e\x4d\x6f\x6e\x54\x75\x65\x57\x65\x64\x54\x68\x75\x46\x72\x69\x53\x61\x74\x4a\x61\x6e\x46\x65\x62\x4d\xff\xb7\x76\xfb\x61\x72\x41\x70\x72\x05\x79\x4a\x26\x02\x6c\x41\x75\x67\x53\x65\x70\x4f\x63\x74\x5b\x81\xfa\xfd\x4e\x6f\x76\x44\x65\x63\x3f\x54\x5a\x1b\x1c\x74\x7b\xb7\xa9\xff\x69\x6d/so) { $virus = "W32/Myparty.b\@MM"; last LINE; }
		} elsif($vtype eq "3") {
			if(/\x69\x77\x6f\x72\x6d\x2e\x61\x78\x6c\x38\x7a\x65/so) { $virus = "W32/Aliz\@MM"; last LINE; }
		} elsif($vtype eq "4") {
			if(/\x53\x43\x61\x6d\x33\x32/so) { $virus = "W32/SirCam\@MM"; last LINE; }
			if(/\x53\x6f\x66\x74\x77\x61\x72\x65\x20\x70\x72\x6f\x76\x69\x64\x65\x20\x62\x79\x20\x5b\x4d\x41\x54\x52\x69\x58\x5d\x20\x56\x58\x20\x74\x65\x61\x6d/so) { $virus = "W32/MTX.gen\@M"; last LINE; }
		} else {
			if(/\x47\x45\x54\x20\x2f\x64\x65\x66\x61\x75\x6c\x74\x2e\x69\x64\x61\x3f\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58/so) { $virus = "W32/CodeRed.c.worm"; last LINE; }
		}
		$save = substr($buff, (length($buff)/2));
	}
	close(FILE);
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

=head1 DESCRIPTION

This module is designed to allows to scan files for known viruses. The
purpose is to provide a perl module to make plattaform independent virus
scanners.

=head1 METHODS

=head2 new([, OPTION ...])

This method create a new File::Scan object. The following keys are 
available:

=over 3

=item extension => "string"

add the specified extension to the infected file

=item move => "directory"

move the infected file to the specified directory

=item copy => "directory"

copy the infected file to the specified directory

=item delete => 1

delete the infected file

=back

=head2 scan([FILE])

This method scan a file for viruses and return the name of virus if a
virus is found.

=head2 error()

This method return a error message if a error happens.

=head1 AUTHOR

Henrique Dias <hdias@esb.ucp.pt>

=head1 CREDITS

Thanks to Rui de Castro, Sergio Castro and Ricardo Oliveira for the help.

Thanks to Fernando Martins for the personal collection of viruses.

=head1 SEE ALSO

perl(1).

=cut
