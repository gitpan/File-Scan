#!/usr/bin/perl -w -T

###########################################################################
#
# ScanVirus for use with Procmail
# Version 0.01
# Copyright (c) 2002 Henrique Dias <hdias@esb.ucp.pt>. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.
# Last Change: Tue May 14 11:18:20 WEST 2002
#
###########################################################################

use strict;
use locale;
use MIME::Parser;
use MD5;
use File::Copy;
use File::Scan;
use Net::SMTP;
use Fcntl qw(:flock);

my $VERSION = '0.01';
if($ENV{HOME} =~ /^(.+)$/) { $ENV{HOME} = $1; }
if($ENV{LOGNAME} =~ /^(.+)$/) { $ENV{LOGNAME} = $1; }

#---begin_config----------------------------------------------------------

my $path       = $ENV{'HOME'};
my $av_email   = "AntiVirus <antivirus\@xpto.org>";
my $admin      = "user\@xpto.org";
my $scandir    = "$path/.scanvirus";
my $logsdir    = "$scandir/logs";
my $quarantine = "$scandir/quarantine";
my $smtp_hosts = ["smtp1.xpto.org", "smtp2.xpto.org"];
my $hostname   = "xpto.org";
my $subject    = ["Returned mail: Virus alert!", "Returned mail: Suspicious file alert!"];
my $copyrg     = "(c) 2002 Henrique Dias - ScanVirus for Mail";

#---end_config------------------------------------------------------------

use constant SEEK_END => 2;
my $preserve = 0;

my @pattern = (
	'^From +([^ ]+)',
	'^To: +.*\b([\w\.\-]+\@[\w\.\-]+\.\w+)',
);

unless(@ARGV) {
	print STDERR "Empty args\n";
	exit(0);
}

my $loop = <<ENDOFCODE;
while(<STDIN>) {
	study;
	(\$from) = (/\$pattern[0]/io) unless(\$from);
	(\$to) = (/\$pattern[1]/io) unless(\$to);
	print TMP \$_;
}
ENDOFCODE

&main();

#---main------------------------------------------------------------------

sub main {
	unless(-d $scandir) { mkdir($scandir, 0700) or exit_script("$!"); }
	my $id = "";
	do { $id = &generate_id(); }
	until(!(-e "$scandir/$id"));
	mkdir("$scandir/$id", 0700) or exit_script("$!");

	my $from = "";
	my $to = "";
	open(TMP, ">$scandir/$id/$id.tmp") or exit_script("$!");
	eval($loop);
	close(TMP);

	my $attachs = &mimeexplode("$scandir/$id", "$id.tmp");
	my $result = &init_scan($attachs, $from, $ENV{LOGNAME}, $to);
	if($result && $quarantine) {
		unless(-d $quarantine) { mkdir($quarantine, 0755) or exit_script("$!"); }
		&deliver_msg("$scandir/$id/$id.tmp", $ENV{LOGNAME}, $quarantine, $from);
	}
	unless($preserve) {
		if(my $res = &clean_dir("$scandir/$id")) { &logs("error.log", "$res"); }
	}
	exit($result);
}

#---deliver_msg-----------------------------------------------------------

sub deliver_msg {
	my $msg = shift;
	my $user = shift;
	my $maildir = shift;
	my $from = shift;

	my $mailbox = "$maildir/$user";
	my $date = localtime;
	open(MSG, "<$msg") or &close_app("$!");
	open(MAILBOX, ">>$mailbox") or &close_app("$!");
	flock(MAILBOX, LOCK_EX);
	seek(MAILBOX, 0, SEEK_END);
	print MAILBOX "From $from $date\n";
	while(<MSG>) { print MAILBOX $_; }
	print MAILBOX "\n"; 
	flock(MAILBOX, LOCK_UN);
	close(MAILBOX);
	close(MSG);

	chmod(0600, $mailbox);
	my ($uid, $gid) = (getpwnam($user))[2,3];
	chown($uid, $gid, $mailbox) if($uid && $gid);

	return();
}

#---clean_dir-------------------------------------------------------------

sub clean_dir {
	my $dir = shift;

	my @files = ();
	opendir(DIRECTORY, $dir) or return("can't opendir $dir: $!");
	while(defined(my $file = readdir(DIRECTORY))) {
		next if($file =~ /^\.\.?$/);
		push(@files, "$dir/$file");
	}
	closedir(DIRECTORY);
	for my $file (@files) {
		if($file =~ /^(.+)$/s) { unlink($1) or return("could not delete $1: $!"); }
	}
	rmdir($dir) or return("couldn't remove dir $dir: $!");
	return();
}

#---init_scan-------------------------------------------------------------

sub init_scan {
	my $files = shift;
	my $from = shift || "unknown";
	my $user = shift || "unknown";
	my $to = shift || "$user\@$hostname";

	my $status = 0;
	my $fs = File::Scan->new(
		mkdir        => 0700,);
	FILE: for my $file (@{$files}) {
		my $virus = $fs->scan($file);
		if(my $e = $fs->error) {
			$preserve = 1;
			&logs("error.log", "$e\n");
			next FILE;
		}
		my ($shortfn) = ($file =~ /([^\/]+)$/o);
		if($virus) {
			$status = 1;
			my $string = "\"$shortfn\" (" . $virus . ")";
			&registration($string, $from, $user);
			&virus_mail($string, $from, &set_addr($user, $to));
			last FILE;
		} else {
			&suspicious_mail($shortfn, $from, &set_addr($user, $to)) if($fs->suspicious);
		}
	}
	return($status);
}

#---set_addr--------------------------------------------------------------

sub set_addr {
	my $user = shift;
	my $email = shift;

	my $name = &getusername($user);
	return("$name <$email>");
}

#---getusername-----------------------------------------------------------

sub getusername {
	my $user = shift;

	my ($name) = split(/,/, (getpwnam($user))[6]);
	return($name);
}

#---suspicious_mail-------------------------------------------------------

sub suspicious_mail {
	my $file = shift;
	my $from = shift;
	my $to = shift;
 
	my $data = <<DATATXT;
Suspicious file alert: $file

The e-mail from $from to $to has a suspicious
file attachement.

Please take a look at the suspicious file.

Thank You.

$copyrg

DATATXT
	&send_mail(
		from    => $av_email,
		to      => $admin,
		subject => $subject->[1],
		data    => $data );
	return();
}

#---virus_mail------------------------------------------------------------

sub virus_mail {
	my $string = shift;
	my $from = shift;
	my $to = shift;

	my $data = <<DATATXT;
Virus alert: $string

You have send a e-mail to $to with a infected file.
Your email was not sent to its destiny.

This infected file cannot be cleaned. You should delete the file and
replace it with a clean copy.

Please try to clean the infected file. If clean fails, delete the file and
replace it with an uninfected copy and try to send the email again.

Thank You.

$copyrg

DATATXT
	&send_mail(
		from    => $av_email,
		to      => $from,
		bcc     => $admin,
		subject => $subject->[0],
		data    => $data );
	return();
}

#---registration----------------------------------------------------------

sub registration {      
	my ($string, $from, $to) = @_;

	&logs("virus.log", "[$string] From: $from To: $to\n");
	return();
}

#---send_mail-------------------------------------------------------------

sub send_mail {
	my $param = {  
		from    => "",
		to      => "",
		bcc     => "",
		subject => "",
		data    => "",
		@_
	};
	HOST: for my $host (@{$smtp_hosts}) {
		my $smtp = Net::SMTP->new($host);
		unless(defined($smtp)) {
			&logs("error.log", "Send mail failed for \"$host\"\n");
			next HOST;
		}
		$smtp->mail($param->{from});
		$smtp->to($param->{to});
		$smtp->bcc(split(/ *\, */, $param->{bcc})) if($param->{bcc});
		$smtp->data();
		$smtp->datasend("From: ", $param->{from}, "\n") if($param->{from});
		$smtp->datasend("To: ", $param->{to}, "\n");
		$smtp->datasend("Bcc: ", $param->{bcc}, "\n") if($param->{bcc});
		$smtp->datasend("Subject: ", $param->{subject}, "\n") if($param->{subject});
		$smtp->datasend("\n");
		$smtp->datasend($param->{data}) if($param->{data});
		$smtp->dataend();
		$smtp->quit;
		return();
	}
	return();
}

#---mimeexplode-----------------------------------------------------------

sub mimeexplode {
	my ($dir, $file) = @_;

	my $attachs = [];
	my $parser = new MIME::Parser;
	$parser->extract_uuencode(1);
	$parser->output_dir($dir);
	open(FILE, "$dir/$file") or &exit_script("couldn't open $file: $!");
	my $entity = $parser->read(\*FILE) or &logs("error.log", "Couldn't parse MIME in $file; continuing...\n");
	close(FILE);
	&dump_entity($entity, $attachs) if($entity);
	return($attachs);
}

#---dump_entity-----------------------------------------------------------

sub dump_entity {
	my $ent = shift; 

	my @parts = $ent->parts;
	eval {
		if(@parts) { map { dump_entity($_, $_[0]) } @parts; }
		else {
			my $bp = $ent->bodyhandle->path || "";
			my $me = $ent->head->mime_encoding || "";
			my $mt = $ent->head->mime_type || "";
			my $cd = $ent->head->mime_attr("content-disposition") || "";
			$bp =~ s/\s+$//;
			push(@{$_[0]}, $bp) if($cd || ($me eq "base64") || ($mt eq "text/html"));
		}
	};
	&logs("error.log", "$@") if($@);
}

#---exit_script-----------------------------------------------------------

sub exit_script {
	my $string = shift;

	&logs("error.log", $string);
	exit(0);
}

#---generate_id-----------------------------------------------------------

sub generate_id {
	return(substr(MD5->hexhash(time(). {}. rand(). $$. 'blah'), 0, 16));
}

#---string_date-----------------------------------------------------------

sub string_date {
	my ($sec,$min,$hour,$mday,$mon,$year) = localtime();

	return sprintf("%04d/%02d/%02d %02d:%02d:%02d",
		$year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}

#---logs------------------------------------------------------------------

sub logs {
	my $logfile = shift;
	my $string = shift; 

	unless(-d $logsdir) { mkdir($logsdir, 0755) or exit(0); }
	my $today = &string_date();
	open(LOG, ">>$logsdir/$logfile") or exit(0);
	print LOG "$today $string";
	close(LOG);

	return();
}

#---end-------------------------------------------------------------------
