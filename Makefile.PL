use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

use strict;

my $bufflen = 256;
my $signs = "files/signatures.txt";

my %filetypes = (
	gif        => 'GIF',
	jpeg       => '\xff\xd8\xff\xe0',
	tiff       => 'MM|II',
	postscript => '%!|\004%!',
	pdf        => '%PDF-',
	basic      => '\.snd',
	png        => '\x89PNG',
	applefile  => '\x00\x05\x16\x00',
	zip        => '\x50\x4b\x03\x04',
	mp3        => '\xff(\xfa|\xfb)',
	mpeg       => '\x00\x00\x01(\xba\x21)|(\xb3\x16)',
);

my %virustypes = (
	'2' => '\x4d\x5a\x90\x00\x03\x00\x00\x00',
	'3' => '\x4d\x5a\x00\x00\x02\x00\x00\x00',
	'4' => '\x4d\x5a\x50\x00\x02\x00\x00\x00',
);

my $hash = &load_signatures($signs);
my $code = &get_code($hash);
&make_module($code);

my @ppd;
if ($] >= 5.00503) {
    @ppd = (
        'AUTHOR'        => 'Henrique Dias <hdias@esb.ucp.pt>',
        'ABSTRACT'      => 'Bla Bla',
    );
}

WriteMakefile(
	'NAME'         => 'File::Scan',
	'DISTNAME'     => 'File-Scan',
	'VERSION_FROM' => 'Scan.pm', # finds $VERSION
	'PREREQ_PM'    => {}, # e.g., Module::Name => 1.1
	'dist'         => { 'COMPRESS' => 'gzip -9f', 'SUFFIX' => 'gz', },
	@ppd,
);


sub load_signatures {
	my $file = shift;

	my $hash = {};
	open(FILE, "<$file") or die("$!");
	while(<FILE>) {
		next if(/^#/);
		chomp;
		my @elem = split(/::/);
		$elem[2] =~ s/\@/\\\@/g;
		$elem[3] =~ s/ +//g;
		$elem[3] =~ s/lt/\</ig;
		$elem[3] =~ s/le/\<\=/ig;
		$elem[3] =~ s/gt/\>/ig;
		$elem[3] =~ s/ge/\>\=/ig;
		$elem[3] =~ s/or/\|\|/ig;
		$elem[3] =~ s/and/\&\&/ig;
		$elem[4] =~ s/(?<![\{\\])([\da-f]{2})(?!\})/\\x$1/g if($elem[1]);
		$hash->{$elem[1]}->{$elem[3]}->{$elem[2]} = $elem[4];
	}
	close(FILE);
	return($hash);
}

sub make_module {
	my $code = shift;

	open(BASEFILE, "<files/Scan.base") or die("$!");
	open(PMFILE, ">Scan.pm") or die("$!");
	while(<BASEFILE>) {
		print PMFILE $_;
		if(/^__DATA__/) {
			print PMFILE $code;
		}
	}
	close(PMFILE);
	close(BASEFILE);
}

sub get_code {
	my $patterns = shift;

	my $min_size = 0;
	my $today = &string_date();
	my $code = <<ENDOFCODE1;
# last change: $today
sub load_txt_signs() {
	\$virustxt = {
ENDOFCODE1
	my $min = 0;
	my $max = 0;
	while(my($key, $value) = each(%{$patterns->{'0'}->{'0'}})) {
		$value =~ s/\"/\\\"/g;
		my @all = split(/}{/, $value);
		my $ne = scalar(@all);
		$min_size = $ne unless($min_size);
		$min_size = $ne if($ne < $min_size);
		for(@all) {
			my $n = length($_);
			$min = $max unless($min);
			$max = $n if($n > $max);
			$min = $n if($n < $min);
		}
		my $line = join('","', @all);
		$code .= "\t\t\"$key\" => [\"$line\"],\n";
	}
	$code .= <<ENDOFCODE2;
	};
	\%keywords = ();
	for my \$v (values(\%{\$virustxt})) {
		\@keywords{\@{\$v}} = ();
	}
}

sub scan_text {
	my\$file = shift;

	my \$pattern = '([\\w-\\.]{$min,$max})';
	my \%hash = ();
	local \$/ = "\0";
	open(FILE, "<\$file") or return(&set_error("\$!"));
	while(<FILE>) {
		while(/\$pattern/osg) {
			next unless(exists(\$keywords{\$1}));
			\$hash{\$1} = "";
		}
	}
	close(FILE);
	return() if(scalar(keys(\%hash)) < $min_size);
	VIRUS: for my \$name (\%{\$virustxt}) {
		my \$found = "";
		for my \$sign (\@{\$virustxt->{\$name}}) {
			next VIRUS unless(exists(\$hash{\$sign}));
			\$found = "\$name";
		}
		return(\$found) if(\$found);
	}
	return();
}

sub scan_binary {
	my \$file = shift;

	my \$virus = "";
	my \$buff = "";
	my \$save = "";
	my \$total = 0;
	my \$size = $bufflen;
	open(FILE, "<\$file") or return(&set_error("\$!"));
	binmode(FILE);
	LINE: while(read(FILE, \$buff, \$size)) {
		\$total += length(\$buff);
		unless(\$save) {
			last LINE unless(length(\$buff) > 9);
ENDOFCODE2
	for my $type (values(%filetypes)) {
		$code .= "\t\t\tif(\$buff =~ /\^$type/o) \{ last LINE; \}\n";
	}
	while(my($key, $value) = each(%virustypes)) {
		$code .= "\t\t\tif(\$buff =~ /\^$value/o) \{ \$vtype = \"$key\"; \}\n";
	}

	$code .= <<ENDOFCODE3;
		}
		\$save .= \$buff;
		\$_ = \$save;
ENDOFCODE3
	my $lcode = "";
	for my $idx (keys(%virustypes)) {
		$lcode .= ($lcode) ? "\t\t} els" : "\t\t";
		$lcode .= "if(\$vtype eq \"$idx\") {\n";
		for my $limit (keys(%{$patterns->{$idx}})) {
			my $tabs = "\t\t\t";
			if($limit) {
				$lcode .= $tabs . "if(\$total$limit) \{\n";
				$tabs .= "\t";
			}
			while(my($key, $value) = each(%{$patterns->{$idx}->{$limit}})) {
				$lcode .= $tabs . "if(/$value/so) \{ \$virus = \"$key\"; last LINE; \}\n";
			}
			$lcode .= "\t\t\t\}\n" if($limit);
		}
	}
	$code .= $lcode;
	$code .= "\t\t\} else \{\n";
	for my $limit (keys(%{$patterns->{'1'}})) {
		my $tabs = "\t\t\t";
		if($limit) {
			$code .= $tabs . "if(\$total$limit) \{\n";
			$tabs .= "\t";
		}
		while(my($key, $value) = each(%{$patterns->{'1'}->{$limit}})) {
			$code .= $tabs . "if(/$value/so) \{ \$virus = \"$key\"; last LINE; \}\n";
		}
		$code .= "\t\t\t\}\n" if($limit);
	}
	$code .= <<ENDOFCODE4;
		}
		\$save = substr(\$buff, (length(\$buff)/2));
	}
	close(FILE);
	return(\$virus);
}
ENDOFCODE4
	return($code);
}

sub string_date {
	my ($sec,$min,$hour,$mday,$mon,$year) = localtime();
	return sprintf("%04d/%02d/%02d %02d:%02d:%02d",
		$year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}
