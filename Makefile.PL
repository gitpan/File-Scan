use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

use strict;

my $bufflen = 1024;
my $signs = "files/signatures.txt";

my %script_lang = (
	"BAT" => "Batch",
	"JS"  => "JavaScript",
	"VBS" => "VBScript");

my %app_signatures = (
	'd0cf11e0a1b11ae1' => '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',
	'4d5a'             => '\x4d\x5a',
	'474554'           => '\x47\x45\x54',
	'e9'               => '\xe9',
);

my $first = 0;
for my $k (keys(%app_signatures)) {
	my $n = length($k)/2;
	$first = $n if($n > $first);
}

my $hash = &load_signatures($signs);
my $code = &get_code($hash);
&make_module($code);

my @ppd;
if ($] >= 5.00503) {
	@ppd = (
		'AUTHOR'   => 'Henrique Dias <hdias@esb.ucp.pt>',
		'ABSTRACT' => 'Extension for Scanning files for Viruses',
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
		$elem[4] =~ s/(?<![\{\\])([\da-f]{2})(?!\})/\\x$1/g unless(exists($script_lang{$elem[1]}));
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

	my $today = &string_date();
	my $code = <<ENDOFCODE1;
# last change: $today

sub scan_text {
	my \$file = shift;

	local \$/ = "\\0";
	local *FILE;
	open(FILE, "<\$file") or return(&set_error("\$!"));
	\$_ = <FILE>;
	close(FILE);
ENDOFCODE1
	for my $sl (keys(%script_lang)) {
		while(my($key, $value) = each(%{$patterns->{$sl}->{'0'}})) {
			$code .= "\treturn(\"$key\") if(\/$value\/iso);\n";
		}
	}
	$code .= <<ENDOFCODE2;
	return();
}

sub scan_binary {
	my \$file = shift;

	my \$skip = 0;
	my \$vtype = "";
	my \$virus = "";
	my \$buff = "";
	my \$save = "";
	my \$total = 0;
	my \$size = $bufflen;
	open(FILE, "<\$file") or return(&set_error("\$!"));
	binmode(FILE);
	LINE: while(read(FILE, \$buff, \$size)) {
		study;
		\$total += length(\$buff);
		unless(\$save) {
			my \$begin = substr(\$buff, 0, $first);
			last LINE unless(length(\$begin) >= $first);
ENDOFCODE2
	while(my($key, $value) = each(%app_signatures)) {
		$code .= "\t\t\tif(\$begin =~ /\^$value/o) \{ \$vtype = \"$key\"; \}\n";
	}
	$code .= <<ENDOFCODE3;
			unless(\$vtype) { \$skip = 1; last LINE; }
		}
		\$save .= \$buff;
		\$_ = \$save;
ENDOFCODE3
	my $lcode = "";
	for my $idx (keys(%app_signatures)) {
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
	$code .= <<ENDOFCODE4;
		}
		\$save = substr(\$buff, (length(\$buff)/2));
	}
	close(FILE);
	&set_skip(1) if(\$skip);
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
