# benchmark.t

use strict;
use warnings;
use Test::More;
use Benchmark 'cmpthese';
use File::Scan;
use File::Slurp 'read_file';

my $FILE  = $ARGV[0];
my $scan  = File::Scan->new( path => $FILE );
my $count = 1000;

sub in_memory {
    my $line_nr = shift;
    my @lines   = read_file($FILE);
    return $lines[$line_nr];
}

cmpthese(
    $count,
    {   'In Memory'  => sub { in_memory(10) },
        'File::Scan' => sub { $scan->slurp_line(10) },
    }
);

done_testing;
