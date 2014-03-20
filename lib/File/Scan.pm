package File::Scan;

#ABSTRACT: file parser intended for big files that doesn't fit into main memory.


use Moo;
use Carp 'croak';
use IO::File;
use Encode qw(decode);


has path => (
    is       => 'ro',
    required => 1,
);


has line_separator => (
    is      => 'ro',
    default => sub {qw/(\015\012|\015|\012)/},
);


has is_utf8 => (
    is      => 'ro',
    default => sub {1},
);


sub slurp_line {
    my ( $self, $line_number ) = @_;

    my $fh         = $self->_fh;
    my $line_index = $self->index->{$line_number};
    my $previous_line_index =
      ( $line_number == 0 ) ? 0 : $self->index->{ $line_number - 1 };

    my $line;
    seek( $fh, $previous_line_index, 0 );
    read( $fh, $line, $line_index - $previous_line_index );

    return decode( "utf8", $line ) if $self->is_utf8;
    return $line;
}

# file handle return by IO::File
has _fh => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my ($self) = @_;
        my $open_file_param = "<:crlf";
        IO::File->new( $self->path, $open_file_param )
          or croak "Failed to open file '" . $self->path . "' : '$!'";
    }
);

# File stat array
has _stat => (
    is => 'lazy',
);

sub _build__stat {
    my ($self) = @_;
    my @stat = stat( $self->_fh );
    return \@stat;
}


has index => (
    is      => 'rw',
    lazy    => 1,
    builder => 1,
);

sub _build_index {
    my ($self) = @_;
    my $index;

    my ($blocksize) = @{ $self->_stat }[11];
    $blocksize ||= 8192;

    my $buffer      = '';
    my $offset      = 0;
    my $line_number = 0;

    # make sure we jump to the begining of the file
    seek( $self->_fh, 0, SEEK_SET );

    # build the index, char by char, splitting on the line separator
    my $line_sep = $self->line_separator;
    while ( my $count = read( $self->_fh, $buffer, $blocksize ) ) {
        for my $i ( 0 .. $count ) {
            my $char = substr $buffer, $i, 1;
            if ( $char =~ /$line_sep/ ) {
                $index->{ $line_number++ } = $offset + $i + 1;
            }
        }
        $offset += $count;
    }

    # reset the cursor at the begining of the file and return the index
    seek( $self->_fh, 0, SEEK_SET );
    return $index;
}

1;


=pod

=head1 NAME

File::Scan - file parser intended for big files that doesn't fit into main memory.

=head1 VERSION

version 0.003

=head1 DESCRIPTION

In most of the cases, you don't want to use this, but L<File::Slurp> instead.

This class is able to slurp a line from a file without loading the whole file in
memory. When you want to deal with files of millions of lines, on a limited
environment, brute force isn't an option.

An index of all the lines in the file is built in order to be able to access
them almost instantly.

The memory used is then limited to the size of the index (HashRef of line
numbers / position values) plus the size of the line that is read.

It also provides a way to nicely iterate over all the lines of the file, using
only the amount of memory needed to store one line at a time, not the whole file.

=head1 ATTRIBUTES

=head2 path

Required, file path as a string.

=head2 line_separator

Optional, regular expression of the newline seperator, default is
C</(\015\012|\015|\012)/>.

=head2 is_utf8

Optional, flag to tell if the file is utf8-encoded, default is true. 

If true, the line returned by C<slurp_line> will be decoded.

=head2 index

Index that contains positions of all lines of the file, usage:

    $self->index->{ $line_number } = $seek_position;

=head1 METHODS

=head2 slurp_line 

Return the line content at the given position.

    my $line_content = $self->slurp_line( $line_number );

=head1 ACKNOWLEDGMENT

This module was written at Weborama when dealing with huge raw files, where huge
means "oh no, it really won't fit anymore in this compute slot!" (which are
limited in main-memory).

=head1 AUTHORS

This module has been written at Weborama by Alexis Sukrieh and Bin Shu.

=head1 AUTHOR

Alexis Sukrieh <sukria@sukria.net>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Weborama.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


__END__
