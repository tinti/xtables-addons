#!/usr/bin/perl
#
#	Converter for MaxMind CSV database to binary, for xt_geoip
#	Copyright © Jan Engelhardt <jengelh@medozas.de>, 2008
#
#	Use -b argument to create big-endian tables.
#
use Getopt::Long;
use IO::Handle;
use Text::CSV_XS; # or trade for Text::CSV
use strict;

my %country;
my %names;
my $csv = Text::CSV_XS->new({binary => 0, eol => $/}); # or Text::CSV
my $mode = "VV";

&Getopt::Long::Configure(qw(bundling));
&GetOptions("b" => sub { $mode = "NN"; });

while (my $row = $csv->getline(*ARGV)) {
	if (!defined($country{$row->[4]})) {
		$country{$row->[4]} = [];
		$names{$row->[4]} = $row->[5];
	}
	my $c = $country{$row->[4]};
	push(@$c, [$row->[2], $row->[3]]);
	if ($. % 4096 == 0) {
		print STDERR "\r\e[2K$. entries";
	}
}

print STDERR "\r\e[2K$. entries total\n";

foreach my $iso_code (sort keys %country) {
	printf "%5u ranges for %s %s\n",
		scalar(@{$country{$iso_code}}),
		$iso_code, $names{$iso_code};

	open(my $fh, ">".uc($iso_code).".iv0");
	foreach my $range (@{$country{$iso_code}}) {
		print $fh pack($mode, $range->[0], $range->[1]);
	}
	close $fh;
}
