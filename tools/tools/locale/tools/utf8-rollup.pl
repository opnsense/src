#!/usr/local/bin/perl -wC
# $FreeBSD$

use strict;
use Getopt::Long;

if ($#ARGV != 0) {
	print "Usage: $0 --unidir=<unidir>\n";
	exit(1);
}

my $UNIDIR = undef;

my $result = GetOptions (
		"unidir=s"	=> \$UNIDIR
	    );

my %utf8map = ();
my $outfilename = "$UNIDIR/posix/xx_Comm_C.UTF-8.src";

get_utf8map("$UNIDIR/posix/UTF-8.cm");
generate_header ();
parse_unidata ("$UNIDIR/UnicodeData.txt");
generate_footer ();

############################

sub get_utf8map {
	my $file = shift;

	open(FIN, $file);
	my @lines = <FIN>;
	close(FIN);
	chomp(@lines);

	my $incharmap = 0;
	foreach my $l (@lines) {
		$l =~ s/\r//;
		next if ($l =~ /^\#/);
		next if ($l eq "");

		if ($l eq "CHARMAP") {
			$incharmap = 1;
			next;
		}

		next if (!$incharmap);
		last if ($l eq "END CHARMAP");

		$l =~ /^(<[^\s]+>)\s+(.*)/;
		my $k = $2;
		my $v = $1;
		$k =~ s/\\x//g;		# UTF-8 char code
		$utf8map{$k} = $v;
	}
}

sub generate_header {
	open(FOUT, ">", "$outfilename")
		or die ("can't write to $outfilename\n");
	print FOUT <<EOF;
# Warning: Do not edit. This file is automatically generated from the
# tools in /usr/src/tools/tools/locale. The data is obtained from the
# CLDR project, obtained from http://cldr.unicode.org/
# -----------------------------------------------------------------------------

comment_char *
escape_char /

LC_CTYPE
EOF
}

sub generate_footer {
	print FOUT "\nEND LC_CTYPE\n";
	close (FOUT);
}

sub wctomb {
	my $wc = hex(shift);
	my $lead;
	my $len;
	my $ret = "";
	my $i;

	if (($wc & ~0x7f) == 0) {
		return sprintf "%02X", $wc;
	} elsif (($wc & ~0x7ff) == 0) {
		$lead = 0xc0;
		$len = 2;
	} elsif (($wc & ~0xffff) == 0) {
		$lead = 0xe0;
		$len = 3;
	} elsif ($wc >= 0 && $wc <= 0x10ffff) {
		$lead = 0xf0;
		$len = 4;
	}

	for ($i = $len - 1; $i > 0; $i--) {
		$ret = (sprintf "%02X", ($wc & 0x3f) | 0x80) . $ret;
		$wc >>= 6;
	}
	$ret = (sprintf "%02X", ($wc & 0xff) | $lead) . $ret;

	return $ret;
}

sub parse_unidata {
	my $file = shift;
	my %data = ();

	open(FIN, $file);
	my @lines = <FIN>;
	close(FIN);
	chomp(@lines);

	foreach my $l (@lines) {
		my @d = split(/;/, $l, -1);
		my $mb = wctomb($d[0]);
		my $cat;

		# XXX There are code points present in UnicodeData.txt
		# and missing from UTF-8.cm
		next if !defined $utf8map{$mb};

		# Define the category
		if ($d[2] =~ /^Lu/) {
			$cat = "upper";
		} elsif ($d[2] =~ /^Ll/) {
			$cat = "lower";
		} elsif ($d[2] =~ /^Nd/) {
			$cat = "digit";
		} elsif ($d[2] =~ /^L/) {
			$cat = "alpha";
		} elsif ($d[2] =~ /^P/) {
			$cat = "punct";
		} elsif ($d[2] =~ /^M/ || $d[2] =~ /^N/ || $d[2] =~ /^S/) {
			$cat = "graph";
		} elsif ($d[2] =~ /^C/) {
			$cat = "cntrl";
		} elsif ($d[2] =~ /^Z/) {
			$cat = "space";
		}
		$data{$cat}{$mb}{'wc'} = $d[0];

		# Check if it's a start or end of range
		if ($d[1] =~ /First>$/) {
			$data{$cat}{$mb}{'start'} = 1;
		} elsif ($d[1] =~ /Last>$/) {
			$data{$cat}{$mb}{'end'} = 1;
		}

		# Check if there's upper/lower mapping
		if ($d[12] ne "") {
			$data{'toupper'}{$mb} = wctomb($d[12]);
		} elsif ($d[13] ne "") {
			$data{'tolower'}{$mb} = wctomb($d[13]);
		}
	}

	my $first;
	my $inrange = 0;

	# Now write out the categories
	foreach my $cat (sort keys (%data)) {
		print FOUT "$cat\t";
		$first = 1;
	foreach my $mb (sort keys (%{$data{$cat}})) {
		if ($first == 1) {
			$first = 0;
		} elsif ($inrange == 1) {
			# Safety belt
			die "broken range end wc=$data{$cat}{$mb}{'wc'}"
			    if !defined $data{$cat}{$mb}{'end'};
			print FOUT ";...;";
			$inrange = 0;
		} else {
			print FOUT ";/\n\t";
		}

		if ($cat eq "tolower" || $cat eq "toupper") {
			print FOUT "($utf8map{$mb},$utf8map{$data{$cat}{$mb}})";
		} else {
			if (defined($data{$cat}{$mb}{'start'})) {
				$inrange = 1;
			}
			print FOUT "$utf8map{$mb}";
		}
	}
		print FOUT "\n";
	}
}
