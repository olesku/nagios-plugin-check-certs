#!/usr/bin/perl -w

use strict;

require "./check_certs.pl";

# test => wanted result.  Take care about the quoting.... ;-) Even
# single quoted strings in perl have some escapes needed for some
# characters.
my %tests = ("foo/bar"  => 'foo/bar',
	     "foo'bar"  => 'foo\\\'bar',
	     'foo"bar'  => 'foo\"bar',
	     "foo bar"  => 'foo\ bar',
	     'foo\bar'  => 'foo\\\bar',
	     "foo\tbar" => "foo\\\tbar",
	     "foo(bar)" => 'foo\(bar\)',
	     "foo[bar]" => 'foo\[bar\]',
	     "foo{bar}" => 'foo\{bar\}',
	     "foo\nbar" => "foo\\\nbar",
	     'foo$bar'  => 'foo\$bar' );

sub runTests {
    my $tests = 0;
    my $fail = 0;
    for my $t (keys %tests) {
	$tests++;
	my $w = $tests{$t};
	my $r = quoteFileName($t);
	if ($r eq $w) {
	    print "Unquoted: /$t/, quoted: /$r/ == /$w/: OK\n";
	} else {
	    print "Unquoted: /$t/, quoted: /$r/ != /$w/: FAIL\n";
	    $fail++;
	}
    }
    print "\n";
    print "Tests run: $tests.  Tests failed: $fail\n";
}


runTests();
