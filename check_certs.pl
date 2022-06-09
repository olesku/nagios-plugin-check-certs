#!/usr/bin/perl -w

# Nagios plugin that monitors expiration dates of x509 certificate files.
# Author: Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>

# nagios: -epn
use strict;
use Getopt::Std;

my %config = (
  'warnDays'        => 30,
  'criticalDays'    => 10,
  'fileExtensions'  => 'cer,crt',
  'xclude'          => '',
);

my $openssl_bin     = `which openssl`;
my $date_bin        = `which date`;

# The shell "Interanl Field Separator" - most commonly
# <space><tab><new‐line> but has interesting uses in security
# contexts.  If it has not been exported by the shell just match
# whitespace.
my $IFS             = $ENV{'IFS'} || '\s';

sub quoteFileName {
    my ($string) = @_;

    # Quote some shell meta characters.
    $string =~ s/([\[\]\{\}\\()"'\$${IFS}])/\\$1/ogm;

    return $string;
}

sub checkCertificates {
  my (@cerificateFiles) = @_;
  my %failedCertificates;

  foreach my $certFile (@cerificateFiles) {
    my $shellName = quoteFileName($certFile);
    my $openssl_cmd = sprintf("%s x509 -in %s -noout -enddate 2>&1", $openssl_bin, $shellName);
    my $openssl_enddate = `$openssl_cmd`;
    if ($?) {
	printf("CRITICAL: openssl fails on check of %s\n", $certFile);
	exit 2;
    }
    next if (!($openssl_enddate =~ m/^notAfter/));

    $openssl_enddate =~ s/notAfter\=//;
    chomp($openssl_enddate);

    my $enddate_unixts_cmd = sprintf("%s --date='%s' '+%%s'", $date_bin, $openssl_enddate);
    my $enddate_unixts = `$enddate_unixts_cmd`;
    $enddate_unixts =~ s/\n//;

    my $daysLeft = (int($enddate_unixts) - time()) / 86400;

    if ($daysLeft < $config{'warnDays'} ) {
      $failedCertificates{$certFile} = {
        'endDate'     => $openssl_enddate,
        'daysLeft'    => $daysLeft,
        'hasExpired'  => ($daysLeft < 1)
      };
    }
  }

  return %failedCertificates;
}

sub parseDir {
  my ($arrayRef, $dir, $ext) = (@_);
  return if (! -d $dir);


  opendir(my $dh, $dir) or return;
    while(my $file = readdir($dh)) {
      next if ($file eq '.' || $file eq '..');
      $file = $dir . "/" . $file;

      if ($config{'xclude'} && $file =~ /$config{'xclude'}/o) {
	  warn "DEBUG: $file matches exclude pattern. EXCLUDED.\n" if $config{'debug'};
	  next;
      }

      if (-d $file) {
        parseDir($arrayRef, $file, $ext);
      } elsif (-f $file) {
        if ($file =~ m/\.${ext}/) {
          push(@{$arrayRef}, $file);
	  warn "DEBUG: $file matches extention pattern. INCLUDED.\n" if $config{'debug'};
        } else {
	  warn "DEBUG: $file does not  match extention pattern. EXCLUDED.\n" if $config{'debug'};
	}
      }
    }
  closedir($dh);
}

sub printUsage {
  printf("Usage:\n" .
  "%s [flags] <path|file> ...\n\n" .
  "Flags:\n  -w <days>\tDays left to expire before triggering a warning alert.\n" .
  "  -c <days>\tDays left to expire before triggering a critical alert.\n" .
  "  -e <ext1,ext2>\tFile extensions to scan if a path is given.\n" .
  "  -x <re>\tFilename pattern to exclude.\n".
  "  -d\tDebug\n", $0);
  exit(0);
}

sub outputSummaryNagios {
  my ($failedCertificates) = (@_);
  my $exitCode = 0;

  foreach (sort keys %{$failedCertificates}) {
    if ($failedCertificates->{$_}{'hasExpired'}) {
      printf("CRITICAL: %s expired on %s\n", $_, $failedCertificates->{$_}{'endDate'});
      $exitCode = 2;
    } else {
      if ($failedCertificates->{$_}{'daysLeft'} <= $config{'warnDays'} && 
          $failedCertificates->{$_}{'daysLeft'} > $config{'criticalDays'}) {
        printf("WARNING: %s expires in %d days on %s\n", $_, $failedCertificates->{$_}{'daysLeft'}, $failedCertificates->{$_}{'endDate'});
        $exitCode = 1 if ($exitCode < 1);
      } elsif ($failedCertificates->{$_}{'daysLeft'} <= $config{'criticalDays'}) {
        printf("CRITICAL: %s expires in %d days on %s\n", $_, $failedCertificates->{$_}{'daysLeft'}, $failedCertificates->{$_}{'endDate'});
        $exitCode = 2;
      }
    }
  }

  if ($exitCode == 0) {
    printf("OK: All checked certificates is valid.\n");
  }

  exit($exitCode);
}

sub main {
  my %opts;
  getopts('dw:c:e:h:x:', \%opts);
  printUsage()                              if (defined($opts{'h'}));
  $config{'warnDays'} = int($opts{'w'})     if (defined($opts{'w'}));
  $config{'criticalDays'} = int($opts{'c'}) if (defined($opts{'c'}));
  $config{'fileExtensions'} = $opts{'e'}    if (defined($opts{'e'}));
  $config{'xclude'} = $opts{'x'}	    if (defined($opts{'x'}));
  $config{'debug'} = 1                      if (defined($opts{'d'}));

  chomp($openssl_bin);
  chomp($date_bin);
  foreach ($openssl_bin, $date_bin) {
    if (! -e $_) {
      printf("UNKNOWN: Error %s binary not found.\n", $_);
      exit(3);
    }
  }

  my (@scanDirectories, @cerificateFiles);

  foreach my $arg (@ARGV) {
    if (-d $arg) {
      push(@scanDirectories, $arg);
    } elsif (-f $arg) {
      push(@cerificateFiles, $arg);
    }
  }

  foreach my $dir (@scanDirectories) {
    foreach my $ext (split(',', $config{'fileExtensions'})) {
      parseDir(\@cerificateFiles, $dir, $ext);
    }
  }

  if (scalar @cerificateFiles > 0) {
    my %failedCertificates = checkCertificates(@cerificateFiles);
    outputSummaryNagios(\%failedCertificates);
  }

  printf("OK: No certificate files found in the given paths.\n");
  exit(0);
}

main unless caller;
