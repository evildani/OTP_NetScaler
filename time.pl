#!/usr/local/bin/perl

$datestring = localtime();
print "Current date and time $datestring\n";

$epoc = time();
$epoc = $epoc - 12 * 60 * 60;   # one day before of current date.

$datestring = localtime($epoc);
print "Yesterday's date and time $datestring\n";