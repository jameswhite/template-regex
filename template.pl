#!/usr/bin/perl -w
BEGIN { 
        my $dir=$0; $dir=~s/\/[^\/]*$//;
        unshift(@INC,"$dir/lib") if ( -d "$dir/lib"); 
      }

use strict;
use Data::Dumper;
use Template::Regex;

my $tr = new Template::Regex;
$tr->load_template_file("cisco-asa.yml");
while(my $line=<STDIN>){
    chomp($line);
    my $result = $tr->parse_line($line);
    print Data::Dumper->Dump([$result]);
}
exit 1;
