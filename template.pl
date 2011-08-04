#!/usr/bin/perl -w
BEGIN { 
        my $dir=$0; $dir=~s/\/[^\/]*$//;
        unshift(@INC,"$dir/lib") if ( -d "$dir/lib"); 
      }

use strict;
use DBI;
use DBD::SQLite;
use Data::Dumper;
use Template::Regex;
################################################################################
# Create the database
################################################################################
my $DBFILE="/var/tmp/connections.db";

my $db = DBI->connect("dbi:SQLite:$DBFILE", "", "", {RaiseError => 1, AutoCommit => 1});
$db->do("CREATE TABLE IF NOT EXISTS hosts (host_id INTEGER PRIMARY KEY AUTOINCREMENT, ipaddress VARCHAR(15), zone VARCHAR(32))");
$db->do("CREATE TABLE IF NOT EXISTS connections (source_host_id INTEGER, destination_host_id INTEGER, source_port INTEGER, destination_port INTEGER, protocol VARCHAR(8), count INTEGER)");

# indexes so our looping select * doesn't get increasingly slower...
$db->do("CREATE INDEX destination_host_id_idx on connections (destination_host_id)");
$db->do("CREATE INDEX destination_port_idx on connections (destination_port)");
$db->do("CREATE INDEX host_id_idx on hosts (host_id)");
$db->do("CREATE INDEX source_host_id_idx on connections (source_host_id)");
$db->do("CREATE INDEX source_port_idx on connections (source_port)");

################################################################################
# Parse the logs
################################################################################
my $tr = new Template::Regex;
$tr->load_template_file("cisco-asa.yml");
while(my $line=<STDIN>){
    chomp($line);
    my ($proto, $src_raw, $src_zone, $src_ip, $src_port, $tgt_raw, $tgt_zone, $tgt_ip, $tgt_port);
    my $result = $tr->parse_line($line);
    if ($result->{'name'} eq 'cisco_asa.session_buildup'){
       $proto = $result->{'patterns'}->[6];
        $proto=~tr/A-Z/a-z/;
        $src_raw = $result->{'patterns'}->[8];
        if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
            $src_zone = $1; $src_ip   = $2; $src_port = $3;
        }
        $tgt_raw = $result->{'pattern'}->[9];
        if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
            $tgt_zone = $1; $tgt_ip   = $2; $tgt_port = $3;
        }
       print "[$proto] $src_zone:$src_ip/$src_port -> $tgt_zone:$tgt_ip/$tgt_port\n";
    }else{
        print "$result->{'name'}\n";
    }
    ############################################################################
    # Load up the database
    ############################################################################
    if($proto&&$src_zone&&$src_ip&&$src_port&&$tgt_zone&&$tgt_ip&&$tgt_port){
        $db->do("INSERT INTO hosts (ipaddress,zone) SELECT '$src_ip','$src_zone' WHERE NOT EXISTS (SELECT * FROM hosts WHERE ipaddress = '$src_ip')");
        $db->do("INSERT INTO hosts (ipaddress,zone) SELECT '$tgt_ip','$tgt_zone' WHERE NOT EXISTS (SELECT * FROM hosts WHERE ipaddress = '$tgt_ip')");
        my $src_id_arry = $db->selectall_arrayref("SELECT host_id from hosts WHERE ipaddress='$src_ip'");
        my $tgt_id_arry = $db->selectall_arrayref("SELECT host_id from hosts WHERE ipaddress='$tgt_ip'");
        #print $#{ $src_id }." -> ".$#{ $tgt_id }."\n";
        my $src_id = $src_id_arry->[0]->[0];
        my $tgt_id = $tgt_id_arry->[0]->[0];
        my $tally = $db->selectall_arrayref("SELECT count FROM connections WHERE source_host_id='$src_id' AND destination_host_id='$tgt_id' AND source_port='$src_port' AND destination_port='$tgt_port' AND protocol='$proto'");
        if($#{ $tally } == -1){
            #print "Inserting\n";
            $db->do("INSERT INTO connections (source_host_id,destination_host_id,source_port,destination_port,protocol,count) VALUES ('$src_id','$tgt_id','$src_port','$tgt_port','$proto','1')");
        }else{
            #print "Updating\n";
            my $newcount=$tally->[0]->[0] + 1;
            $db->do("UPDATE connections SET count='$newcount' WHERE  source_host_id='$src_id' AND destination_host_id='$tgt_id' AND source_port='$src_port' AND destination_port='$tgt_port' AND protocol='$proto'");
        }
    }
    ############################################################################
    # End Load up the database
    ############################################################################
}
################################################################################
# End Parse the logs
################################################################################
