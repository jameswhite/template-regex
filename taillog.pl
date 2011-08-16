#!/usr/bin/perl -w
################################################################################
BEGIN {
        # figure out where we are and include our relative lib directory
        use Cwd;
        my $script=$0;
        my $pwd = getcwd();
        my $libdir = $pwd;
        if($0=~s/(.*)\/([^\/]*)//){
            $script = $2;
            my $oldpwd = $pwd;
            chdir($1);
            $pwd = getcwd();
            if($libdir=~m/\/bin$/){
                $libdir=$pwd; $libdir=~s/\/bin$/\/lib/;
            }else{
                $libdir="$pwd/lib";
            }
        }
        unshift(@INC,"$libdir") if ( -d "$libdir");
      }
################################################################################
package Log::Tail::Reporter;
use POE qw(Wheel::FollowTail);
use YAML;
use Template::Regex;

# Net::Infrastructure is what we use to match 
# use Net::Infrastructure; 

sub new {
    my $class = shift;
    my $self = {};
    my $cnstr = shift if @_;
    bless($self,$class);
    foreach my $arg ('file', 'template'){
        if(! defined($cnstr->{$arg})){
            print STDERR "Necessary parameter [ $arg ] not defined. Aborting object.\n";
            return undef;
        }
    }
    $self->{'max_lines'}=$cnstr->{'max_lines'}||undef;
    $self->{'TR'} = new Template::Regex;
    $self->{'TR'}->load_template_file($cnstr->{'template'});
    POE::Session->create(
                          inline_states => {
                                             _start => sub {
                                                             $_[HEAP]{linecount}=0;
                                                             $_[HEAP]{tailor} = POE::Wheel::FollowTail->new(
                                                                  Filename => $cnstr->{'file'},
                                                                  InputEvent => "got_log_line",
                                                                  ResetEvent => "got_log_rollover",
                                                             );
                                                           },
                                           },
                          object_states => [
                                             $self => [ 'got_log_line', 'got_log_rollover' ],
                                           ],
    );
    return $self;
}

sub got_log_line {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
   my $line = $args[0];
   my $result = $self->{'TR'}->parse_line($line);
   my $last = $#{ $result->{'patterns'} } - 1;
   my $output = $result->{'name'};
   if( $output =~ m/remainder$/ ){
       $output =~ s/remainder$/\[$result->{'patterns'}->[ $last ]\]/;
       if(defined($self->{'max_lines'})){
           $heap->{'linecount'}++ ;
           if($heap->{'linecount'} > $self->{'max_lines'}){
               exit 0;
           }
       }
       print "$output\n";
   }else{
       $heap->{'last'}='' unless( defined($heap->{'last'}));
       # remove line-after-line of repeated output
       if($heap->{'last'} ne $result->{'name'}){
           $self->sketch_connection($result->{'name'}, $result->{'patterns'});
           $heap->{'last'} = $result->{'name'};
       }
   }
   #my $proto = $result->{'patterns'}->[11];
} 

sub sketch_connection {
    my ($self, $match, $args) = ( @_ );
    my @ignore = ( 
                   'cisco_asa.aaa_failback_local',
                   'cisco_asa.aaa.user_auth_success',
                   'cisco_asa.aaa.transaction_status_accept',
                   'cisco_asa.session_teardown',
                   'cisco_asa.icmp_tear',
                   'cisco_asa.local_host_teardown',
                   'cisco_asa.dynamic_tear',
                   'cisco_asa.deny',
                   'cisco_asa.discard',
                   'cisco_asa.esmtp_size_violation',
                   'cisco_asa.ftp',
                   'cisco_asa.icmp',
                   'cisco_asa.ids',
                   'cisco_asa.ike_no_policy',
                   'cisco_asa.ipsec',
                   'cisco_asa.local_host_buildup',
                   'cisco_asa.nat_t',
                   'cisco_asa.pitcher_key_aquire',
                   'cisco_asa.pitcher_key_delete',
                   'cisco_asa.udp_route_fail',
                   'cisco_asa.user.auth_success',
                   'cisco_asa.user.priv_level_change',
                   'cisco_asa.user.executed_cmd',
                   'cisco_asa.user.executed_the_cmd',
                   'pfsense.icmp',
                   'pfsense.tab',
                 );

    if(grep(/$match/, @ignore)){                      # do nothing, we dont' care about these right now.
        print ""; 
    }elsif ($match eq 'cisco_asa.session_buildup'){   # we want connection buildups through the firewalls
#        $proto = $args->[6];
#        $proto=~tr/A-Z/a-z/;
#        $src_raw = $args->[8];
#        if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
#            $src_ip = $2; $src_port = $3;
#        }
#        $tgt_raw = $args->[9];
#        if($tgt_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
#            $tgt_ip = $2; $tgt_port = $3;
#        }
#        print "$src_ip:$src_port -> $tgt_ip:$tgt_port/$proto\n";
        print "";
    }elsif($match =~ m/cisco_asa.dynamic_build/){      # we want connection buildups through the firewalls
#        if($args->[6] =~ m/(\S+):(\S+)\/([0-9]+)/){
#            $src_if = $1; $src_ip = $2; $src_port = $3;
#        }
#        if($args->[7] =~ m/(\S+):(\S+)\/([0-9]+)/){
#            $tgt_if = $1; $tgt_ip = $2; $tgt_port = $3;
#        }
        print "";
    }elsif($match =~ m/cisco_asa.udp_permitted/){       # we want connection buildups through the firewalls
        #print Data::Dumper->Dump([ $args ]);
#        if($args->[6] =~ m/(\S+):(\S+)\/([0-9]+)/){
#            $src_if = $1; $src_ip = $2; $src_port = $3;
#        }
#        if($args->[7] =~ m/(\S+):(\S+)\/([0-9]+)/){
#            $tgt_if = $1; $tgt_ip = $2; $tgt_port = $3;
#        }
#        $proto=udp;
    }elsif($match =~ m/pfsense.connection/){            # we want connection buildups through the firewalls
        print "";
        #print Data::Dumper->Dump([$args]);
#        $proto='';
#        if($args->[9] =~ m/proto\s+(\S+)\s+/){
#            $proto = $1;
#            $proto =~ tr/A-Z/a-z/;
#        }
#        @src = split(/\./,$args->[10]);
#        $src_port = pop(@src);
#        $src = join('.',@src);
#
#        @tgt = split(/\./,$args->[11]);
#        $tgt_port = pop(@tgt);
#        $tgt = join('.',@tgt);
#        print "$src:$src_port -> $tgt:$tgt_port/$proto\n";
    }else{
        print "Unhandled: $match [$#{ $args }]\n"; 
    }
}

sub got_log_rollover {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "Log rolled over.\n"; 
}

1;

$|=1;

my $pfsence = Log::Tail::Reporter->new({ 
                                         'file'     => '/var/log/pfsense/pfsense.log',
                                         'template' => 'pfsense.yml',
                                         #'max_lines'    => 100,
                                       });
my $cisco  = Log::Tail::Reporter->new({ 
                                         'file'     => '/var/log/cisco/network.log',
                                         'template' => 'cisco-asa.yml',
                                         #'max_lines'    => 100,
                                       });
POE::Kernel->run();
exit;
