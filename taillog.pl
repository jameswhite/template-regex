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
use POE::Component::Client::TCP;
use POE::Filter::Stream;

# Net::Infrastructure is what we use to match 
# use Net::Infrastructure; 

sub new {
    my $class = shift;
    my $self = {};
    my $cnstr = shift if @_;
    my ($host,$port) = split(/:/,$cnstr->{'server'}) if($cnstr->{'server'});
    $host=127.0.0.1 unless $host;
    $port=3737 unless $port;
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
                                             $self => [ 
                                                        'got_log_line', 
                                                        'got_log_rollover',
                                                        'sketch_connection',
                                                        'send_sketch',
                                                      ],
                                           ],
    );
    POE::Component::Client::TCP->new(
                                      RemoteAddress => $host,
                                      RemotePort    => $port,
                                      Filter        => "POE::Filter::Stream",
    
                                      # The client has connected.  Display some status and prepare to
                                      # gather information.  Start a timer that will send ENTER if the
                                      # server does not talk to us for a while.
                                      Connected => sub {
                                                         print "connected to $host:$port ...\n";
                                                         $_[HEAP]->{banner_buffer} = [];
                                                         $_[KERNEL]->delay(send_enter => 5);
                                      },
                                      # The connection failed.
                                      ConnectError => sub { print "could not connect to $host:$port ...\n"; },
                                      ServerInput => sub {
                                                           my ($kernel, $heap, $input) = @_[KERNEL, HEAP, ARG0];
                                                           print "got input from $host:$port ...\n";
                                                           push @{$heap->{banner_buffer}}, $input;
                                                           $kernel->delay(send_enter    => undef);
                                                           $kernel->delay(input_timeout => 1);
                                                         },
                                      # These are handlers for additional events not included in the
                                      # default Server::TCP module.  In this example, they handle
                                      # timers that have gone off.
                                      InlineStates => {  # The server has not sent us anything yet.  Send an ENTER
                                                         # keystroke (really a network newline, \x0D\x0A), and wait
                                                         # some more.
                                                         send_enter => sub {
                                                                             print "sending enter on $host:$port ...\n";
                                                                             $_[HEAP]->{server}->put("");    # sends enter
                                                                             $_[KERNEL]->delay(input_timeout => 5);
                                                                           },
                                                                     
                                                                           # The server sent us something already, but it has become idle
                                                                           # again.  Display what the server sent us so far, and shut
                                                                           # down.
                                                         input_timeout => sub {
                                                                                 my ($kernel, $heap) = @_[KERNEL, HEAP];
                                                                                 print "got input timeout from $host:$port ...\n";
                                                                                 print ",----- Banner from $host:$port\n";
                                                                                 foreach (@{$heap->{banner_buffer}}) {
                                                                                   print "| $_";
                                                                         
                                                                                   # print "| ", unpack("H*", $_), "\n";
                                                                                 }
                                                                                 print "`-----\n";
                                                                                 $kernel->yield("shutdown");
                                                                               },
                                                      },
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
       print STDERR "$output\n";
   }else{
       $heap->{'last'}='' unless( defined($heap->{'last'}));
       # remove line-after-line of repeated output
       if($heap->{'last'} ne $result->{'name'}){
           $kernel->yield("sketch_connection",$result->{'name'}, $result->{'patterns'});
           $heap->{'last'} = $result->{'name'};
       }
   }
   #my $proto = $result->{'patterns'}->[11];
} 

sub send_sketch {
    my ($self, $kernel, $heap, $sender, $sketch, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "$sketch\n";
}

sub sketch_connection {
    my ($self, $kernel, $heap, $sender, $match, $args, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my @ignore = ( 
                   'cisco_asa.aaa.auth_server_inaccesable',
                   'cisco_asa.aaa_failback_local',
                   'cisco_asa.aaa.user_auth_success',
                   'cisco_asa.aaa.transaction_status_accept',
                   'cisco_asa.asymmetric_nat_rules',
                   'cisco_asa.session_teardown',
                   'cisco_asa.icmp_tear.*',
                   'cisco_asa.local_host_teardown',
                   'cisco_asa.dynamic_tear',
                   'cisco_asa.deny',
                   'cisco_asa.discard',
                   'cisco_asa.esmtp_size_violation',
                   'cisco_asa.ftp',
                   'cisco_asa.icmp',
                   'cisco_asa.ids',
                   'cisco_asa.ike_no_policy',
                   'cisco_asa.ipsec.*',
                   'cisco_asa.local_host_buildup',
                   'cisco_asa.nat_t',
                   'cisco_asa.pitcher_received',
                   'cisco_asa.key_sa_active',
                   'cisco_asa.pitcher_key_aquire',
                   'cisco_asa.pitcher_key_delete',
                   'cisco_asa.ssh_session_normal_termination',
                   'cisco_asa.sa_inbound_created',
                   'cisco_asa.sa_inbound_deleted',
                   'cisco_asa.sa_outbound_created',
                   'cisco_asa.sa_outbound_deleted',
                   'cisco_asa.translation_failed',
                   'cisco_asa.udp_route_fail',
                   'cisco_asa.udp_egress_iface_fail',
                   'cisco_asa.user.auth_success',
                   'cisco_asa.user.logout',
                   'cisco_asa.user.priv_level_change',
                   'cisco_asa.user.executed_cmd',
                   'cisco_asa.user.executed_the_cmd',
                   'cisco_asa_host_matched',
                   'pfsense.icmp',
                   'pfsense.tab',
                 );
    my $ignore=0;
    foreach my $i (@ignore){ if($match =~m/$i/){ $ignore=1; } }

    if($ignore == 1){                                 # do nothing, we dont' care about these right now.
        print STDERR "";
    }elsif ($match eq 'cisco_asa.session_buildup'){   # we want connection buildups through the firewalls
         $proto = $args->[6];
         $proto=~tr/A-Z/a-z/;
         $src_raw = $args->[8];
         if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
             $src_ip = $2; $src_port = $3;
         }
         $tgt_raw = $args->[9];
         if($tgt_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
             $tgt_ip = $2; $tgt_port = $3;
         }
         $kernel->yield("send_sketch","$src_ip:$src_port -> $tgt_ip:$tgt_port/$proto");
    }elsif($match =~ m/cisco_asa.dynamic_build/){      # we want connection buildups through the firewalls
         if($args->[6] =~ m/(\S+):(\S+)\/([0-9]+)/){
             $src_if = $1; $src_ip = $2; $src_port = $3;
         }
         if($args->[7] =~ m/(\S+):(\S+)\/([0-9]+)/){
             $tgt_if = $1; $tgt_ip = $2; $tgt_port = $3;
         }
         $kernel->yield("send_sketch","$src_ip:$src_port -> $tgt_ip:$tgt_port/$proto");
    }elsif($match =~ m/cisco_asa.udp_permitted/){       # we want connection buildups through the firewalls
         if($args->[6] =~ m/(\S+):(\S+)\/([0-9]+)/){
             $src_if = $1; $src_ip = $2; $src_port = $3;
         }
         if($args->[7] =~ m/(\S+):(\S+)\/([0-9]+)/){
             $tgt_if = $1; $tgt_ip = $2; $tgt_port = $3;
         }
         $proto='udp';
    }elsif($match =~ m/pfsense.connection/){            # we want connection buildups through the firewalls
         $proto='';
         if($args->[9] =~ m/proto\s+(\S+)\s+/){
             $proto = $1;
             $proto =~ tr/A-Z/a-z/;
         }
         @src = split(/\./,$args->[10]);
         $src_port = pop(@src);
         $src_ip = join('.',@src);
 
         @tgt = split(/\./,$args->[11]);
         $tgt_port = pop(@tgt);
         $tgt_ip = join('.',@tgt);
         $kernel->yield("send_sketch","$src_ip:$src_port -> $tgt_ip:$tgt_port/$proto");
    }else{
        print STDERR "Unhandled: $match [$#{ $args }]\n"; 
    }
}

sub got_log_rollover {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "Log rolled over.\n"; 
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

