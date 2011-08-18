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
use POE::Filter::Stream;
use POE qw(Component::IRC);


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
    $self->{'file'} = $cnstr->{'file'} if($cnstr->{'file'});
    $self->{'max_lines'}=$cnstr->{'max_lines'}||undef;
    $self->{'TR'} = new Template::Regex;
    $self->{'TR'}->load_template_file($cnstr->{'template'});
    $self->{'irc'} = POE::Component::IRC->spawn(
                                                 nick => 'vpnwatcher',
                                                 ircname => 'VPN Connection watcher',
                                                 server  => 'hercules',
                                               ) or die "Oh noooo! $!";
    POE::Session->create(
                          object_states => [
                                             $self => [ 
                                                        '_start',
                                                        'got_log_line', 
                                                        'got_log_rollover',
                                                        'sketch_connection',
                                                        'send_sketch',
                                                        '_default',
                                                        'irc_001',
                                                        'irc_public',
                                                      ],
                                           ],
    );
    return $self;
}

sub _start {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $_[HEAP]{linecount}=0;
    $_[HEAP]{tailor} = POE::Wheel::FollowTail->new(
                                                    Filename => $self->{'file'},
                                                    InputEvent => "got_log_line",
                                                    ResetEvent => "got_log_rollover",
                                                  );
    $self->{'irc'}->yield( register => 'all' );
    $self->{'irc'}->yield( connect => { } );
    return;

}

sub ip2n{
    my $self=shift;
    return unpack N => pack CCCC => split /\./ => shift;
}

sub n2ip{
    my $self=shift;
    return join('.',map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

sub got_log_line {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
   my $line = $args[0];
   my $result = $self->{'TR'}->parse_line($line);
   my $last = $#{ $result->{'patterns'} } - 1;
   my $output = $result->{'name'};
   if( $output =~ m/remainder$/ ){
       $output =~ s/remainder$/\[$result->{'patterns'}->[ $last ]\]/;
   }else{
       $heap->{'last'}='' unless( defined($heap->{'last'}) );
       # remove line-after-line of repeated output
       if($heap->{'last'} ne $result->{'name'}){
           $kernel->yield("sketch_connection",$result->{'name'}, $result->{'patterns'}, $line);
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
    my ($self, $kernel, $heap, $sender, $match, $patterns, $line, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];

    my $start_net=$self->ip2n("10.100.1.0");
    my $state='';
    my  ($date, $time, $tz, $asa, $trash, $group, $peer, $network, $netmask);

    if ($match eq 'cisco_asa.ipsec_route_add'){   # we want connection buildups through the firewalls
        ($date, $time, $tz, $asa, $trash, $peer, $network, $netmask) = (@{ $patterns });
    }elsif($match eq 'cisco_asa.ipsec_route_add_group'){   # we want connection buildups through the firewalls
        ($date, $time, $tz, $asa, $trash, $group, $peer, $network, $netmask) = (@{ $patterns });
        $state = 'connected';
    }elsif($match eq 'cisco_asa.ipsec_route_del'){   # we want connection buildups through the firewalls
        ($date, $time, $tz, $asa, $trash, $peer, $network, $netmask) = (@{ $patterns });
        $state='disconnected';
    }elsif($match eq 'cisco_asa.ipsec_route_del_group'){   # we want connection buildups through the firewalls
        ($date, $time, $tz, $asa, $trash, $group, $peer, $network, $netmask) = (@{ $patterns });
        $state='disconnected';
    }

    if($state ne ''){
        $asa=~s/\..*//;
        $time=~s/\..*//; # lose the milliseconds
        my $soekris = (($self->ip2n($network) - $start_net)/4) + 1;
        if($soekris < 10 ){ $soekris = "000$soekris"; }
        elsif($soekris < 100 ){ $soekris = "00$soekris"; }
        elsif($soekris < 1000 ){ $soekris = "0$soekris"; }
        print "$line\n";
        print "$date $time: $asa skrs$soekris $state.\n";
        $self->{'irc'}->yield( privmsg => '#bottest' => "$date $time: $asa skrs$soekris $state.");
    }
}

sub got_log_rollover {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "Log rolled over.\n"; 
}

sub irc_001 {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];

     # Since this is an irc_* event, we can get the component's object by
     # accessing the heap of the sender. Then we register and connect to the
     # specified server.
     my $irc = $sender->get_heap();

     print "Connected to ", $irc->server_name(), "\n";

     # we join our channels
     $irc->yield( join => $_ ) for ('#infrastructure');
     $irc->yield( privmsg => '#infrastructure' => "*cough*");
     return;
}

sub irc_public {
     my ($self, $kernel, $heap, $sender, $who, $where, $what, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
     my $nick = ( split /!/, $who )[0];
     my $channel = $where->[0];

     if ( my ($rot13) = $what =~ /^rot13 (.+)/ ) {
         $rot13 =~ tr[a-zA-Z][n-za-mN-ZA-M];
         $irc->yield( privmsg => $channel => "$nick: $rot13" );
     }
     return;
}

# We registered for all events, this will produce some debug info.
sub _default {
     my ($self, $kernel, $heap, $sender, $event, $args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
     my @output = ( "$event: " );

     for my $arg (@$args) {
         if ( ref $arg eq 'ARRAY' ) {
             push( @output, '[' . join(', ', @$arg ) . ']' );
         }
         else {
             push ( @output, "'$arg'" );
         }
     }
     print join ' ', @output, "\n";
     return;
}

1;

$|=1;
my $cisco  = Log::Tail::Reporter->new({ 
                                         'file'     => '/var/log/cisco/network.log',
                                         'template' => 'cisco-asa.yml',
                                         #'server' => '192.168.7.71:3737',
                                         #'max_lines'    => 100,
                                       });
POE::Kernel->run();
exit;

