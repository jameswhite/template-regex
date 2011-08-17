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
    return $self;
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
    if ($match eq 'cisco_asa.ipsec_route_add'){   # we want connection buildups through the firewalls
        my ($date, $time, $tz, $asa, $trash, $group, $peer, $network, $netmask) = (@{ $patterns });
        $asa=~s/\..*//;
        $time=~s/\..*//; # lose the milliseconds
        my $soekris = (($self->ip2n($network) - $start_net)/4) + 1;
        print "$date $time: $asa skrs$soekris connected.\n"

    }elsif($match eq 'cisco_asa.ipsec_route_del'){   # we want connection buildups through the firewalls
        my ($date, $time, $tz, $asa, $trash, $group, $peer, $network, $netmask) = (@{ $patterns });
        $asa=~s/\..*//;
        $time=~s/\..*//; # lose the milliseconds
        my $soekris = (($self->ip2n($network) - $start_net)/4) + 1;
        print "$date $time: $asa skrs$soekris disconnected.\n"
    }
}

sub got_log_rollover {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "Log rolled over.\n"; 
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

