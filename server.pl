#!/usr/bin/perl
################################################################################
#                                                                              #
BEGIN {
        # figure out where we are and include our relative lib directory
        my @libsearch = ('lib','../magnetosphere/lib');
        use Cwd;
        my $oldpwd=getcwd();
        my $script=$0;
        if($script=~s/(.*)\/([^\/]*)//){ $script=$2; }
        chdir($1);
        $pwd=getcwd();
        foreach my $lib (@libsearch){
            unshift(@INC,"$pwd/$lib") if ( -d "$pwd/$lib");
        }
      }
#                                                                              #
################################################################################
package Something::Or::Other;
use Net::Infrastructure;
use strict;
use warnings;

use Socket;
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW Filter::Stream);
use Data::Dumper;

################################################################################
# server
################################################################################
sub new {
    my $class = shift;
    my $cnstr = shift;
    my $self = {};
    bless($self, $class);

    $self->{'counter'}=0;
    ($self->{'ip'},$self->{'port'}) = split(/:/, $cnstr->{'listen'}) if($cnstr->{'listen'});
    $self->{'ip'}='0.0.0.0' unless $self->{'ip'};
    $self->{'port'}=3737 unless $self->{'port'};
    $self->{'policy_dir'} = $cnstr->{'policies'}||"/var/cache/git/firewall-rules";
    $self->{'ignore'} = YAML::LoadFile("$self->{'policy_dir'}/exceptions");
    $self->{'inf'} = Net::Infrastructure->new({ 'conf_dir' => $self->{'policy_dir'} });

    POE::Session->create(
                          object_states => [ 
                                             $self => [ 
                                                        '_start',
                                                        '_stop',
                                                        'socket_birth',
                                                        'socket_input',
                                                        'socket_death',
                                                      ],
                                           ],

                        );
}

sub _start {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $heap->{listener} = POE::Wheel::SocketFactory->new(
                                                        BindAddress  => $self->{'ip'},
                                                        BindPort     => $self->{'port'},
                                                        Reuse        => 'yes',
                                                        SuccessEvent => 'socket_birth',
                                                        FailureEvent => 'socket_death',
                                                      );
}

sub _stop {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    delete $heap->{listener};
    delete $heap->{session};
}

################################################################################
# socket
################################################################################

sub socket_birth {
    my ($self, $kernel, $heap, $sender, $socket, $address, $port) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $address = inet_ntoa($address);
    POE::Session->create(
                          inline_states => {
                                             _start => sub { $kernel->yield("socket_success", $socket, $address, $port); },
                                             _stop  => sub { $kernel->yield("socket_death", $socket, $address, $port); },
                                           },
                          object_states => [
                                             $self => [
                                                        'socket_success',
                                                        'socket_input',
                                                        'socket_death',
                                                        'process_token',
                                                      ],
                                           ],
                          args          => [ $socket, $address, $port ],

                      );

}

sub socket_death {
    my ($self, $kernel, $heap, $sender, $socket, $address, $port) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    if ($_[HEAP]->{socket_wheel}) { delete $_[HEAP]->{socket_wheel}; }
}

sub socket_success {
    my ($self, $kernel, $heap, $sender, $connected_socket, $address, $port) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "= I = CONNECTION from $address : $port \n";
    $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                                                        Handle => $connected_socket,
                                                        Driver => POE::Driver::SysRW->new(),
                                                        Filter => POE::Filter::Stream->new(),
 
                                                        InputEvent => 'socket_input',
                                                        ErrorEvent => 'socket_death',
   );
}

sub socket_input {
    my ($self, $kernel, $heap, $sender, $buf, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    # append the ringbuffer for that session id
    $self->{'rbuf'}->{ $sender->ID } .= $buf if($buf);
    my $in_token = 0;
    my $token='';
  
    ############################################################################   
    # Now the data can come in partially, so we need to tokenize the input and
    # print only the token data we care about, and save the remainder for the
    # next transmission. wcyd?
    ############################################################################   

    for(my $i=0; $i<=length( $self->{'rbuf'}->{ $sender->ID }) - 1 ; $i++){
        my $char = substr($self->{'rbuf'}->{ $sender->ID },$i,1);
        if($char eq ']'){ $in_token = 0; $kernel->yield("process_token",$token); $token=''; }
        if($in_token == 1){ $token.=$char; }
        if($char eq '['){ $in_token = 1; }
    }

    # remvove any and everything up to the last complete token (last token close)
    $self->{'rbuf'}->{ $sender->ID }=~s/.*\]//; 
    # remvove everything up to the last (partial) token's start character, leave that in the ring buffer for the next event
    $self->{'rbuf'}->{ $sender->ID }=~s/.*\[/\[/; 
}

# this is the inspector
sub process_token {
    my ($self, $kernel, $heap, $sender, $token, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $process=1;
    # if it matches any of our skip list, don't process it.
    foreach my $omit (@{ $self->{'ignore'} }){ if($token=~m/$omit/){ $process=0; } }
    if($process == 1){
        if(!$self->{'inf'}->allowed("$token")){
            # $self->{'inf'}->close_to("$token");
            print STDERR "$token\n";
        }
    }
}

1;
my $server = Something::Or::Other->new({ 
                                         'listen'   => '0.0.0.0:3737',
                                         'policies' => $ENV{'HOME'}.'/dev/git/firewall-rules',
                                       });

#YAML::DumpFile("/var/tmp/suggestions",$self->{'inf'}->{'rules_to_add'});
$poe_kernel->run();
exit;


