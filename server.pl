#!/usr/bin/perl
# http://poe.perl.org/?POE_Cookbook/TCP_Servers
use strict;
use warnings;

use Socket;
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW Filter::Stream);

#####
# MAIN
#####

local $| = 1;
our $debug      = 0;        # be very very noisy
our $serverport = 3737;

#fork and exit unless $debug;

POE::Session->create(
                      inline_states => {
                                         _start => \&parent_start,
                                         _stop  => \&parent_stop,
                                     
                                         socket_birth => \&socket_birth,
                                         socket_death => \&socket_death,
                                       }
                    );

# $poe_kernel is exported from POE
$poe_kernel->run();

exit;

####################################

sub parent_start {
  my $heap = $_[HEAP];
  #print "= L = Listener birth\n" if $debug;
  $heap->{listener} = POE::Wheel::SocketFactory->new(
                                                      BindAddress  => '0.0.0.0',
                                                      BindPort     => $serverport,
                                                      Reuse        => 'yes',
                                                      SuccessEvent => 'socket_birth',
                                                      FailureEvent => 'socket_death',
                                                    );
}

sub parent_stop {
  my $heap = $_[HEAP];
  delete $heap->{listener};
  delete $heap->{session};
  #print "= L = Listener death\n" if $debug;
}

##########
# SOCKET #
##########

sub socket_birth {
  my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];
  $address = inet_ntoa($address);

  #print "= S = Socket birth\n" if $debug;

  POE::Session->create(
                        inline_states => {
                          _start => \&socket_success,
                          _stop  => \&socket_death,
                    
                          socket_input => \&socket_input,
                          socket_death => \&socket_death,
                        },
                        args => [$socket, $address, $port],
                      );

}

sub socket_death {
  my $heap = $_[HEAP];
  if ($heap->{socket_wheel}) {
   #print "= S = Socket death\n" if $debug;
    delete $heap->{socket_wheel};
  }
}

sub socket_success {
  my ($heap, $kernel, $connected_socket, $address, $port) =
    @_[HEAP, KERNEL, ARG0, ARG1, ARG2];

  #print "= I = CONNECTION from $address : $port \n" if $debug;

  $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                                                      Handle => $connected_socket,
                                                      Driver => POE::Driver::SysRW->new(),
                                                      Filter => POE::Filter::Stream->new(),
                                                  
                                                      InputEvent => 'socket_input',
                                                      ErrorEvent => 'socket_death',
                                                    );

  #$heap->{socket_wheel}->put("1 Welcome. Say something. I'll say it back.\n\n");
}

sub socket_input {
  my ($heap,$sender, $buf) = @_[HEAP, SENDER, ARG0];
  #$buf =~ s/[\r\n]//gs;
  print STDERR $sender->ID.": $buf\n\n";
  #$heap->{socket_wheel}->put("$buf\n");
}
