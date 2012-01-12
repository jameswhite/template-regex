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
use POE::Wheel::Run;
use POE qw(Component::IRC);
use LWP::Simple;
use JSON;
use Net::LDAP;

sub new {
    my $class = shift;
    my $self = {};
    my $cnstr = shift if @_;
    bless($self,$class);
    foreach my $argument ('server', 'port', 'channel', 'nick', 'ircname'){
        $self->{$argument} = $cnstr->{$argument} if($cnstr->{$argument});
    }
    foreach my $arg ('file', 'template'){
        if(! defined($cnstr->{$arg})){
            print STDERR "Necessary parameter [ $arg ] not defined. Aborting object.\n";
            return undef;
        }
    }
    if($cnstr->{'ignore'}){
        if(-f "$cnstr->{'ignore'}"){
            $self->{'ignore'} = YAML::LoadFile($cnstr->{'ignore'}); # should be a yaml list list of regexes
        }
    }
    $self->{'file'} = $cnstr->{'file'} if($cnstr->{'file'});
    $self->{'max_lines'}=$cnstr->{'max_lines'}||undef;
    $self->{'TR'} = new Template::Regex;
    $self->{'TR'}->load_template_file($cnstr->{'template'});
    $self->{'irc'} = POE::Component::IRC->spawn(
                                                 nick => $self->{'nick'},
                                                 ircname => $self->{'ircname'},
                                                 server  => $self->{'server'},
                                               ) or die "Oh noooo! $!";
    POE::Session->create(
                          object_states => [
                                             $self => [ 
                                                        '_start',
                                                        'start_log',
                                                        'got_log_line', 
                                                        'got_log_rollover',
                                                        'say',
                                                        'irc_001',
                                                        'irc_public',
                                                        '_default',
                                                        'spawn',
                                                        'on_child_stdout',
                                                        'on_child_stderr',
                                                        'on_child_close',
                                                        'on_child_signal',
                                                      ],
                                           ],
    );
    return $self;
}

sub _start {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $_[HEAP]{linecount}=0;
    $_[HEAP]{ignore} = $self->{'ignore'};
    $self->{'irc'}->yield( register => 'all' );
    $self->{'irc'}->yield( connect => { } );
    $kernel->delay('start_log',5);
    return;
}

################################################################################
# math stuff
################################################################################
sub ip2n{
    my $self=shift;
    return unpack N => pack CCCC => split /\./ => shift;
}

sub n2ip{
    my $self=shift;
    return join('.',map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

################################################################################
# log stuff
################################################################################
sub start_log {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "Loading Log.\n";
    $heap->{'tailor'} = POE::Wheel::FollowTail->new(
                                                     Filename   => $self->{'file'},
                                                     InputEvent => "got_log_line",
                                                     ResetEvent => "got_log_rollover",
                                                     #Seek   => 0,
                                                   );
    return;
}

sub got_log_line {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
   my $line = $args[0];
   if($line=~m/rule (617|939|1067|1195|2222)/){
       my $ignore=0;
       foreach my $regex (@{ $heap->{'ignore'} }){
           if($line=~m/$regex/){ 
               $ignore=1; 
           }
       }
       unless($ignore == 1){ 
           $kernel->yield("say",$line);
       }
   }
} 

sub got_log_rollover {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $self->{'irc'}->yield( privmsg => $self->{'channel'} => "Log rolled over.");
}

################################################################################
# irc stuff
################################################################################
sub say {
    my ($self, $kernel, $heap, $sender, $comment, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "$comment\n";
    $self->{'irc'}->yield( privmsg => $self->{'channel'} => "$comment");
}

sub irc_001 {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
     my $irc = $sender->get_heap();
     print "Connected to ", $irc->server_name(), "\n";
     # we join our channels
     $irc->yield( join => $_ ) for ($self->{'channel'});
     return;
}

sub irc_public {
    my ($self, $kernel, $heap, $sender, $who, $where, $what, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $nick = ( split /!/, $who )[0];
    my $channel = $where->[0];
    my $fqdn = `hostname -f`;
    chomp($fqdn);
    my @parts = split(/\./,$fqdn);
    my $hostname = shift(@parts);
    my $domainname = join('.',@parts);
    print "$what\n";
    if ( my ($device) = $what =~ /ls/ ){ 
        print STDERR Data::Dumper->Dump([$heap->{'ignore'}]);
        my $output='';
        foreach my $exception (@{ $heap->{'ignore'} }){
            $output.="$exception";
            if(length($output) > 200){
                $kernel->yield("say", "(".$output.")");
                $output='';
            }else{
                $output.="|";
            }
        }
        chop($output); # lose the last pipe
        $kernel->yield("say", "(".$output.")");
    }elsif( my ($pattern) = $what =~ /ignore\s+\/(.*)\// ){ 
        my $have=0;    
        foreach my $exception (@{ $heap->{'ignore'} }){
            if($pattern eq $exception){
                $have=1;    
            }
        }
        if($have == 0){
            push(@{ $heap->{'ignore'} },$pattern);
            $kernel->yield("say", "/$pattern/ ignored.");
            print STDERR Data::Dumper->Dump([$heap->{'ignore'}]);
        }
    }elsif( my ($rmpattern) = $what =~ /unignore\s+\/(.*)\// ){ 
        my @newignorelist;
        my @ignorelist = @{ $heap->{'ignore'} };
        while(my $item = shift (@ignorelist)){
            push(@newignorelist,$item) unless($item eq $rmpattern);
        }
        $heap->{'ignore'} = @newignorelist;
        print STDERR Data::Dumper->Dump([$heap->{'ignore'}]);
    }
    return $self;
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

################################################################################
# sub-process hooks.
################################################################################
sub spawn{
    my ($self, $kernel, $heap, $sender, $program, $reply_event) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $child = POE::Wheel::Run->new(
                                      Program      => $program,
                                      StdoutEvent  => "on_child_stdout",
                                      StderrEvent  => "on_child_stderr",
                                      CloseEvent   => "on_child_close",
                                    );

    $_[KERNEL]->sig_child($child->PID, "on_child_signal");

    # Wheel events include the wheel's ID.
    $_[HEAP]{children_by_wid}{$child->ID} = $child;

    # Signal events include the process ID.
    $_[HEAP]{children_by_pid}{$child->PID} = $child;

    # Save who whil get the reply
    $_[HEAP]{device}{$child->ID} = $program->[1];

    print("Child pid ", $child->PID, " started as wheel ", $child->ID, ".\n");
}

sub on_child_stdout {
    my ($self, $kernel, $heap, $sender, $stdout_line, $wheel_id) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $child = $_[HEAP]{children_by_wid}{$wheel_id};

    print "pid ", $child->PID, " STDOUT: $stdout_line\n";
    my $device =  $_[HEAP]{device}{$wheel_id};
    $self->{'irc'}->yield( privmsg => $self->{'channel'} => "$device => $stdout_line") unless( $stdout_line =~m/^\s*$/ ) ;
}

# Wheel event, including the wheel's ID.
sub on_child_stderr {
    my ($self, $kernel, $heap, $sender, $stderr_line, $wheel_id) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $child = $_[HEAP]{children_by_wid}{$wheel_id};
    print "pid ", $child->PID, " STDERR: $stderr_line\n";
}

# Wheel event, including the wheel's ID.
sub on_child_close {
    my ($self, $kernel, $heap, $sender, $wheel_id) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $child = delete $_[HEAP]{children_by_wid}{$wheel_id};
    delete $_[HEAP]{device}{$wheel_id};

    # May have been reaped by on_child_signal().
    unless (defined $child) {
      print "wid $wheel_id closed all pipes.\n";
      return;
    }

    print "pid ", $child->PID, " closed all pipes.\n";
    delete $_[HEAP]{children_by_pid}{$child->PID};
}

sub on_child_signal {
    my ($self, $kernel, $heap, $sender, $wheel_id) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "pid $_[ARG1] exited with status $_[ARG2].\n";
    my $child = delete $_[HEAP]{children_by_pid}{$_[ARG1]};

    # May have been reaped by on_child_close().
    return unless defined $child;

    delete $_[HEAP]{children_by_wid}{$child->ID};
    delete $_[HEAP]{device}{$wheel_id};
}

1;

################################################################################
# main.c
################################################################################
$|=1;
my $cisco  = Log::Tail::Reporter->new({ 
                                         'file'     => '/var/log/pfsense/pfsense.log',
                                         'template' => 'pfsense.yml',
                                         'ignore'    => '/tmp/ignore.yml',
                                         'server'   => 'irc',
                                         'ircname'  => 'Magneto Sphere',
                                         'nick'     => 'msphere',
                                         'channel'  => '#bottest',
                                       });
POE::Kernel->run();
exit;
