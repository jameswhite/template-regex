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
                                                                                                             SeekBack => 10000,
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
################################################################################
# here we shove the line through Template::Regex and convert it to the tag.tag.tag form
#
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
   }else{
       $heap->{'last'}='' unless( defined($heap->{'last'}));
       # remove line-after-line of repeated output
       if($heap->{'last'} ne $result->{'name'}){
           $kernel->yield("sketch_connection",$result->{'name'}, $result->{'patterns'});
           $heap->{'last'} = $result->{'name'};
       }
   }
   print STDERR "$output\n";
} 


################################################################################
# this routine is used to ship the notification somewhere
#
sub send_sketch {
    my ($self, $kernel, $heap, $sender, $sketch, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $kernel->post($self->{'client'},"put","[$sketch]"); 
}

################################################################################
# here we take actions based on the tag.tag.tag and arguments that get returned
#
sub sketch_connection {
    my ($self, $kernel, $heap, $sender, $match, $args, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my @ignore = ( );
    my $ignore=0;
    foreach my $i (@ignore){ if($match =~m/$i/){ $ignore=1; } }

    if($ignore == 1){                                 # do nothing, we dont' care about these right now.
        print STDERR "";
    }elsif ($match eq 'windows_event.failed_command_buffer_submit'){
        print "################################################################################\n";
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
my $applications = Log::Tail::Reporter->new({ 
                                              'file'     => '/var/log/windows/applications.log',
                                              'template' => 'windows.yml',
                                            });
POE::Kernel->run();
exit;

