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
   if($output=~m/anything$/){
       $output=~s/anything$/\[$result->{'patterns'}->[ $last ]\]/;
       if(defined($self->{'max_lines'})){
           $heap->{'linecount'}++ ;
           if($heap->{'linecount'} > $self->{'max_lines'}){
               exit 0;
           }
       }
       print "$output\n";
   }
   #my $proto = $result->{'patterns'}->[11];
} 
sub got_log_rollover {
   my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "Log rolled over.\n"; 
}

1;

#'[% DATE %]T[% TIME %][% TZ_OFF %] [% HOSTNAME %] pf: [% INT %] rule [% RULE %]: [% ACTION %] [% DIRECTION %] on [% IFACE %] [% PARENTHETICAL %] [% IP_PORT %] > [% IP_PORT %]'
#    chomp($line);
#    my ($proto, $src_raw, $src_zone, $src_ip, $src_port, $tgt_raw, $tgt_zone, $tgt_ip, $tgt_port);
#    if ($result->{'name'} eq 'cisco_asa.session_buildup'){
#       $proto = $result->{'patterns'}->[6];
#        $proto=~tr/A-Z/a-z/;
#        $src_raw = $result->{'patterns'}->[8];
#        if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
#            $src_zone = $1; $src_ip   = $2; $src_port = $3;
#        }
#        $tgt_raw = $result->{'pattern'}->[9];
#        if($src_raw=~m/([^:]+):([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+)\s+\(([^\)]*)\)/){
#            $tgt_zone = $1; $tgt_ip   = $2; $tgt_port = $3;
#        }
#       print "[$proto] $src_zone:$src_ip/$src_port -> $tgt_zone:$tgt_ip/$tgt_port\n";
#    }else{
#        print "$result->{'name'}\n";
#    }
my $pfsence = Log::Tail::Reporter->new({ 
                                         'file'     => '/var/log/pfsense/pfsense.log',
                                         'template' => 'pfsense.yml',
                                         #'max_lines'    => 100,
                                       });
POE::Kernel->run();
exit;
