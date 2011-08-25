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
use LWP::Simple;
use JSON;
use Net::LDAP;


# Net::Infrastructure is what we use to match 
# use Net::Infrastructure; 

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
                                                        'got_log_line', 
                                                        'got_log_rollover',
                                                        'sketch_connection',
                                                        'send_sketch',
                                                        '_default',
                                                        'irc_001',
                                                        'irc_public',
                                                        'start_log',
                                                        'event_timeout',
                                                        'printer_lookup',
                                                      ],
                                           ],
    );
    return $self;
}

sub _start {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    $_[HEAP]{linecount}=0;
    $self->{'irc'}->yield( register => 'all' );
    $self->{'irc'}->yield( connect => { } );
    $kernel->delay('start_log',5);
    return;
}

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
} 

sub event_timeout{
    my ($self, $kernel, $heap, $sender, $id, $message, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    if($heap->{'pending'}->{$id}){
        $kernel->yield('send_sketch', "$id: $message");
        delete ($heap->{'pending'}->{$id});
    }
}

sub send_sketch {
    my ($self, $kernel, $heap, $sender, $sketch, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print "SKETCH: $sketch\n";
    $self->{'irc'}->yield( privmsg => $self->{'channel'} => "$sketch");
}

sub sketch_connection {
    my ($self, $kernel, $heap, $sender, $match, $args, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my @ignore = ( );
    my $ignore=0;
    foreach my $i (@ignore){ if($match =~m/$i/){ $ignore=1; } }
    if($ignore == 1){
        # do nothing, we dont' care about these right now.
        print "";
    }elsif ($match eq 'windows_event.printer_jobid'){
        $args->[3]=~s/\..*//g; $args->[3]=~tr/A-Z/a-z/;
        $args->[7]=~s/\..*//g; $args->[7]=~tr/A-Z/a-z/;
        next if ( $args->[3] =~ m/^arctic/) ; # ignore the lab
        next if ( $args->[7] =~ m/^prnt0024/) ; # ignore the qa printer
        $kernel->yield('send_sketch', "Job: $args->[10]: $args->[7]");
        $heap->{'pending'}->{ $args->[10] }->{'host'} = $args->[7];
        $kernel->delay('event_timeout', 600, $args->[10],"job timed out");
    }elsif ($match eq 'windows_event.dualsys_work_thread_msg'){
        $args->[3]=~s/\..*//g; $args->[3]=~tr/A-Z/a-z/;
        $args->[7]=~s/\..*//g; $args->[7]=~tr/A-Z/a-z/;
        $args->[9]=~s/\..*//g; $args->[9]=~tr/A-Z/a-z/;
        next if ( $args->[3] =~ m/^arctic/) ; # ignore the lab
        next if ( $args->[7] =~ m/^prnt0024/) ; # ignore the qa printer
        $kernel->yield('send_sketch',"$args->[7]: $args->[9]") unless(( $args->[9]=~m/^ok$/i) || ( $args->[9]=~m/^5,00 volts$/i));
    }elsif ($match eq 'windows_event.print_end'){
        $args->[8]=~tr/A-Z/a-z/; $args->[9]=~tr/A-Z/a-z/;
        # ignore things we're not waiting for:
        if($heap->{'pending'}->{$args->[8]}){
                delete($heap->{'pending'}->{$args->[8]});
                $kernel->yield('send_sketch', "Job: $args->[8]: $args->[9]");
        }
    }
}

sub got_log_rollover {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    print STDERR "Log rolled over.\n"; 
}

sub lookup_printer{
    my $self = shift;
    my $soekris = shift if @_;
    return undef unless defined($soekris);
    my $fqdn = `hostname -f`;
    chomp($fqdn);
    my @parts = split(/\./,$fqdn);
    my $hostname = shift(@parts);
    my $domainname = join('.',@parts);
    my $basedn = "dc=".join(',dc=',@parts);
    my $ldap = Net::LDAP->new( "ldap.$domainname" ) or warn "$@\n";
    my $mesg = $ldap->bind;
    print STDERR $mesg->error."\n" if $mesg->code;
    print STDERR "searching: ou=Card\@Once,$basedn for (uniqueMember=cn=$soekris,ou=Hosts,$basedn)\n";
    $mesg = $ldap->search( base   => "ou=Card\@Once,$basedn", filter => "(uniqueMember=cn=$soekris,ou=Hosts,$basedn)", scope=> 'sub');
    print STDERR Data::Dumper->Dump([$mesg]);
    print STDERR $mesg->error."\n" if $mesg->code;
    my $found = 0;
    foreach $entry ($mesg->entries) {
        $found ++;
        my $distname = $entry->dn;
        $distname=~s/,\s+/,/g;
        my ($city, $branch);
        if($distname =~m/cn=(.*),\s*ou=Systems,ou=(.*),*ou=Card\@Once,$basedn/){
            ($city,$branch) = ($1, $2);
            $city=~s/,$//;
        }
        return "$branch ($city)";
    }
    unless ($found > 0){
        return undef;
    }

    
}

sub printer_lookup{
    my ($self, $kernel, $heap, $sender, $soekris, $replyto, $who, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];
    my $description = $self->lookup_printer($soekris);
    print STDERR "-=[$description]=-\n";
    if($description){
        $self->{'irc'}->yield( privmsg => $replyto => "$soekris => $description");
    }else{
        $self->{'irc'}->yield( privmsg => $replyto => "$soekris not found. (did you forget to put it in LDAP ou=Card\@Once?)");
    }
}

sub irc_001 {
    my ($self, $kernel, $heap, $sender, @args) = @_[OBJECT, KERNEL, HEAP, SENDER, ARG0 .. $#_];

     # Since this is an irc_* event, we can get the component's object by
     # accessing the heap of the sender. Then we register and connect to the
     # specified server.
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
    my $soekris=undef;
    my $fqdn = `hostname -f`;
    chomp($fqdn);
    my @parts = split(/\./,$fqdn);
    my $hostname = shift(@parts);
    my $domainname = join('.',@parts);

    print "$what\n";
    if ( my ($device) = $what =~ /^\s*[Ww]here\s*is\s*(\S*[0-9]+)\s*\?*$/ ){ 
        $device=~s/^[Ss][Kk][Rr][Ss]//;
        $device=~s/^[Pp][Rr][Nn][Tt]//;
        $device=~s/^0*//;
        if($device=~m/[0-9]+/){
            if($device < 10){ $soekris="skrs000$device"; }
            elsif($device < 100){ $soekris="skrs00$device"; }
            elsif($device < 1000){ $soekris="skrs0$device"; }
            #$self->{'irc'}->yield( privmsg => $channel => "parsed as: $soekris");
            $kernel->yield('printer_lookup',$soekris,$channel,$nick);
        }
    
    }elsif ( $what =~ /^\s*!*report/ ){ 
        print STDERR "http://mina.dev.$domainname:9090/caoPrinterStatus/\n";
        my $json = JSON->new->allow_nonref;
        my $struct = $json->decode( get("http://mina.dev.$domainname:9090/caoPrinterStatus/") );
        foreach my $item (@{ $struct }){
            my $name=$item->{'PrinterName'};
            $name=~s/\..*//;
            $name=~tr/A-Z/a-z/;
            my $total = ($item->{'GoodJobs'} + $item->{'BadJobs'});
            my $percentage = int(10000*($item->{'GoodJobs'}/$total))/100;
print STDERR "[$item->{'GoodJobs'}/$total] $name ($percentage%)\n";
        }
        #$self->{'irc'}->yield( privmsg => $channel => "$content");
    
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
                                         'file'     => '/var/log/windows/applications.log',
                                         'template' => 'windows.yml',
                                         'server'   => 'irc',
                                         'ircname'  => 'Card@Once Watcher',
#                                         'nick'     => 'cardwatch',
                                         'nick'     => 'caobot',
#                                         'channel'  => '#cao',
                                         'channel'  => '#bottest',
                                       });
POE::Kernel->run();
exit;
