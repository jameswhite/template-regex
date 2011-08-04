#!/usr/bin/perl -w
package Template::Regex;
################################################################################
# template out regular expressions to abstract some of the insanity away from
# parsing log files that have repetitive patterns in them (Cisco PIX)
################################################################################
use strict;
use Template;
use YAML;
use Data::Dumper;
my $DEBUG=1;

sub new{
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    $self->{'cfg'}->{'spc_to_ws'} = $cnstr->{'spc_to_ws'}||1;
    bless($self,$class);
    return $self;
}

sub load_template_file{
    my $self = shift;
    my $file=shift if @_;
    return $self unless $file;
    $self->{'templates'} = YAML::LoadFile($file);
    return $self;
}

sub parse_line{
    my $self = shift;
    my $line = shift if @_;
    #print "$line\n";
    return undef unless $line;
    # send the line, top-level log templates and regular expression templates to parse_line_segment
    $self->parse_line_segment( $line, $self->{'templates'}->{'log_tpl'}, $self->{'templates'}->{'regex_tpl'});
}

sub parse_line_segment{
    my $self = shift;
    my ($line, $log_t, $rgx_t) = @_;
    my $entry_name = undef; 
    my $entry_patters = [];
    my $remainder = undef;
    my $config = { INTERPOLATE => 1, POST_CHOMP => 1 };
    my $tt = Template->new($config);
    my $match = undef;
    foreach my $log_template (@{ $log_t }){
        my $tpl=$log_template->{'regex'};
        # clone the tag
        my $tag_counter = $tpl;
        # replace all tags with <ESC>
        $tag_counter =~ s/\[%[^%]+%\]//g;
        # count the <ESC>s
        my $tag_count = $tag_counter =~ tr/// + 1; # $1 is always the whole string
        # remove the spaces in the tags:
        $tpl=~s/\[%\s+/\[%/g; $tpl=~s/\s+%\]/%\]/g; 
        # convert all other whitespace to a literal '\s+'
        $tpl=~s/\s+/\\s+/g; 
        # put the spaces back in the templates, and wrap the templates in parenthesis for pattern retrieval
        $tpl=~s/\[%/\(\[% /g; $tpl=~s/%\]/ %\]\)/g;
        my $output = undef;
        $tt->process(\$tpl, $rgx_t, \$output) || die $tt->error();
        if($line=~m/^($output)/){ 
            my $matched=$1;
            # now we're matching only what was matched again with the /g option so we can get a list of patterns
            my @patterns = ($matched =~ /$output/g) ;
            # Parenthesis in a sed replace need to be escaped
            my $replace=$matched;
            print STDERR "[$line]\n";
            print STDERR "[$replace]\n";
            $replace=~s/\(/\\\(/g;
            $replace=~s/\)/\\\)/g;
            $line=~s/^$replace//;
            $remainder = $line;
            # process the remainder of the string if exists and remainder is defined
            #print STDERR "$log_template->{'name'}.[$remainder]\n";
            $entry_name = $log_template->{'name'};
            push(@{ $entry_patters }, @patterns );
            if( ($remainder ne "") && defined($log_template->{'remainder'}) ){
                my $return = $self->parse_line_segment( $remainder, $log_template->{'remainder'}, $self->{'templates'}->{'regex_tpl'} );
                if($return->{'name'}){ $entry_name.=".".$return->{'name'}; }
                push(@{ $entry_patters },@{ $return->{'patterns'} });
            }
            last;
        }
    }
    return { 'name' => $entry_name, 'patterns' => $entry_patters }
}

1;
