# Copyrights 2013 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.01.
use warnings;
use strict;

package Net::Domain::SMD::File;
use vars '$VERSION';
$VERSION = '0.11';

use Log::Report   'net-domain-smd';

use MIME::Base64       qw/decode_base64/;
use XML::LibXML        ();
use POSIX              qw/mktime tzset/;
use XML::Compile::Util qw/type_of_node/;
use List::Util         qw/first/;


sub new($%) { my ($class, %args) = @_; (bless {}, $class)->init(\%args) }
sub init($)
{   my ($self, $args) = @_;

    # Clean object construction is needed when we are going to write
    # SMD files... but we won't for now.
    $self;
}


sub fromFile($%)
{   my ($class, $fn, %args) = @_;
    my $self   = $class->new(%args);

    $self->{NDSF_fn} = $fn;
    my $schemas = $args{schemas} or panic;

    open my($fh), '<:raw', $fn
        or fault "cannot read from smd file {fn}", fn => $fn;

    my $xml;
  LINE:
    while(<$fh>)
    {   next LINE if m/^#|^\s*$/;   # not yet permitted in those files
        if( m/^-{3,}BEGIN .* SMD/)
        {   my @smd;
            while(<$fh>)
            {   last if m/^-{3,}END .* SMD/;
                push @smd, $_;
            }
            $xml = \decode_base64(join '', @smd);
            next LINE;
        }

        # Only few of the fields are of interest: often better inside XML
        my ($label, $value) = split /\:\s+/;
        defined $value && length $value or next;
        $label = lc $label;
        $value =~ s/\s*$//s;
        if($label eq 'u-labels')
        {   $self->{NDSF_labels} = [split /\s*\,\s*/, $value];
        }
        elsif($label eq 'marks')  # trademark names?  Comma list?
        {   $self->{NDSF_marks}  =  [split /\s*\,\s*/, $value];
        }

    }

    $xml or error __x"there is not SMD information in {fn}", fn => $fn;

    my $root = $schemas->dataToXML($xml);
    $self->{NDSF_payload} = $root;
    my $type = type_of_node $root;
#warn $root;

    my $data = $schemas->reader($type)->($root);
    $self->{NDSF_data}  = $data;
    $self;
}
    
#----------------

sub filename()  {shift->{NDSF_fn}}
sub payload()   {shift->{NDSF_payload}}
sub labels()    { @{shift->{NDSF_labels} || []} }
sub marks()     { @{shift->{NDSF_marks}  || []} }

sub _data()     {shift->{NDSF_data}}     # hidden
sub _mark()     {shift->_data->{mark}}     # hidden

#----------------

sub smdID()     {shift->_data->{smd_id}}
sub from()      {shift->_data->{smd_notBefore}}
sub until()     {shift->_data->{smd_notAfter}}
sub fromTime()  {my $s = shift; $s->date2time($s->from)}
sub untilTime() {my $s = shift; $s->date2time($s->until)}

sub issuer()
{   my $i = shift->_data->{smd_issuerInfo} or return;
    # remove smd namespace prefixes
    my %issuer;
    while(my($k, $v) = each %$i)
    {   $k =~ s/smd_//;
        $issuer{$k} = $v;
    }
    \%issuer;
}


sub courts()  { @{shift->_mark->{court} || []} }


sub trademarks()  { @{shift->_mark->{trademark} || []} }


sub treaties()  { @{shift->_mark->{treatyOrStatute} || []} }


sub date2time($)
{   my ($self, $date) = @_;
    # For now, I only support Zulu time: 2013-07-12T12:53:48.408Z
    $date =~ m/^([0-9]{4})\-([0-1]?[0-9])\-([0-3]?[0-9])T([0-2]?[0-9])\:([0-5]?[0-9])\:([0-6]?[0-9])(\.[0-9]+)?Z?$/ or return;

    my $oldtz = $ENV{TZ};
    $ENV{TZ}  = 'UTC';
    tzset;

    my $sec = mktime $6, $5, $4, $3, $2-1, $1-1900;
    $sec += $7 if defined $7;

    $ENV{TZ} = $oldtz;
    tzset;

    $sec;
}

#---------------

sub certificates(%)
{   my ($self, %args) = @_;

    my $tokens = $self->_data->{ds_Signature}{ds_KeyInfo}{__TOKENS} || [];
    my @certs  = map $_->certificate, @$tokens;

    my $issuer = $args{issuer};
    $issuer ? (grep $_->subject eq $issuer, @certs) : @certs;
}

1;
