# Copyrights 2013-2014 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.01.
use warnings;
use strict;

package Net::Domain::SMD::Schema;
use vars '$VERSION';
$VERSION = '0.17';

use base 'Exporter';

our @EXPORT_OK   = qw/SMD10_NS MARK10_NS/;
our %EXPORT_TAGS =
  ( ns10 => [ qw/SMD10_NS MARK10_NS/ ]
  );

use Log::Report                  'net-domain-smd';
use XML::Compile::Cache          ();
use XML::Compile::WSS::Signature ();
use XML::Compile::WSS::Util      qw(DSIG_NS);
use Net::Domain::SMD::File       ();
use File::Basename               qw(dirname);
use Scalar::Util                 qw(blessed);

use constant
  { SMD10_NS  => 'urn:ietf:params:xml:ns:signedMark-1.0'
  , MARK10_NS => 'urn:ietf:params:xml:ns:mark-1.0'
  };

my %prefixes =
  ( ds   => DSIG_NS   # do not take this prefix from these schemas
  , smd  => SMD10_NS
  , mark => MARK10_NS
  );


sub new($%) { my ($class, %args) = @_; (bless {}, $class)->init(\%args) }
sub init($)
{   my ($self, $args) = @_;

    my $xsddir = (dirname __FILE__) . '/xsd';
    my @xsds   =
      ( "$xsddir/mark-1.0.xsd"
      , "$xsddir/mark-1.0-bugs.xsd"
      , "$xsddir/signedMark-1.0.xsd"
      , "$xsddir/signedMark-1.0-bugs.xsd"
      );

    my $schemas = $self->{NDSS_schemas}
      = XML::Compile::Cache->new(\@xsds, prefixes => \%prefixes);

    # do not prefix 'mark', because the accesses it all the time.
    $schemas->addKeyRewrite('PREFIXED(smd)');
    my $sig = XML::Compile::WSS::Signature->new
      ( schema     => $schemas
      , prepare    => ($args->{prepare} || 'READER')
      , sign_types => [ 'smd:signedMarkType', 'ds:KeyInfoType' ]
      , sign_put   => 'smd:signedMarkType'
      , sign_when  => 'smd:signedMarkType'
      );

    if($args->{auto_datetime})
    {   $schemas->addHook
          ( action => 'READER', type => 'xsd:dateTime'
          , after => sub { Net::Domain::SMD->date2time($_[1]) }
          );
    }

    $self;
}

#-------------------------


sub schemas()     {shift->{NDSS_schemas}}

#-------------------------


sub from($%)
{   my ($self, $xml, %args) = @_;

    return ($self->read($xml, %args), $xml)
        if $xml !~ m/\n/ && -f $xml;

    my $source;
    unless(blessed $xml && $xml->isa('XML::LibXML::Node'))
    {   $xml      = XML::LibXML->load_xml(string => $xml);
        $source   = 'string';
    }

    if($xml->isa('XML::LibXML::Document'))
    {   $xml      = $xml->documentElement;
        $source ||= 'document';
    }

    my $smd   = Net::Domain::SMD->fromNode($xml, schemas => $self->schemas);
    $source ||= 'element';

    ($smd, $source);
}


sub read($)
{   my ($self, $fn) = @_;
    Net::Domain::SMD::File->fromFile($fn, schemas => $self->schemas);
}

1;
