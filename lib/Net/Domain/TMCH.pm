# Copyrights 2013 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.01.
use warnings;
use strict;

package Net::Domain::TMCH;
use vars '$VERSION';
$VERSION = '0.12';

use base 'Exporter';

use Log::Report                  'net-domain-smd';

use Net::Domain::SMD       ();
use Net::Domain::TMCH::CRL ();
use Net::Domain::SMD::RL   ();

use Crypt::OpenSSL::VerifyX509 ();
use Crypt::OpenSSL::X509   ();
use File::Basename         qw(dirname);
use File::Spec::Functions  qw(catfile);
use Scalar::Util           qw(blessed);
use URI                    ();

use constant
  { CRL_SOURCE => 'http://crl.icann.org/tmch.crl'   # what? no https?
  };


sub new($%) { my ($class, %args) = @_; (bless {}, $class)->init(\%args) }

sub init($)
{   my ($self, $args) = @_;
    $self->{NDT_smds} = $args->{smds_admin}
      || Net::Domain::SMD->new(prepare => 'READER');

    my $stage    = $self->{NDT_pilot}
      = $args->{is_pilot} ? 'tmch_pilot' : 'tmch';
    my $tmch_pem = $args->{tmch_certificate}
     || catfile dirname(__FILE__), 'TMCH', 'icann', "$stage.pem";

    $self->{NDT_tmch_cert} = Crypt::OpenSSL::X509->new_from_file($tmch_pem);
    $self->{NDT_tmch_ca}   = Crypt::OpenSSL::VerifyX509->new($tmch_pem);

    $self->{NDT_crl}   = $self->_crl($args->{cert_revocations} || CRL_SOURCE);
    $self->{NDT_smdrl} = [ $self->_smdrl($args->{smd_revocations}) ];

    $self;
}

sub _crl($)
{   my ($self, $r) = @_;

    $r = URI->new($r)
        if !blessed $r && $r =~ m!^https?://!;

    return Net::Domain::TMCH::CRL->fromFile($r)
        if !blessed $r;

    return $r
        if $r->isa('Net::Domain::TMCH::CRL');

    return Net::Domain::TMCH::CRL->fromURI($r)
        if $r->isa('URI');

    error __x"revocation_list for THMC is not a {pkg}, filename, or uri"
      , pkg => 'Net::Domain::TMCH::CRL';
}

sub _smdrl($)
{   my ($self, $r) = @_;

    return ()
        unless defined $r;

    return map $self->_smdrl($_), @$r
        if ref $r eq 'ARRAY';

    $r = URI->new($r)
        if !blessed $r && $r =~ m!^https?://!;

    return Net::Domain::SMD::RL->fromFile($r)
        if !blessed $r;

    return $r
        if $r->isa('Net::Domain::SMD::RL');

    return Net::Domain::SMD::RL->fromURI($r)
        if $r->isa('URI');
    
    error __x"revocation_list for SMD is not a {pkg} or filename"
      , pkg => 'Net::Domain::SMD::RL';
}

#-------------------------


sub smdAdmin()       {shift->{NDT_smds}}
sub isPilot()        {shift->{NDT_pilot}}
sub tmchCertificate(){shift->{NDT_tmch_cert}}
sub tmchCA()         {shift->{NDT_tmch_ca}}
sub certRevocations(){shift->{NDT_crl}}
sub smdRevocations() { @{shift->{NDT_smdrl}} }

#-------------------------


sub smd($%)
{   my ($self, $filename, %args) = @_;

    my $smd = $self->smdAdmin->read($filename);
    return $smd
        if !$smd || $args{trust_certificates};

    my $tmch_cert = $self->tmchCertificate;

    my ($tmv_cert) = $smd->certificates(issuer => $tmch_cert->subject);
    defined $tmv_cert
        or error __x"smd in {fn} does not contain an TMV certificate"
             , fn => $filename;

    $self->tmchCA->verify($tmv_cert)
        or error __x"invalig TMV certificate in {fn}", fn => $filename;

    $args{accept_expired} || ! $tmv_cert->checkend(0)
        or error __x"the TMV certificate in {fn} has expired", fn => $filename;

    $self->certRevocations->isRevoked($tmv_cert)
        and error __x"smd in {fn} contains revoked TMV certificate"
             , fn => $filename;

    foreach my $rl ($self->smdRevocations)
    {   error __x"smd in {fn} is revoked according to {source}"
          , fn => $filename, source => $rl->source
            if $rl->isRevoked($smd);
    }

    $smd;
}

1;
