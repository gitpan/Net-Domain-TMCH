# Describing complex smd:signedMark
#     {urn:ietf:params:xml:ns:signedMark-1.0}signedMark
#
# Produced by XML::Compile::Translate::Template version undef
#          on Thu Nov 14 11:22:17 2013
#
# BE WARNED: in most cases, the example below cannot be used without
# interpretation.  The comments will guide you.
#
# xmlns:ds        http://www.w3.org/2000/09/xmldsig#
# xmlns:mark      urn:ietf:params:xml:ns:mark-1.0
# xmlns:smd       urn:ietf:params:xml:ns:signedMark-1.0

# is a smd:signedMarkType
{ # sequence of smd_id, smd_issuerInfo, smd_notBefore,
  #   smd_notAfter, abstractMark, ds_Signature

  # is a xsd:token
  # Pattern: \d+-\d+
  smd_id => "token",

  # is a smd:issuerInfoType
  smd_issuerInfo =>
  { # sequence of smd_org, smd_email, smd_url, smd_voice

    # is a xsd:token
    smd_org => "token",

    # is a xsd:token
    # length >= 1
    smd_email => "token",

    # is a xsd:token
    # is optional
    smd_url => "token",

    # is a mark:e164Type
    # smd_voice is simple value with attributes
    # is optional
    smd_voice =>
    { # is a xsd:token
      x => "token",

      # is a xsd:token
      # string content of the container
      _ => "token", },

    # is a xsd:token
    # attribute issuerID is required
    issuerID => "token", },

  # is a xsd:dateTime
  smd_notBefore => "2006-10-06T00:23:02Z",

  # is a xsd:dateTime
  smd_notAfter => "2006-10-06T00:23:02Z",

  # substitutionGroup mark:abstractMark
  #   abstractMark mark:abstractMarkType (abstract)
  #   mark         mark:markType
  abstractMark => { mark => {...} },

  # is a ds:SignatureType
  ds_Signature =>
  { # sequence of ds_SignedInfo, ds_SignatureValue, ds_KeyInfo,
    #   ds_Object

    # is a ds:SignedInfoType
    ds_SignedInfo =>
    { # sequence of ds_CanonicalizationMethod, ds_SignatureMethod,
      #   ds_Reference

      # is a ds:CanonicalizationMethodType
      ds_CanonicalizationMethod =>
      { # sequence of ANY

        # any element in any namespace
        # occurs any number of times
        ANY => [ "Anything", ],

        # is a xsd:anyURI
        # attribute Algorithm is required
        Algorithm => "http://example.com", },

      # is a ds:SignatureMethodType
      ds_SignatureMethod =>
      { # sequence of ds_HMACOutputLength, ANY

        # is a xsd:integer
        # is optional
        ds_HMACOutputLength => 42,

        # any element not in ds:
        # occurs any number of times
        ANY => [ "Anything", ],

        # is a xsd:anyURI
        # attribute Algorithm is required
        Algorithm => "http://example.com", },

      # is a ds:ReferenceType
      # occurs 1 <= # <= unbounded times
      ds_Reference =>
      [ { # sequence of ds_Transforms, ds_DigestMethod, ds_DigestValue

          # is a ds:TransformsType
          # is optional
          ds_Transforms =>
          { # sequence of ds_Transform

            # is a ds:TransformType
            # occurs 1 <= # <= unbounded times
            ds_Transform =>
            [ { # choice of ANY, ds_XPath
                # occurs any number of times
                cho_any => 
                [ {
                    # any element not in ds:
                    ANY => "Anything",

                    # is a xsd:string
                    ds_XPath => "example", },
                ],

                # is a xsd:anyURI
                # attribute Algorithm is required
                Algorithm => "http://example.com", }, ], },

          # is a ds:DigestMethodType
          ds_DigestMethod =>
          { # sequence of ANY

            # any element not in ds:
            # occurs any number of times
            ANY => [ "Anything", ],

            # is a xsd:anyURI
            # attribute Algorithm is required
            Algorithm => "http://example.com", },

          # is a xsd:base64Binary
          ds_DigestValue => "decoded bytes",

          # is a xsd:ID
          Id => "id_0",

          # is a xsd:anyURI
          URI => "http://example.com",

          # is a xsd:anyURI
          Type => "http://example.com", }, ],

      # is a xsd:ID
      Id => "id_0", },

    # is a ds:SignatureValueType
    # ds_SignatureValue is simple value with attributes
    ds_SignatureValue =>
    { # is a xsd:ID
      Id => "id_0",

      # is a xsd:base64Binary
      # string content of the container
      _ => "decoded bytes", },

    # is a ds:KeyInfoType
    # is optional
    ds_KeyInfo =>
    { # choice of ds_KeyName, ds_KeyValue, ds_RetrievalMethod,
      #   ds_X509Data, ds_PGPData, ds_SPKIData, ds_MgmtData, ANY
      # occurs 1 <= # <= unbounded times
      cho_ds_KeyName => 
      [ {
          # is a xsd:string
          ds_KeyName => "example",

          # is a ds:KeyValueType
          ds_KeyValue =>
          { # choice of ds_DSAKeyValue, ds_RSAKeyValue, ANY

            # is a ds:DSAKeyValueType
            ds_DSAKeyValue =>
            { # sequence of sequence, ds_G, ds_Y, ds_J, sequence

              # sequence of ds_P, ds_Q
              # is optional

              # is a xsd:base64Binary
              ds_P => "decoded bytes",

              # is a xsd:base64Binary
              ds_Q => "decoded bytes",

              # is a xsd:base64Binary
              # is optional
              ds_G => "decoded bytes",

              # is a xsd:base64Binary
              ds_Y => "decoded bytes",

              # is a xsd:base64Binary
              # is optional
              ds_J => "decoded bytes",

              # sequence of ds_Seed, ds_PgenCounter
              # is optional

              # is a xsd:base64Binary
              ds_Seed => "decoded bytes",

              # is a xsd:base64Binary
              ds_PgenCounter => "decoded bytes", },

            # is a ds:RSAKeyValueType
            ds_RSAKeyValue =>
            { # sequence of ds_Modulus, ds_Exponent

              # is a xsd:base64Binary
              ds_Modulus => "decoded bytes",

              # is a xsd:base64Binary
              ds_Exponent => "decoded bytes", },

            # any element not in ds:
            ANY => "Anything", },

          # is a ds:RetrievalMethodType
          ds_RetrievalMethod =>
          { # sequence of ds_Transforms

            # is a ds:TransformsType
            # complex structure shown above
            # is optional
            ds_Transforms => [{},],

            # is a xsd:anyURI
            URI => "http://example.com",

            # is a xsd:anyURI
            Type => "http://example.com", },

          # is a ds:X509DataType
          ds_X509Data =>
          { # sequence of choice
            # occurs 1 <= # <= unbounded times
            seq_ds_X509IssuerSerial => 
            [ {
                # choice of ds_X509IssuerSerial, ds_X509SKI,
                #   ds_X509SubjectName, ds_X509Certificate, ds_X509CRL, ANY

                # is a ds:X509IssuerSerialType
                ds_X509IssuerSerial =>
                { # sequence of ds_X509IssuerName, ds_X509SerialNumber

                  # is a xsd:string
                  ds_X509IssuerName => "example",

                  # is a xsd:integer
                  ds_X509SerialNumber => 42, },

                # is a xsd:base64Binary
                ds_X509SKI => "decoded bytes",

                # is a xsd:string
                ds_X509SubjectName => "example",

                # is a xsd:base64Binary
                ds_X509Certificate => "decoded bytes",

                # is a xsd:base64Binary
                ds_X509CRL => "decoded bytes",

                # any element not in ds:
                ANY => "Anything", },
            ], },

          # is a ds:PGPDataType
          ds_PGPData =>
          { # choice of sequence, sequence

            # sequence of ds_PGPKeyID, ds_PGPKeyPacket, ANY

            # is a xsd:base64Binary
            ds_PGPKeyID => "decoded bytes",

            # is a xsd:base64Binary
            # is optional
            ds_PGPKeyPacket => "decoded bytes",

            # any element not in ds:
            # occurs any number of times
            ANY => [ "Anything", ],

            # sequence of ds_PGPKeyPacket, ANY

            # is a xsd:base64Binary
            ds_PGPKeyPacket => "decoded bytes",

            # any element not in ds:
            # occurs any number of times
            ANY => [ "Anything", ], },

          # is a ds:SPKIDataType
          ds_SPKIData =>
          { # sequence of ds_SPKISexp, ANY
            # occurs 1 <= # <= unbounded times
            seq_ds_SPKISexp => 
            [ {
                # is a xsd:base64Binary
                ds_SPKISexp => "decoded bytes",

                # any element not in ds:
                # is optional
                ANY => "Anything", },
            ], },

          # is a xsd:string
          ds_MgmtData => "example",

          # any element not in ds:
          ANY => "Anything", },
      ],

      # is a xsd:ID
      Id => "id_0", },

    # is a ds:ObjectType
    # occurs any number of times
    ds_Object =>
    [ { # sequence of ANY
        # occurs any number of times
        seq_any => 
        [ {
            # any element in any namespace
            ANY => "Anything", },
        ],

        # is a xsd:ID
        Id => "id_0",

        # is a xsd:string
        MimeType => "example",

        # is a xsd:anyURI
        Encoding => "http://example.com", }, ],

    # is a xsd:ID
    Id => "id_0", },

  # is a xsd:ID
  # attribute id is required
  id => "id_0", }
