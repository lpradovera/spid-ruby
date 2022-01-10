# frozen_string_literal: true

require "xmldsig"

module Spid
  module Saml2
    # rubocop:disable Metrics/ClassLength
    class SPMetadata # :nodoc:
      attr_reader :document
      attr_reader :settings

      def initialize(settings:)
        @document = REXML::Document.new
        @settings = settings
      end

      def unsigned_document
        document.add_element(entity_descriptor)
        document.to_s
      end

      def signed_document
        doc = Xmldsig::SignedDocument.new(unsigned_document)
        doc.sign(settings.private_key)
      end

      def to_saml
        signed_document
      end

      def entity_descriptor
        @entity_descriptor ||=
          begin
            element = REXML::Element.new("md:EntityDescriptor")
            element.add_attributes(entity_descriptor_attributes)
            element.add_element sp_sso_descriptor
            element.add_element signature
            element.add_element organization
            element.add_element contact_person
            element.add_element billing_contact
            element
          end
      end

      def entity_descriptor_attributes
        @entity_descriptor_attributes ||= {
          "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#",
          "xmlns:md" => "urn:oasis:names:tc:SAML:2.0:metadata",
          "xmlns:spid" => "https://spid.gov.it/saml-extensions",
          "entityID" => settings.sp_entity_id,
          "ID" => entity_descriptor_id
        }
      end

      # rubocop:disable Metrics/MethodLength
      # rubocop:disable Metrics/AbcSize
      def sp_sso_descriptor
        @sp_sso_descriptor ||=
          begin
            element = REXML::Element.new("md:SPSSODescriptor")
            element.add_attributes(sp_sso_descriptor_attributes)
            element.add_element key_descriptor
            element.add_element ac_service
            element.add_element slo_service
            settings.sp_attribute_services.each.with_index do |service, index|
              name = service[:name]
              fields = service[:fields]
              element.add_element attribute_consuming_service(
                index, name, fields
              )
            end
            element
          end
      end
      # rubocop:enable Metrics/AbcSize
      # rubocop:enable Metrics/MethodLength

      def signature
        @signature ||= ::Spid::Saml2::XmlSignature.new(
          settings: settings,
          sign_reference: entity_descriptor_id
        ).signature
      end

      def attribute_consuming_service(index, name, fields)
        element = REXML::Element.new("md:AttributeConsumingService")
        element.add_attributes("index" => index)
        element.add_element service_name(name)
        fields.each do |field|
          element.add_element requested_attribute(field)
        end
        element
      end

      def service_name(name)
        element = REXML::Element.new("md:ServiceName")
        element.add_attributes("xml:lang" => "it")
        element.text = name
        element
      end

      def requested_attribute(name)
        element = REXML::Element.new("md:RequestedAttribute")
        element.add_attributes("Name" => ATTRIBUTES_MAP[name])
        element
      end

      def organization
        element = REXML::Element.new("md:Organization")

        orgname = REXML::Element.new("md:OrganizationName")
        orgname.add_attributes("xml:lang" => "it")
        orgname.text = 'Organization Name' # TODO: get this from config
        element.add_element orgname

        orgdisplay = REXML::Element.new("md:OrganizationDisplayName")
        orgdisplay.add_attributes("xml:lang" => "it")
        orgdisplay.text = 'Organization Name' # TODO: get this from config
        element.add_element orgdisplay

        orgurl = REXML::Element.new("md:OrganizationURL")
        orgurl.add_attributes("xml:lang" => "it")
        orgurl.text = 'https://lucasmbp.ngrok.io' # TODO: get this from config
        element.add_element orgurl

        element
      end

      def contact_person
        element = REXML::Element.new("md:ContactPerson")
        element.add_attributes("contactType" => "other")

        extension = REXML::Element.new("md:Extensions")
        vat = REXML::Element.new("spid:VATNumber")
        vat.text = "IT12345678901" # TODO: get this from config
        extension.add_element vat
        private_tag = REXML::Element.new("spid:Private")
        extension.add_element private_tag
        element.add_element extension

        email = REXML::Element.new("md:EmailAddress")
        email.text = "info@example.org" # TODO: get this from config
        element.add_element email

        element
      end

      def billing_contact
        REXML::Element.new("md:ContactPerson").tap do |element|
          element.add_attributes("contactType" => "billing")
          element.add_element REXML::Element.new("md:Extensions").tap { |ext|
            ext.add_attributes("xmlns:fpa" => "https://spid.gov.it/invoicing-extensions")
            ext.add_element REXML::Element.new("fpa:CessionarioCommittente").tap { |cc|
              cc.add_element REXML::Element.new("fpa:DatiAnagrafici").tap { |anag|
                anag.add_element REXML::Element.new("fpa:IdFiscaleIVA").tap { |idfisc|
                  idfisc.add_element REXML::Element.new("fpa:IdPaese").tap { |idpaese|
                    idpaese.text = "IT"
                  }
                  idfisc.add_element REXML::Element.new("fpa:IdCodice").tap { |idcodice|
                    idcodice.text = "01234567891"
                  }
                }

                anag.add_element REXML::Element.new("fpa:Anagrafica").tap { |an|
                  an.add_element REXML::Element.new("fpa:Denominazione").tap { |den|
                    den.text = "Destinatario_Billing"
                  }
                }
              }
            }
          }
        end
      end

      def sp_sso_descriptor_attributes
        @sp_sso_descriptor_attributes ||= {
          "protocolSupportEnumeration" =>
            "urn:oasis:names:tc:SAML:2.0:protocol",
          "AuthnRequestsSigned" => true
        }
      end

      def ac_service
        @ac_service ||=
          begin
            element = REXML::Element.new("md:AssertionConsumerService")
            element.add_attributes(ac_service_attributes)
            element
          end
      end

      def ac_service_attributes
        @ac_service_attributes ||= {
          "Binding" => settings.sp_acs_binding,
          "Location" => settings.sp_acs_url,
          "index" => 0,
          "isDefault" => true
        }
      end

      def slo_service
        @slo_service ||=
          begin
            element = REXML::Element.new("md:SingleLogoutService")
            element.add_attributes(
              "Binding" => settings.sp_slo_service_binding,
              "Location" => settings.sp_slo_service_url
            )
            element
          end
      end

      def key_descriptor
        @key_descriptor ||=
          begin
            kd = REXML::Element.new("md:KeyDescriptor")
            kd.add_attributes("use" => "signing")
            ki = kd.add_element "ds:KeyInfo"
            data = ki.add_element "ds:X509Data"
            certificate = data.add_element "ds:X509Certificate"
            certificate.text = settings.x509_certificate_der
            kd
          end
      end

      private

      def entity_descriptor_id
        @entity_descriptor_id ||=
          begin
            "_#{Digest::MD5.hexdigest(settings.sp_entity_id)}"
          end
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
