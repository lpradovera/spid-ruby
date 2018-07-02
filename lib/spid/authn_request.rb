# frozen_string_literal: true

require "onelogin/ruby-saml/authrequest"
require "spid/onelogin_extension"
require "onelogin/ruby-saml/settings"

module Spid
  class AuthnRequest # :nodoc:
    using OneLoginExtension

    attr_reader :authn_request_attributes

    # rubocop:disable Metrics/MethodLength
    def initialize(
          idp_sso_target_url:,
          assertion_consumer_service_url:,
          issuer:,
          authn_context: Spid::L1
        )

      unless AUTHN_CONTEXTS.include?(authn_context)
        raise Spid::UnknownAuthnContextError,
              "Provided authn_context is not valid:" \
              " use one of #{AUTHN_CONTEXTS.join(', ')}"
      end

      @authn_request_attributes = {
        idp_sso_target_url: idp_sso_target_url,
        assertion_consumer_service_url: assertion_consumer_service_url,
        protocol_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        issuer: issuer,
        name_identifier_format: name_identifier_format,
        authn_context: authn_context
      }
    end
    # rubocop:enable Metrics/MethodLength

    def to_xml
      authn_request.create_xml_document(saml_settings)
    end

    private

    def name_identifier_format
      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    end

    def authn_request
      ::OneLogin::RubySaml::Authrequest.new
    end

    def saml_settings
      ::OneLogin::RubySaml::Settings.new authn_request_attributes
    end
  end
end
