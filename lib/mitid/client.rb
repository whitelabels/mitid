require "faraday"
require "jwt"
require "securerandom"
require "uri"

module MitID
  class Client
    # @param openid_configuration_url [String] URL to the OpenID Connect discovery document
    # @param client_id [String] Client ID issued by Signaturgruppen
    # @param private_key [OpenSSL::PKey::RSA] RSA private key for JWT client assertion auth. Either private_key or client_secret is required
    # @param client_secret [String] Client secret for client_secret_post auth. Either private_key or client_secret is required
    # @raise [ArgumentError] If neither private_key nor client_secret is provided
    def initialize(openid_configuration_url:, client_id:, private_key: nil, client_secret: nil)
      raise ArgumentError, "Either private_key or client_secret must be provided" unless private_key || client_secret

      @client_id     = client_id
      @private_key   = private_key
      @client_secret = client_secret

      fetch_openid_configuration openid_configuration_url
    end

    # Generates the authorization URL to redirect the end-user to.
    #
    # @param redirect_uri [String] URI the broker will redirect to with the authorization code
    # @param scope [String] Space-separated OAuth scopes, e.g. "openid mitid ssn"
    # @param idp_values [String] Identity provider hint, e.g. "mitid" to skip the IDP selection screen
    # @return [String] Authorization URL
    def authorize_url(redirect_uri:, scope:, idp_values: nil)
      if @private_key
        payload = { client_id: @client_id,
                    redirect_uri: redirect_uri,
                    response_type: "code",
                    scope: scope,
                    aud: @aud,
                    iss: @client_id,
                    iat: Time.now.to_i,
                    exp: (Time.now + 15*60).to_i,
                    nbf: Time.now.to_i }
        payload[:idp_values] = idp_values if idp_values

        request = JWT.encode(payload, @private_key, "RS256")

        "#{@authorization_endpoint}?client_id=#{@client_id}&request=#{request}"
      else
        params = { client_id: @client_id, redirect_uri: redirect_uri, response_type: "code", scope: scope }
        params[:idp_values] = idp_values if idp_values
        "#{@authorization_endpoint}?#{URI.encode_www_form(params)}"
      end
    end

    # Exchanges an authorization code for tokens.
    #
    # @param code [String] Authorization code received in the redirect callback
    # @param redirect_uri [String] Must match the redirect_uri used in authorize_url
    # @return [Hash] Tokens hash containing id_token and access_token
    # @raise [MitID::BrokerError] If the broker returns an unexpected error
    def authorize(code:, redirect_uri:)
      if @private_key
        client_assertion = JWT.encode({ jti: SecureRandom.uuid,
                                        sub: @client_id,
                                        iat: Time.now.to_i,
                                        nbf: Time.now.to_i,
                                        exp: (Time.now + 15*60).to_i,
                                        iss: @client_id,
                                        aud: @token_endpoint },
                                      @private_key,
                                      "RS256")

        response = connection.post(@token_endpoint,
                                   grant_type:            "authorization_code",
                                   code:                  code,
                                   client_id:             @client_id,
                                   redirect_uri:          redirect_uri,
                                   client_assertion:      client_assertion,
                                   client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      else
        response = connection.post(@token_endpoint,
                                   grant_type:    "authorization_code",
                                   code:          code,
                                   client_id:     @client_id,
                                   client_secret: @client_secret,
                                   redirect_uri:  redirect_uri)
      end

      raise BrokerError.new(response.status, response.body) unless response.success?

      response.body
    end

    # Fetches user claims for the authenticated end-user.
    #
    # @param access_token [String] Access token returned by authorize
    # @return [Hash] User claims, e.g. mitid_uuid, mitid.identity_name, da.cpr
    # @raise [MitID::BrokerError] If the broker returns an unexpected error
    def userinfo(access_token)
      response = connection.get(@userinfo_endpoint) { |req| req.headers["Authorization"] = "Bearer #{access_token}" }
      raise BrokerError.new(response.status, response.body) unless response.success?

      response.body
    end

    private

      def fetch_openid_configuration(configuration_url)
        response = connection.get(configuration_url)

        @aud                    = response.body["issuer"]
        @authorization_endpoint = response.body["authorization_endpoint"]
        @token_endpoint         = response.body["token_endpoint"]
        @userinfo_endpoint      = response.body["userinfo_endpoint"]
      end

      def connection
        @connection ||= Faraday.new do |f|
          f.request :url_encoded
          f.response :json
        end
      end
  end
end
