require "faraday"
require "jwt"
require "securerandom"
require "uri"

module MitID
  class Client
    def initialize(openid_configuration_url:, client_id:, private_key: nil, client_secret: nil)
      raise ArgumentError, "Either private_key or client_secret must be provided" unless private_key || client_secret

      @client_id     = client_id
      @private_key   = private_key
      @client_secret = client_secret

      fetch_openid_configuration openid_configuration_url
    end

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

        connection.post(@token_endpoint,
                        grant_type:            "authorization_code",
                        code:                  code,
                        client_id:             @client_id,
                        redirect_uri:          redirect_uri,
                        client_assertion:      client_assertion,
                        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer").body
      else
        connection.post(@token_endpoint,
                        grant_type:    "authorization_code",
                        code:          code,
                        client_id:     @client_id,
                        client_secret: @client_secret,
                        redirect_uri:  redirect_uri).body
      end
    end

    def userinfo(access_token)
      connection.get(@userinfo_endpoint) { |req| req.headers["Authorization"] = "Bearer #{access_token}" }.body
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
