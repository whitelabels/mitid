require "faraday"
require "jwt"
require "securerandom"

module MitID
  class Client
    def initialize(openid_configuration_url:, client_id:, private_key:)
      @client_id     = client_id
      @private_key   = private_key

      fetch_openid_configuration openid_configuration_url
    end

    def authorize_url(redirect_uri:, scope:)
      request = JWT.encode({ client_id: @client_id,
                             redirect_uri: redirect_uri,
                             response_type: "code",
                             scope: scope,
                             aud: @aud,
                             iss: @client_id,
                             iat: Time.now.to_i,
                             exp: (Time.now + 15*60).to_i,
                             nbf: Time.now.to_i },
                           @private_key,
                           "RS256")

      "#{@authorization_endpoint}?client_id=#{@client_id}&request=#{request}"
    end

    def authorize(code:, redirect_uri:)
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
