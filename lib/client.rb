require "faraday"
require "jwt"
require "securerandom"

module MitID
  class Client
    def initialize(openid_configuration_url:, client_id:, client_secret:, private_key:)
      @client_id = client_id
      @client_secret = client_secret
      @private_key = private_key

      fetch_openid_configuration openid_configuration_url
    end

    def create_authorize_url(redirect_uri:)
      request = JWT.encode({ client_id: @client_id,
                             redirect_uri: redirect_uri,
                             response_type: "code",
                             scope: "openid",
                             aud: @aud,
                             iss: @client_id,
                             iat: Time.now.to_i,
                             exp: (Time.now + 15*60).to_i,
                             nbf: Time.now.to_i },
                           @client_secret,
                           "HS256")

      "#{@authorization_endpoint}?client_id=#{@client_id}&request=#{request}"
    end

    def fetch_token_from_code(code:, redirect_uri:)
      client_assertion = JWT.encode({
        jti: SecureRandom.uuid,
        sub: @client_id,
        iat: Time.now.to_i,
        nbf: Time.now.to_i,
        exp: (Time.now + 15*60).to_i,
        iss: @client_id,
        aud: @token_endpoint
      }, @private_key, "RS256")

      connection.post(@token_endpoint,
                      grant_type: "authorization_code",
                      code: code,
                      client_id: @client_id,
                      redirect_uri: redirect_uri,
                      client_assertion: client_assertion,
                      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer").body
    end

    private

      def fetch_openid_configuration(configuration_url)
        response = connection.get(configuration_url)

        @aud = response.body["issuer"]
        @authorization_endpoint = response.body["authorization_endpoint"]
        @token_endpoint = response.body["token_endpoint"]
      end

      def connection
        @connection ||= Faraday.new do |f|
          f.request :url_encoded
          f.response :json
        end
      end
  end
end
