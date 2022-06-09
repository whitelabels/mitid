require "faraday"
require "jwt"

module MitID
  class Client
    def initialize(openid_configuration_url:, client_id:, client_secret:)
      @client_id = client_id
      @client_secret = client_secret

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

    private

      def fetch_openid_configuration(configuration_url)
        connection = Faraday.new do |f|
          f.response :json
        end

        response = connection.get(configuration_url)

        @aud = response.body["issuer"]
        @authorization_endpoint = response.body["authorization_endpoint"]
      end
  end
end
