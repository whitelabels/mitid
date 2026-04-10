require "faraday"
require "json"

module MitID
  class CIBAClient
    # Read more: https://signaturgruppen-a-s.github.io/signaturgruppen-broker-documentation/enterprise/flex-app-ciba.html

    def initialize(openid_configuration_url:, client_id:, client_secret:)
      @client_id     = client_id
      @client_secret = client_secret

      fetch_openid_configuration openid_configuration_url
    end

    # Initiates a CIBA Flex App flow. Returns the full response body, which includes
    # auth_req_id, expires_in, and interval.
    #
    # Either cpr or uuid is required to identify the end-user.
    # reference_text is displayed to the user in their MitID app.
    # ip is the IPv4 or IPv6 address of the end-user.
    def initiate(reference_text:, ip:, scope: "openid mitid", cpr: nil, uuid: nil, action: nil, reference_id: nil, ciba_nonce: nil)
      raise ArgumentError, "Either cpr or uuid must be provided" unless cpr || uuid

      login_hint_token = { idp: "mitid", referenceTextBody: reference_text, ip: ip }
      login_hint_token[:cpr]         = cpr          if cpr
      login_hint_token[:uuid]        = uuid         if uuid
      login_hint_token[:action]      = action       if action
      login_hint_token[:referenceId] = reference_id if reference_id
      login_hint_token[:ciba_nonce]  = ciba_nonce   if ciba_nonce

      connection.post(@ciba_endpoint,
                      grant_type:       "urn:openid:params:grant-type:ciba",
                      scope:            scope,
                      client_id:        @client_id,
                      client_secret:    @client_secret,
                      login_hint_token: JSON.generate(login_hint_token)).body
    end

    # Attempts a single token fetch. Returns the response body, which is either:
    # - tokens hash on success
    # - { "error" => "authorization_pending" } if the user hasn't acted yet
    # - { "error" => "access_denied" } or other error if the flow failed
    #
    # The caller is responsible for deciding when and how often to retry.
    def fetch_tokens(auth_req_id)
      connection.post(@token_endpoint,
                      grant_type:    "urn:openid:params:grant-type:ciba",
                      auth_req_id:   auth_req_id,
                      client_id:     @client_id,
                      client_secret: @client_secret).body
    end

    # Cancels a pending CIBA flow.
    def cancel(auth_req_id)
      connection.delete("#{@ciba_cancel_base}/#{auth_req_id}").body
    end

    def userinfo(access_token)
      connection.get(@userinfo_endpoint) { |req| req.headers["Authorization"] = "Bearer #{access_token}" }.body
    end

    private

      def fetch_openid_configuration(configuration_url)
        response = connection.get(configuration_url)

        issuer                = response.body["issuer"]
        @ciba_endpoint        = response.body["backchannel_authentication_endpoint"]
        @token_endpoint       = response.body["token_endpoint"]
        @userinfo_endpoint    = response.body["userinfo_endpoint"]
        @ciba_cancel_base     = "#{issuer}/api/v1/ciba"
      end

      def connection
        @connection ||= Faraday.new do |f|
          f.request :url_encoded
          f.response :json
        end
      end
  end
end
