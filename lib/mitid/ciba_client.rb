require "faraday"
require "json"

module MitID
  class CIBAClient
    # Read more: https://signaturgruppen-a-s.github.io/signaturgruppen-broker-documentation/enterprise/flex-app-ciba.html

    # @param openid_configuration_url [String] URL to the OpenID Connect discovery document
    # @param client_id [String] Client ID issued by Signaturgruppen
    # @param client_secret [String] Client secret issued by Signaturgruppen
    def initialize(openid_configuration_url:, client_id:, client_secret:)
      @client_id     = client_id
      @client_secret = client_secret

      fetch_openid_configuration openid_configuration_url
    end

    # Initiates a CIBA Flex App flow.
    #
    # @param reference_text [String] Message displayed to the end-user in their MitID app
    # @param ip [String] IPv4 or IPv6 address of the end-user
    # @param scope [String] Space-separated OAuth scopes (default: "openid mitid")
    # @param cpr [String] Danish CPR number of the end-user. Either cpr or uuid is required
    # @param uuid [String] MitID UUID of the end-user. Either cpr or uuid is required
    # @param action [String] Action verb shown in the app. One of: LOG_ON, APPROVE, CONFIRM, ACCEPT, SIGN
    # @param reference_id [String] Opaque reference string passed through to the response
    # @param ciba_nonce [String] Opaque nonce value for replay protection
    # @return [Hash] Response body containing auth_req_id, expires_in, and interval
    # @raise [ArgumentError] If neither cpr nor uuid is provided
    # @raise [MitID::BrokerError] If the broker returns an unexpected error
    def initiate(reference_text:, ip:, scope: "openid mitid", cpr: nil, uuid: nil, action: nil, reference_id: nil, ciba_nonce: nil)
      raise ArgumentError, "Either cpr or uuid must be provided" unless cpr || uuid

      login_hint_token = { idp: "mitid", referenceTextBody: reference_text, ip: ip }
      login_hint_token[:cpr]         = cpr          if cpr
      login_hint_token[:uuid]        = uuid         if uuid
      login_hint_token[:action]      = action       if action
      login_hint_token[:referenceId] = reference_id if reference_id
      login_hint_token[:ciba_nonce]  = ciba_nonce   if ciba_nonce

      response = connection.post(@ciba_endpoint,
                                 grant_type:       "urn:openid:params:grant-type:ciba",
                                 scope:            scope,
                                 client_id:        @client_id,
                                 client_secret:    @client_secret,
                                 login_hint_token: JSON.generate(login_hint_token))

      raise BrokerError.new(response.status, response.body) unless response.success?

      response.body
    end

    # Attempts a single token fetch. The caller is responsible for deciding when
    # and how often to retry.
    #
    # @param auth_req_id [String] The auth_req_id returned by initiate
    # @return [Hash] Tokens hash containing id_token and access_token on success
    # @raise [MitID::AuthorizationPending] User hasn't acted yet — retry after interval seconds
    # @raise [MitID::AccessDenied] User rejected the request — do not retry
    # @raise [MitID::SlowDown] Polling too fast — back off before retrying
    # @raise [MitID::InvalidGrant] auth_req_id is invalid or expired — do not retry
    # @raise [MitID::BrokerError] Unexpected error from the broker
    def fetch_tokens(auth_req_id)
      response = connection.post(@token_endpoint,
                                 grant_type:    "urn:openid:params:grant-type:ciba",
                                 auth_req_id:   auth_req_id,
                                 client_id:     @client_id,
                                 client_secret: @client_secret)

      return response.body if response.success?

      case response.body["error"]
      when "authorization_pending" then nil
      when "access_denied"         then raise AccessDenied
      when "slow_down"             then raise SlowDown
      when "invalid_grant"         then raise InvalidGrant
      else                              raise BrokerError.new(response.status, response.body)
      end
    end

    # Cancels a pending CIBA flow.
    #
    # @param auth_req_id [String] The auth_req_id returned by initiate
    # @raise [MitID::BrokerError] If the broker returns an unexpected error
    def cancel(auth_req_id)
      response = connection.delete("#{@ciba_cancel_base}/#{auth_req_id}")

      raise BrokerError.new(response.status, response.body) unless response.success?
    end

    # Fetches user claims for the authenticated end-user.
    #
    # @param access_token [String] Access token returned by fetch_tokens
    # @return [Hash] User claims, e.g. mitid_uuid, mitid.identity_name, da.cpr
    # @raise [MitID::BrokerError] If the broker returns an unexpected error
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
          f.adapter Faraday.default_adapter
        end
      end
  end
end
