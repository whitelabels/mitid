module MitID
  # Base class for all MitID errors.
  Error = Class.new(StandardError)

  # Raised when the broker returns an unexpected HTTP error response.
  class BrokerError < Error
    attr_reader :status, :body

    def initialize(status, body)
      @status = status
      @body   = body
      super("Broker error (HTTP #{status}): #{body}")
    end
  end

  # Raised by fetch_tokens when the user has not yet acted. Retry after interval seconds.
  AuthorizationPending = Class.new(Error)

  # Raised by fetch_tokens when the user explicitly rejected the request.
  AccessDenied = Class.new(Error)

  # Raised by fetch_tokens when polling too frequently. Back off before retrying.
  SlowDown = Class.new(Error)

  # Raised by fetch_tokens when the auth_req_id is invalid or has expired.
  InvalidGrant = Class.new(Error)
end
