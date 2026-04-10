describe MitID::CIBAClient do
  before do
    stub_request(:get, configuration_url).
      to_return(headers: { content_type: "application/json" },
                body:    JSON.generate(issuer:                                remote_host,
                                       backchannel_authentication_endpoint:   ciba_endpoint,
                                       token_endpoint:                        token_endpoint,
                                       userinfo_endpoint:                     userinfo_endpoint))
  end

  let(:remote_host)       { "https://example.com" }
  let(:configuration_url) { "#{remote_host}/.well-known/openid-configuration" }
  let(:ciba_endpoint)     { "#{remote_host}/connect/ciba" }
  let(:ciba_cancel_base)  { "#{remote_host}/api/v1/ciba" }
  let(:token_endpoint)    { "#{remote_host}/connect/token" }
  let(:userinfo_endpoint) { "#{remote_host}/connect/userinfo" }

  let(:client_id)     { SecureRandom.hex }
  let(:client_secret) { SecureRandom.base64 }
  let(:auth_req_id)   { SecureRandom.hex }
  let(:cpr)           { "0101012345" }
  let(:uuid)          { SecureRandom.uuid }
  let(:ip)            { "1.2.3.4" }
  let(:reference_text) { "Please approve the transaction" }

  subject do
    described_class.new(openid_configuration_url: configuration_url,
                        client_id:                client_id,
                        client_secret:            client_secret)
  end

  def login_hint_token_from(request)
    JSON.parse(CGI.parse(request.body)["login_hint_token"].first)
  end

  describe "initiate" do
    it "raises when neither cpr nor uuid is given" do
      expect {
        subject.initiate(reference_text: reference_text, ip: ip)
      }.to raise_error(ArgumentError)
    end

    it "posts to the CIBA endpoint" do
      request = stub_request(:post, ciba_endpoint)

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "sends client credentials, scope and grant_type" do
      request = stub_request(:post, ciba_endpoint).with(body: hash_including(
        client_id:     client_id,
        client_secret: client_secret,
        scope:         "openid mitid",
        grant_type:    "urn:openid:params:grant-type:ciba"
      ))

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "accepts a custom scope" do
      request = stub_request(:post, ciba_endpoint).with(body: hash_including(scope: "openid mitid ssn"))

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr, scope: "openid mitid ssn")

      assert_requested request
    end

    it "sets idp to mitid in login_hint_token" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["idp"] == "mitid" }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "sets referenceTextBody in login_hint_token" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["referenceTextBody"] == reference_text }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "sets ip in login_hint_token" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["ip"] == ip }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "sets cpr in login_hint_token when given" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["cpr"] == cpr }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "sets uuid in login_hint_token when given" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["uuid"] == uuid }

      subject.initiate(reference_text: reference_text, ip: ip, uuid: uuid)

      assert_requested request
    end

    it "sets action in login_hint_token when given" do
      request = stub_request(:post, ciba_endpoint).with { |req| login_hint_token_from(req)["action"] == "APPROVE" }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr, action: "APPROVE")

      assert_requested request
    end

    it "omits action from login_hint_token when not given" do
      request = stub_request(:post, ciba_endpoint).with { |req| !login_hint_token_from(req).key?("action") }

      subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      assert_requested request
    end

    it "returns the response body" do
      stub_request(:post, ciba_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate(auth_req_id: auth_req_id, expires_in: 300, interval: 2))

      response = subject.initiate(reference_text: reference_text, ip: ip, cpr: cpr)

      expect(response["auth_req_id"]).to eq auth_req_id
      expect(response["expires_in"]).to eq 300
      expect(response["interval"]).to eq 2
    end
  end

  describe "fetch_tokens" do
    it "posts to the token endpoint with the auth_req_id and credentials" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(
        grant_type:  "urn:openid:params:grant-type:ciba",
        auth_req_id: auth_req_id,
        client_id:   client_id
      )).to_return(headers: { content_type: "application/json" },
                   body:    JSON.generate(id_token: "tok", access_token: "acc"))

      subject.fetch_tokens(auth_req_id)

      assert_requested request
    end

    it "returns tokens when authentication is complete" do
      stub_request(:post, token_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate(id_token: "id_tok", access_token: "acc_tok"))

      result = subject.fetch_tokens(auth_req_id)

      expect(result["id_token"]).to eq "id_tok"
      expect(result["access_token"]).to eq "acc_tok"
    end

    it "returns authorization_pending without retrying" do
      stub_request(:post, token_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate(error: "authorization_pending"))

      result = subject.fetch_tokens(auth_req_id)

      expect(result["error"]).to eq "authorization_pending"
      expect(WebMock).to have_requested(:post, token_endpoint).once
    end

    it "returns the error response on failure" do
      stub_request(:post, token_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate(error: "access_denied"))

      result = subject.fetch_tokens(auth_req_id)

      expect(result["error"]).to eq "access_denied"
    end
  end

  describe "cancel" do
    it "sends a DELETE to the cancel endpoint with the auth_req_id" do
      request = stub_request(:delete, "#{ciba_cancel_base}/#{auth_req_id}")

      subject.cancel(auth_req_id)

      assert_requested request
    end
  end

  describe "userinfo" do
    it "uses the token as a bearer token" do
      request = stub_request(:get, userinfo_endpoint).
        with(headers: { "Authorization" => "Bearer some_token" })

      subject.userinfo("some_token")

      assert_requested request
    end

    it "returns the userinfo" do
      mitid_uuid = SecureRandom.uuid
      mitid_name = "Hans Hansen"

      stub_request(:get, userinfo_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate("mitid_uuid": mitid_uuid, "mitid.identity_name": mitid_name))

      userinfo = subject.userinfo("some_token")

      expect(userinfo["mitid_uuid"]).to eq mitid_uuid
      expect(userinfo["mitid.identity_name"]).to eq mitid_name
    end
  end
end
