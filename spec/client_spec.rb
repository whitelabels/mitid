describe MitID::Client do
  before do
    stub_request(:get, configuration_url).
      to_return(headers: { content_type: "application/json" },
                body:     JSON.generate(issuer: remote_host, authorization_endpoint: authorization_endpoint, token_endpoint: token_endpoint, userinfo_endpoint: userinfo_endpoint))
  end

  let(:remote_host) { "https://example.com" }
  let(:configuration_url) { "#{remote_host}/.well-known/openid-configuration" }
  let(:authorization_endpoint) { "#{remote_host}/connect/authorize" }
  let(:token_endpoint) { "#{remote_host}/connect/token" }
  let(:userinfo_endpoint) { "#{remote_host}/connect/userinfo" }

  let(:client_id) { SecureRandom.hex }
  let(:private_key) { OpenSSL::PKey::RSA.generate 2048 }

  subject do
    described_class.new(openid_configuration_url: configuration_url,
                        client_id:                client_id,
                        private_key:              private_key)
  end

  describe "authorize_url" do
    let(:redirect_uri) { "http://localhost:3000/callbacks/mitid" }
    let(:scope) { "openid mitid ssn" }

    it "use the authorization endpoint" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)

      expect(authorize_url).to start_with(authorization_endpoint)
    end

    it "use the client_id in the query" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      expect(query).to include "client_id=#{client_id}"
    end

    it "set the redirect_uri to the given redirect_uri" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["redirect_uri"]).to eq redirect_uri
    end

    it "set the response_type to code" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["response_type"]).to eq "code"
    end

    it "set the scope to the given scope" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["scope"]).to eq scope
    end

    it "set the aud to the issuer of the server" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["aud"]).to eq remote_host
    end

    it "set the iss to our client id" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["iss"]).to eq client_id
    end

    it "set the iat to now" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["iat"]).to be_within(1).of(Time.now.to_i)
    end

    it "set the exp to now plus 15 minutes" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["exp"]).to be_within(1).of((Time.now + 15*60).to_i)
    end

    it "set the nbf to now" do
      authorize_url = subject.authorize_url(redirect_uri: redirect_uri, scope: scope)
      query = URI.parse(authorize_url).query

      jwt = CGI.parse(query)["request"].first
      decoded_request = JWT.decode(jwt, private_key.public_key, true, { algorithm: "RS256" }).first

      expect(decoded_request["nbf"]).to be_within(1).of(Time.now.to_i)
    end
  end

  describe "authorize" do
    let(:code) { SecureRandom.hex }
    let(:redirect_uri) { "http://localhost:3000/callbacks/mitid" }

    it "set the client_id in the request body" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(client_id: client_id))

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "set the grant_type to authorization_code in the request body" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(grant_type: "authorization_code"))

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "set the redirect_uri to the given url in the request body" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(redirect_uri: redirect_uri))

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "set the code to the given code in the request body" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(code: code))

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "set the client_assertion_type in the request body" do
      request = stub_request(:post, token_endpoint).with(body: hash_including(client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "generate a JWT as the client_assertion in the request body" do
      parse_body = lambda do |body|
        parsed_body = CGI.parse(body)
        decoded_client_assertion = JWT.decode(parsed_body["client_assertion"].first, private_key.public_key, true, { algorithm: "RS256" }).first

        expect(decoded_client_assertion["sub"]).to eq client_id
        expect(decoded_client_assertion["iss"]).to eq client_id
        expect(decoded_client_assertion["iat"]).to be_within(1).of(Time.now.to_i)
        expect(decoded_client_assertion["nbf"]).to be_within(1).of(Time.now.to_i)
        expect(decoded_client_assertion["exp"]).to be_within(1).of((Time.now + 15*60).to_i)
        expect(decoded_client_assertion["aud"]).to eq token_endpoint
      end

      request = stub_request(:post, token_endpoint).with(body: parse_body)

      subject.authorize(code: code, redirect_uri: redirect_uri)

      assert_requested request
    end

    it "returns the tokens" do
      id_token = JWT.encode({}, nil)
      access_token = JWT.encode({}, nil)

      stub_request(:post, token_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body: JSON.generate(id_token: id_token, access_token: access_token))

      tokens = subject.authorize(code: code, redirect_uri: redirect_uri)

      expect(tokens["id_token"]).to eq id_token
      expect(tokens["access_token"]).to eq access_token
    end
  end

  describe "userinfo" do
    it "uses the token as a bearer token" do
      access_token = JWT.encode({}, nil)

      request = stub_request(:get, userinfo_endpoint).
        with(headers: { "Authorization": "Bearer #{access_token}"})

      subject.userinfo(access_token)

      assert_requested request
    end

    it "returns the userinfo" do
      mitid_uuid = SecureRandom.uuid
      mitid_age = 35
      mitid_date_of_birth = "1985-03-29"
      mitid_cpr = "290385-1234"
      mitid_name = "Hans Hansen"

      stub_request(:get, userinfo_endpoint).
        to_return(headers: { content_type: "application/json" },
                  body:    JSON.generate("mitid_uuid": mitid_uuid, "mitid.age": mitid_age, "mitid.date_of_birth": mitid_date_of_birth, "da.cpr" => mitid_cpr, "mitid.identity_name": mitid_name))

      userinfo = subject.userinfo(JWT.encode({}, nil))

      expect(userinfo["mitid_uuid"]).to eq mitid_uuid
      expect(userinfo["mitid.age"]).to eq mitid_age
      expect(userinfo["mitid.date_of_birth"]).to eq mitid_date_of_birth
      expect(userinfo["da.cpr"]).to eq mitid_cpr
      expect(userinfo["mitid.identity_name"]).to eq mitid_name
    end
  end
end
