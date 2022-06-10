Gem::Specification.new do |s|
  s.name        = "mitid"
  s.version     = "0.1.0"
  s.license     = "MIT"
  s.summary     = "MitID Client"
  s.description = "Client for Danish MitID"
  s.authors     = ["Mads Lundholm <mads@madslundholm.dk>"]
  s.email       = "ml@whitelabels.dk"
  s.files       = ["lib/client.rb"]
  s.homepage    = "https://github.com/whitelabels/mitid"
  s.metadata    = { "source_code_uri" => "https://github.com/whitelabels/mitid" }

  s.add_runtime_dependency "faraday", "~> 2.3.0"
  s.add_runtime_dependency "jwt", "~> 2.4.1"

  s.add_development_dependency "rspec", "~> 3.11.0"
  s.add_development_dependency "webmock", "~> 3.14.0"
end
