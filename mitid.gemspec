Gem::Specification.new do |s|
  s.name        = "mitid"
  s.version     = "0.3.2"
  s.license     = "MIT"
  s.summary     = "MitID Client"
  s.description = "Client for Danish MitID"
  s.authors     = ["Mads Lundholm <mads@madslundholm.dk>", "Mikkel Raakjær Stidsen <mikkel@raakjaer.dk>"]
  s.email       = "ml@whitelabels.dk"
  s.files       = ["lib/client.rb"]
  s.homepage    = "https://github.com/whitelabels/mitid"
  s.metadata    = { "source_code_uri" => "https://github.com/whitelabels/mitid" }

  s.add_runtime_dependency "faraday", ">= 0.15.4", "< 3"
  s.add_runtime_dependency "jwt", ">= 2.1.0", "< 4"

  s.add_development_dependency "rspec", "~> 3.11.0"
  s.add_development_dependency "webmock", "~> 3.14.0"
  s.add_development_dependency "irb"
end
