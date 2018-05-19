Gem::Specification.new do |spec|
  spec.name          = "tinydtls"
  spec.version       = "0.1.0"
  spec.authors       = ["Sören Tempel"]
  spec.email         = ["tempel@uni-bremen.de"]

  spec.summary       = "It wraps the tinydtls library"
  spec.description   = "tinydtls provides a DTLS implementation"
  spec.homepage      = "https://github.com/ruby-dtls/rb-tinydtls"
  spec.license       = "MIT"

  spec.files         = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "ffi", "~> 1.9"
end
