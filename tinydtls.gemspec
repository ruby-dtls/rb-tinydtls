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

  spec.required_ruby_version = ">= 2.2.0"

  spec.add_runtime_dependency "ffi", "~> 1.9"
  spec.add_development_dependency "minitest", "~> 5.11"
end
