# tinydtls

Ruby wrapper for [tinydtls][tinydtls homepage].

# Status

This rubygem is far from finished and not stable at all. It also
currently requires a [patched version of tinydtls][tinydtls fork], even
though that will (hopefully) change soon.

# Installing

The gem can easily be installed from [rubygems.org][rubygems] using:

	$ gem install tinydtls

# Tests

A basic test suite is also available which can be run using:

	$ ruby -Ilib:test test/test.rb

# Documentation

The high-level API to interact with tinydtls provided by this gem is the
`TinyDTLS::UDPSocket` class. This class currently extends the standard
ruby UDPSocket class and the `UDPSocket#recvfrom` and `UDPSocket#send`
methods should work as expected.

However, before being able to use the `TinyDTLS::UDPSocket` a pre-shared
key needs to be configured. Thus the code for creating a socket and
receiving a packet from it looks as follows:

```ruby
require "tinydtls"

s = TinyDTLS::UDPSocket.new
s.add_client("client identity", "very secret key")

s.bind("localhost", 1337)
p s.recvfrom(1000)
```

A simple DTLS client and DTLS echo server is available in `examples/`.

[tinydtls homepage]: https://projects.eclipse.org/projects/iot.tinydtls
[tinydtls fork]: https://github.com/ruby-dtls/tinydtls
[rubygems]: https://rubygems.org/
