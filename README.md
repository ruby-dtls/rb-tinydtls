# tinydtls

Ruby wrapper for [tinydtls][tinydtls homepage].

# Status

This rubygem is far from finished and not stable at all. It currently
also requires an unreleased version of the [tinydtls library][tinydtls
homepage].

# Installing

The gem can easily be installed from [rubygems.org][rubygems] using:

	$ gem install tinydtls

Before the gem can actually be used [tinydtls][tinydtls homepage] needs
to be build from the git repository using the following commands:

	$ git clone https://git.eclipse.org/r/tinydtls/org.eclipse.tinydtls
	$ cd org.eclipse.tinydtls
	$ git checkout develop
	$ autoconf && autoheader && ./configure
	$ make && make install

To verify that the gem actually works as expected run the test suite.
Instructions for doing so are provided in the next section.

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

A simple DTLS client and DTLS echo server are available in `examples/`.

[tinydtls homepage]: https://projects.eclipse.org/projects/iot.tinydtls
[rubygems]: https://rubygems.org/
