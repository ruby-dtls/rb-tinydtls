require "tinydtls"
require_relative "./keys.rb"

socket = TinyDTLS::UDPSocket.new
socket.add_key(TEST_IDENTITY, TEST_PSK)
socket.connect("localhost", 2342)

PROMPT = "> ".freeze

print PROMPT
while line = gets
  socket.send(line[0..-1], 0)
  print PROMPT
end
