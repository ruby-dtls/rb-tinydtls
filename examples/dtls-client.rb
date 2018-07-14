require "tinydtls"
require_relative "./keys.rb"

socket = TinyDTLS::UDPSocket.new
socket.add_client(TEST_IDENTITY, TEST_PSK)
socket.connect("localhost", 2342)

PROMPT = "> ".freeze

recvthr = Thread.new do
  loop do
    payload, _ = socket.recvfrom
    puts "Received: #{payload}"
  end
end

print PROMPT
while line = gets
  input = line[0..-2]
  unless input.empty?
    socket.send(input, 0)
  end
  print PROMPT
end
