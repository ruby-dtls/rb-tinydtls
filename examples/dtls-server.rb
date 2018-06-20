require "tinydtls"
require_relative "./keys.rb"

socket = TinyDTLS::UDPSocket.new
socket.add_key(TEST_IDENTITY, TEST_PSK)
socket.bind("localhost", 2342)

while true
  msg = socket.recvfrom
  puts "Received: #{msg}"

  addr = msg.last
  socket.send(msg.first, 0, addr[2], addr[1])
end
