require "tinydtls"

socket = TinyDTLS::UDPSocket.new(Socket::AF_INET6)
socket.bind("::1", 2342)

while true
  msg = socket.recvfrom
  puts "Received: #{msg}"
end
