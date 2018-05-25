require "tinydtls"

socket = TinyDTLS::UDPSocket.new(Socket::AF_INET6)
socket.bind("::1", 2342)

socket.add_key("foobar")
socket.add_key("foobar", "foobar")

while true
  msg = socket.recvfrom
  puts "Received: #{msg}"
end
