require "tinydtls"

socket = TinyDTLS::UDPSocket.new(Socket::AF_INET6)
socket.bind("::1", 2342)

socket.add_key("foobar")
socket.add_key("foobar", "foobar")

while true
  msg = socket.recvfrom
  puts "Received: #{msg}"

  addr = msg.last
  socket.send(msg.first, 0, addr[2], addr[1])
end
