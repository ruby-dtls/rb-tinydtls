module TinyDTLS
  class UDPSocket
    Write = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, addrptr = Wrapper::dtls_session_addr(sess, portptr)
      portstr = portptr[:value].to_s

      ctxobj = Wrapper::DTLSContextStruct.new(ctx)
      socket, _ = CONTEXT_MAP[Wrapper::dtls_get_app_data(ctxobj).to_i]

      socket.send(buf.read_string(len), 0, addrstr, portstr)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      ctxobj = Wrapper::DTLSContextStruct.new(ctx)
      _, queue = CONTEXT_MAP[Wrapper::dtls_get_app_data(ctxobj).to_i]

      str = buf.read_string(len)
      queue.push(str)

      # It is unclear to me why this callback even needs a return value,
      # the `tests/dtls-client.c` program in the tinydtls repository
      # simply uses 0 as a return value, so let's do that as well.
      0
    end

    def initialize(address_family)
      Wrapper::dtls_init

      @queue  = Queue.new
      @family = address_family

      @socket = ::UDPSocket.new(@family)
      socket_id = @socket.object_id
      CONTEXT_MAP[socket_id] = [@socket, @queue]

      cptr = Wrapper::dtls_new_context(
        FFI::Pointer.new(socket_id))
      @ctx = Wrapper::DTLSContextStruct.new(cptr)

      @handler = Wrapper::DTLSHandlerStruct.new
      @handler[:write] = UDPSocket::Write
      @handler[:read]  = UDPSocket::Read
      Wrapper::dtls_set_handler(@ctx, @handler)
    end

    def bind(host, port)
      @socket.bind(host, port)
      @thread = Thread.new do
        while true
          data, addr = @socket.recvfrom(Wrapper::DTLS_MAX_BUF)

          # TODO: Is the session memory freed properly?
          sess = Wrapper::dtls_new_session(@family, addr[1], addr[3])

          Wrapper::dtls_handle_message(@ctx, sess, data, data.bytesize)
        end
      end
    end

    def recvfrom(maxlen = -1)
      msg = @queue.pop
      return maxlen >= 0 ? msg.byteslice(0, maxlen) : msg
    end
  end
end
