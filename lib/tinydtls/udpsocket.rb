module TinyDTLS
  class UDPSocket < UDPSocket
    Write = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, addrptr = Wrapper::dtls_session_addr(sess, portptr)
      portstr = portptr[:value].to_s

      ctxobj = Wrapper::DTLSContextStruct.new(ctx)
      socket = SOCKET_MAP[Wrapper::dtls_get_app_data(ctxobj).to_i]

      socket.send(buf.read_string(len), 0, addrstr, portstr)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      # TODO: store data in queue
      puts "Received new data"
    end

    def initialize(address_family)
      Wrapper::dtls_init
      @family = address_family

      @socket = super(@family)
      socket_id = @socket.object_id
      SOCKET_MAP[socket_id] = @socket

      cptr = Wrapper::dtls_new_context(
        FFI::Pointer.new(socket_id))
      @ctx = Wrapper::DTLSContextStruct.new(cptr)

      @handler = Wrapper::DTLSHandlerStruct.new
      @handler[:write] = UDPSocket::Write
      @handler[:read]  = UDPSocket::Read
      Wrapper::dtls_set_handler(@ctx, @handler)
    end

    def bind(host, port)
      super(host, port)
      @thread = Thread.new do
        data, addr = @socket.recvfrom(Wrapper::DTLS_MAX_BUF)

        # TODO: Is the session memory freed properly?
        sess = Wrapper::dtls_new_session(@family, addr[1], addr[3])

        Wrapper::dtls_handle_message(@ctx, sess, data, data.bytesize)
      end
    end

    def wait
      @thread.join
    end
  end
end
