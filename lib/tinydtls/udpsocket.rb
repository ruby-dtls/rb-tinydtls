module TinyDTLS
  # This class implements a DTLS socket on top of a ruby UDPSocket. It
  # isn't currently nowhere near being API compatible with the ruby
  # UDPSocket. Being 100% backwards compatible with the ruby UDPSocket
  # is not possible to to tinydtls internals. For instance we can't
  # properly implement IO#select. It should thus be considered if it is
  # really a good idea to extend the ruby UDPSocket in the long run.
  #
  # Basic send and receive methods are implemented and should work.
  class UDPSocket < ::UDPSocket
    Write = Proc.new do |ctx, sess, buf, len|
      addrinfo = Session.from_ptr(sess).addrinfo

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.sendfn.call(buf.read_string(len),
                         Socket::MSG_DONTWAIT,
                         addrinfo.ip_address, addrinfo.ip_port)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      addrinfo = Session.from_ptr(sess).addrinfo

      # We need to perform a reverse lookup here because
      # the #recvfrom function needs to return the DNS
      # hostname.
      sender = Socket.getaddrinfo(addrinfo.ip_address,
                                  addrinfo.ip_port,
                                  addrinfo.afamily,
                                  :DGRAM, 0, 0, true).first

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.queue.push([buf.read_string(len), sender])

      # It is unclear to me why this callback even needs a return value,
      # the `tests/dtls-client.c` program in the tinydtls repository
      # simply uses 0 as a return value, so let's do that as well.
      0
    end

    def initialize(address_family = Socket::AF_INET, timeout = nil)
      super(address_family)
      Wrapper::dtls_init

      @timeout = timeout.freeze
      @queue   = Queue.new
      @family  = address_family
      @sendfn  = method(:send).super_method
      @secconf = SecurityConfig.new

      @context = TinyDTLS::Context.new(@sendfn, @queue, @secconf)
      CONTEXT_MAP[@context.key] = @context

      if timeout.nil?
        @sessions = SessionManager.new(@context)
      else
        @sessions = SessionManager.new(@context, timeout)
      end

      @handler = Wrapper::DTLSHandlerStruct.new
      @handler[:write] = UDPSocket::Write
      @handler[:read] = UDPSocket::Read
      @handler[:get_psk_info] = SecurityConfig::GetPSKInfo
      Wrapper::dtls_set_handler(@context.to_ffi, @handler)
    end

    def add_client(id, key)
      @secconf.add_client(id, key)
    end

    def bind(host, port)
      super(host, port)
      start_thread
    end

    # TODO: close_{read,write}

    def close
      @sessions.destroy!
      @thread.kill unless @thread.nil?

      # dtls_free_context sends messages to peers so we need to
      # explicitly free the dtls_context_t before closing the socket.
      Wrapper::dtls_free_context(@context.to_ffi)
      super

      # Assuming the @thread is already stopped at this point
      # we can safely access the CONTEXT_MAP without running
      # into any kind of concurrency problems.
      CONTEXT_MAP.delete(@context.key)
    end

    def connect(host, port)
      @defhost = host
      @defport = port
    end

    def recvfrom(len = -1, flags = 0)
      ary = @queue.pop
      return [byteslice(ary.first, len), ary.last]
    end

    def recvfrom_nonblock(len = -1, flag = 0, outbuf = nil, exception: true)
      ary = nil
      begin
        ary = @queue.pop(true)
      rescue ThreadError
        if exception
          raise IO::EAGAINWaitReadable
        else
          return :wait_readable
        end
      end

      pay = byteslice(ary.first, len)
      unless outbuf.nil?
        outbuf << pay
      end

      return [pay, ary.last]
    end

    # TODO: The recvmsg functions only implement a subset of the
    # functionallity of the UDP socket class, e.g. they don't return
    # ancillary data.

    def recvmsg(maxmesglen = nil, flags = 0, maxcontrollen = nil, opts = {})
      mesg, sender = recvfrom(maxmesglen.nil? ? -1 : maxmesglen, flags)
      return [mesg, to_addrinfo(*sender), 0, nil]
    end

    def recvmsg_nonblock(maxdatalen = nil, flags = 0, maxcontrollen = nil, opts = {})
      mesg, sender = recvfrom_nonblock(maxdatalen.nil? ? -1 : maxdatalen, flags)
      return [mesg, to_addrinfo(*sender), 0, nil]
    end

    def send(mesg, flags, host = nil, port = nil)
      start_thread

      if host.nil? and port.nil?
        if @defport.nil? or @defhost.nil?
          raise Errno::EDESTADDRREQ
        end

        host = @defhost
        port = @defport
      elsif port.nil? # host is not nil and must be a sockaddr_to
        port, host = Socket.unpack_sockaddr_in(host)
      end

      addr = Addrinfo.getaddrinfo(host, port, @family, :DGRAM).first

      # If a new thread has been started above a new handshake needs to
      # be performed by it. We need to block here until the handshake
      # was completed.
      #
      # The current approach is calling `Wrapper::dtls_write` until it
      # succeeds which is suboptimal because it doesn't take into
      # account that the handshake may fail.
      until (res = dtls_send(addr, mesg)) > 0
        sleep 1
      end

      return res
    end

    private

    def to_addrinfo(*args)
      af, port, _, addr = args
      Addrinfo.getaddrinfo(addr, port, af, :DGRAM).first
    end

    def byteslice(str, len)
      return len >= 0 ? str.byteslice(0, len) : str
    end

    # Sends a dtls message to a specified address. It also takes care
    # of locking the session manager and is thus thread-safe.
    def dtls_send(addr, mesg)
      @sessions[addr] do |sess|
        res = Wrapper::dtls_write(@context.to_ffi, sess.to_ptr,
                                  mesg, mesg.bytesize)
        res == -1 ? raise(Errno::EIO) : res
      end
    end

    # Creates a thread responsible for reading from reciving messages
    # from the underlying socket and passing them to tinydtls.
    #
    # The thread is only created once.
    def start_thread
      @thread ||= Thread.new do
        loop do
          data, addr = method(:recvfrom).super_method
            .call(Wrapper::DTLS_MAX_BUF)
          addrinfo = to_addrinfo(*addr)

          @sessions[addrinfo] do |sess|
            Wrapper::dtls_handle_message(@context.to_ffi, sess.to_ptr,
                                         data, data.bytesize)
          end
        end
      end
    end
  end
end
