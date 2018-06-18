module TinyDTLS
  class UDPSocket < ::UDPSocket
    # Character encoding used for strings.
    ENCODING = "UTF-8".freeze

    # Default timeout for the cleanup thread in seconds.
    DEFAULT_TIMEOUT = (5 * 60).freeze

    Write = Proc.new do |ctx, sess, buf, len|
      lenptr = Wrapper::SocklenPtr.new
      sockaddr = Wrapper::dtls_session_addr(sess, lenptr)
      port, addr = Socket.unpack_sockaddr_in(
        sockaddr.read_string(lenptr[:value]))

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.sendfn.call(buf.read_string(len),
                         Socket::MSG_DONTWAIT,
                         addr, port)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      lenptr = Wrapper::SocklenPtr.new
      sockaddr = Wrapper::dtls_session_addr(sess, lenptr)
      port, addr = Socket.unpack_sockaddr_in(
        sockaddr.read_string(lenptr[:value]))

      # We need to perform a reverse lookup here because
      # the #recvfrom function needs to return the DNS
      # hostname which we cannot extract from the sockaddr.
      addrinfo = Socket.getaddrinfo(addr, port,
                                    nil, :DGRAM,
                                    0, 0, true).first

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.queue.push([buf.read_string(len)
        .force_encoding(ENCODING), addrinfo])

      # It is unclear to me why this callback even needs a return value,
      # the `tests/dtls-client.c` program in the tinydtls repository
      # simply uses 0 as a return value, so let's do that as well.
      0
    end

    GetPSKInfo = Proc.new do |ctx, sess, type, desc, dlen, result, rlen|
      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      if desc.null?
        key = ctxobj.default_key
      end

      if type == :DTLS_PSK_KEY
        key ||= ctxobj.get_key(desc.read_string(dlen))
        if key.nil?
          Wrapper::dtls_alert_fatal_create(
            Wrapper::Alert[:DTLS_ALERT_DECRYPT_ERROR])
        elsif key.bytesize > rlen
          Wrapper::dtls_alert_fatal_create(
            Wrapper::Alert[:DTLS_ALERT_INTERNAL_ERROR])
        else
          result.put_bytes(0, key)
          key.bytesize
        end
      elsif type == :DTLS_PSK_IDENTITY
        identity = ctxobj.default_id
        result.put_bytes(0, identity)
        identity.bytesize
      else
        0
      end
    end

    def initialize(address_family = Socket::AF_INET, timeout = DEFAULT_TIMEOUT)
      super(address_family)
      Wrapper::dtls_init

      @timeout = timeout.freeze
      @queue   = Queue.new
      @family  = address_family
      @sendfn  = method(:send).super_method

      @sess_hash  = Hash.new
      @sess_mutex = Mutex.new

      id = object_id
      CONTEXT_MAP[id] = TinyDTLS::Context.new(@sendfn, @queue)

      cptr = Wrapper::dtls_new_context(FFI::Pointer.new(id))
      @ctx = Wrapper::DTLSContextStruct.new(cptr)

      @handler = Wrapper::DTLSHandlerStruct.new
      @handler[:write] = UDPSocket::Write
      @handler[:read] = UDPSocket::Read
      @handler[:get_psk_info] = UDPSocket::GetPSKInfo
      Wrapper::dtls_set_handler(@ctx, @handler)
    end

    def default_id
      CONTEXT_MAP[object_id].default_id
    end

    def default_id=(identity)
      CONTEXT_MAP[object_id].default_id = identity
    end

    def add_key(key, identity = nil)
      CONTEXT_MAP[object_id].add_key(identity, key)
    end

    def bind(host, port)
      super(host, port)
      start_threads
    end

    # TODO: close_{read,write}

    def close
      @dtls_thread.kill unless @dtls_thread.nil?
      @cleanup_thread.kill unless @cleanup_thread.nil?

      # DTLS free context sends messages to peers so we need to
      # call it before we actually close the underlying socket.
      Wrapper::dtls_free_context(@ctx)
      super

      # Assuming the thread is already stopped at this point
      # we can safely access the CONTEXT_MAP without running
      # into any kind of concurrency problems.
      CONTEXT_MAP.delete(object_id)
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

    def send(mesg, flags, host = nil, port = nil)
      if host.nil? and port.nil?
        if @defport.nil? or @defhost.nil?
          raise Errno::EDESTADDRREQ
        end

        host = @defhost
        port = @defport
      elsif port.nil? # host is not nil and must be a sockaddr_to
        port, host = Socket.unpack_sockaddr_in(host)
      end

      addr = Addrinfo.getaddrinfo(host, port, nil, :DGRAM).first

      @sess_mutex.lock
      sess = get_session(addr)
      @sess_mutex.unlock

      start_threads # Start thread, if it hasn't been started already

      # If a new thread has been started above a new handshake needs to
      # be performed by it. We need to block here until the handshake
      # was completed.
      #
      # The current approach is calling `Wrapper::dtls_write` until it
      # succeeds which is suboptimal because it doesn't take into
      # account that the handshake may fail.
      until (res = Wrapper::dtls_write(@ctx, sess, mesg, mesg.bytesize)) > 0
        if res == -1
          raise Errno::EIO
        end

        sleep 1
      end

      return res
    end

    private

    def get_session(addr)
      key = addr.getnameinfo
      if @sess_hash.has_key? key
        sess, _ = @sess_hash[key]
      else
        sess = Wrapper::dtls_new_session(
          addr.to_sockaddr, addr.to_sockaddr.bytesize)
        if sess.null?
          raise Errno::ENOMEM
        end

        @sess_hash[key] = [sess, true]
      end

      return sess
    end

    def byteslice(str, len)
      return len >= 0 ? str.byteslice(0, len) : str
    end

    def start_threads
      start_dtls_thread
      start_cleanup_thread
    end

    # Creates a thread responsible for reading from reciving messages
    # from the underlying socket and passing them to tinydtls.
    #
    # The thread is only created once.
    def start_dtls_thread
      @dtls_thread ||= Thread.new do
        while true
          data, addr = method(:recvfrom).super_method
            .call(Wrapper::DTLS_MAX_BUF)
          addrinfo = Addrinfo.getaddrinfo(addr[3], addr[1], nil, :DGRAM).first

          @sess_mutex.lock
          sess = get_session(addrinfo)
          Wrapper::dtls_handle_message(@ctx, sess, data, data.bytesize)
          @sess_mutex.unlock
        end
      end
    end

    # Creates a thread responsible for freeing ressources assigned to
    # stale connection. This thread implements the clock hand algorithm
    # as described in Modern Operating Systems, p. 212.
    #
    # The thread is only created once.
    def start_cleanup_thread
      @cleanup_thread ||= Thread.new do
        while true
          sleep @timeout

          @sess_mutex.lock
          @sess_hash.transform_values! do |value|
            sess, used = value
            if used
              [sess, !used]
            else # Not used since we've been here last time → free resources
              peer = Wrapper::dtls_get_peer(@ctx, sess)
              if peer.null?
                # dtls_handle_messages already frees peers for us if
                # it receive an alert message from them. So if we can't
                # find a peer for the session we don't need to free it.
                nil
              else
                Wrapper::dtls_reset_peer(@ctx, peer)
                nil
              end
            end
          end

          # We can't delete elements from the map in the #transform_values!
          # block, we just assign nil to them. Thus we need to filter
          # the map again here.
          @sess_hash.reject! { |_, v| v.nil? }

          @sess_mutex.unlock
        end
      end
    end

  end
end
