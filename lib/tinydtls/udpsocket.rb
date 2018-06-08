module TinyDTLS
  class UDPSocket < ::UDPSocket
    # Character encoding used for strings.
    ENCODING = "UTF-8".freeze

    # Default timeout for the cleanup thread in seconds.
    DEFAULT_TIMEOUT = (5 * 60).freeze

    Write = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, _ = Wrapper::dtls_session_addr(sess, portptr)
      portstr = portptr[:value].to_s

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.sendfn.call(buf.read_string(len),
                         Socket::MSG_DONTWAIT,
                         addrstr, portstr)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, _ = Wrapper::dtls_session_addr(sess, portptr)

      addrinfo = Socket.getaddrinfo(addrstr, nil).first
      addr = [addrinfo[0], portptr[:value].to_i,
              addrinfo[2], addrinfo[3]]

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.queue.push([buf.read_string(len)
        .force_encoding(ENCODING), addr])

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
      return [Util::byteslice(ary.first, len), ary.last]
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

      pay = Util::byteslice(ary.first, len)
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
      sess = get_session(addr)

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
      @sess_mutex.lock
      key = addr.getnameinfo
      if @sess_hash.has_key? key
        sess, _ = @sess_hash[key]
      else
        sess = Wrapper::dtls_new_session(
          addr.afamily, addr.ip_port, addr.ip_address)
        @sess_hash[key] = [sess, true]
      end
      @sess_mutex.unlock

      return sess
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

          # TODO: Is the session memory freed properly?
          sess = Wrapper::dtls_new_session(@family, addr[1], addr[3])
          # TODO: Interact with the @sess_hash

          @sess_mutex.lock
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
                raise RuntimeError, "Peer wasn't found"
              end

              Wrapper::dtls_reset_peer(@ctx, peer)

              # We actually want to delete the element from the map now,
              # however, that doesn't seem to be possible. Instead assign
              # nil to it and filter the map again using #reject! later on.
              nil
            end
          end

          @sess_hash.reject! { |_, v| v.nil? }
          @sess_mutex.unlock
        end
      end
    end

  end
end
