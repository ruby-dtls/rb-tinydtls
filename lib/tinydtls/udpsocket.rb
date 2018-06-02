module TinyDTLS
  class UDPSocket < ::UDPSocket
    Write = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, _ = Wrapper::dtls_session_addr(sess, portptr)
      portstr = portptr[:value].to_s

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.sendfn.call(buf.read_string(len), 0, addrstr, portstr)
    end

    Read = Proc.new do |ctx, sess, buf, len|
      portptr = Wrapper::Uint16Ptr.new
      addrstr, _ = Wrapper::dtls_session_addr(sess, portptr)

      addrinfo = Socket.getaddrinfo(addrstr, nil).first
      addr = [addrinfo[0], portptr[:value].to_i,
              addrinfo[2], addrinfo[3]]

      ctxobj = TinyDTLS::Context.from_ptr(ctx)
      ctxobj.queue.push([buf.read_string(len), addr])

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
          Wrapper::dtls_alert_fatal_create(:DTLS_ALERT_DECRYPT_ERROR)
        elsif key.bytesize > rlen
          Wrapper::dtls_alert_fatal_create(:DTLS_ALERT_INTERNAL_ERROR)
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

    def initialize(address_family = Socket::AF_INET)
      super(address_family)
      Wrapper::dtls_init

      @queue  = Queue.new
      @family = address_family
      @defdst = nil
      @sendfn = method(:send).super_method

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
      @thread = Thread.new do
        while true
          data, addr = method(:recvfrom).super_method
            .call(Wrapper::DTLS_MAX_BUF)

          # TODO: Is the session memory freed properly?
          sess = Wrapper::dtls_new_session(@family, addr[1], addr[3])

          Wrapper::dtls_handle_message(@ctx, sess, data, data.bytesize)
        end
      end
    end

    # TODO: close_{read,write}

    def close
      @thread.kill
      super

      # Assuming the thread is already stopped and this point
      # we can safely access the CONTEXT_MAP without running
      # into any kind of concurrency problems.
      CONTEXT_MAP.delete(object_id)
    end

    def connect(host, port)
      @defdst = Addrinfo.getaddrinfo(host, port, nil, :DGRAM).first
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

    def send(mesg, flags)
      if @defdst.nil?
        raise Errno::EDESTADDRREQ
      end

      return Util::dtls_send(@ctx, mesg, @defdst)
    end

    def send(mesg, flags, sockaddr_to)
      addr, port = Socket.unpack_sockaddr_in(sockaddr_to)
      return send(mesg, flags, addr, port)
    end

    def send(mesg, flags, host, port)
      return Util::dtls_send(
        @ctx,
        mesg,
        Addrinfo.getaddrinfo(host, port, nil, :DGRAM).first
      )
    end
  end
end
