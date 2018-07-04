module TinyDTLS
  class Session
    attr_reader :addrinfo

    def initialize(addrinfo)
      @addrinfo = addrinfo
      unless @addrinfo.is_a? Addrinfo
        raise TypeError
      end

      sockaddr = @addrinfo.to_sockaddr
      @session = Wrapper::dtls_new_session(sockaddr, sockaddr.bytesize)
      if @session.null?
        raise Errno::ENOMEM
      end
    end

    def self.from_ptr(ptr)
      lenptr = Wrapper::SocklenPtr.new
      sockaddr = Wrapper::dtls_session_addr(ptr, lenptr)

      addrinfo = Addrinfo.new(sockaddr.read_string(lenptr[:value]))
      return Session.new(addrinfo)
    end

    def to_ptr
      @session
    end

    def destroy!(ctx)
      peer = Wrapper::dtls_get_peer(ctx, @session)
      unless peer.null?
        Wrapper::dtls_reset_peer(ctx, peer)
      end
    end
  end
end
