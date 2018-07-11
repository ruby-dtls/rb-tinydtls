module TinyDTLS
  # This class offers a higher-level abstraction for the `session_t` type.
  class Session
    attr_reader :addrinfo

    # Creates a new instance of this class from the given Addrinfo.
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

    # Creates a new instance of this class from a pointer to a
    # `session_t` tinydtls type. Such a pointer is, for instance, passed
    # to the various tinydtls callback functions.
    def self.from_ptr(ptr)
      lenptr = Wrapper::SocklenPtr.new
      sockaddr = Wrapper::dtls_session_addr(ptr, lenptr)

      addrinfo = Addrinfo.new(sockaddr.read_string(lenptr[:value]))
      return Session.new(addrinfo)
    end

    # Converts the object into a C pointer to a `session_t` tinydtls
    # type. This pointer can be passed to various functions provided by
    # TinyDTLS::Wrapper.
    def to_ptr
      @session
    end

    # Frees all resources associated with the underlying `session_t`
    # tinydtls type and reset any existing connections.
    def destroy!(ctx)
      peer = Wrapper::dtls_get_peer(ctx, @session)
      unless peer.null?
        Wrapper::dtls_reset_peer(ctx, peer)
      end
    end
  end
end
