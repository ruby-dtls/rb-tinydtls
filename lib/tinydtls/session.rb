module TinyDTLS
  # This class offers a higher-level abstraction for the `session_t` type.
  class Session
    attr_reader :addrinfo

    # Creates a new instance of this class from a given Addrinfo
    # instance. This functions allocates memory for the underlying
    # `session_t` type which needs to be freed explicitly freed using
    # #close.
    def initialize(addrinfo)
      @addrinfo = addrinfo
      unless @addrinfo.is_a? Addrinfo
        raise TypeError.new("Expected Addrinfo or FFI::Pointer")
      end

      sockaddr = @addrinfo.to_sockaddr
      @session = Wrapper::dtls_new_session(sockaddr, sockaddr.bytesize)
      if @session.null?
        raise Errno::ENOMEM
      end
    end

    # Extracts an Addrinfo instance of a FFI::Pointer to a `session_t`
    # as returned by #to_ptr.
    def self.addr_from_ptr(ptr)
      lenptr = Wrapper::SocklenPtr.new
      sockaddr = Wrapper::dtls_session_addr(ptr, lenptr)

      Addrinfo.new(sockaddr.read_string(lenptr[:value]))
    end

    # Converts the object into a C pointer to a `session_t` tinydtls
    # type. This pointer can be passed to various functions provided by
    # TinyDTLS::Wrapper.
    def to_ptr
      @session
    end

    # Frees all resources associated with the underlying `session_t`.
    # Optionally it also resets all peer connections associated with the
    # session (if any). In order to do so a TinyDTLS::Context needs to
    # be passed.
    def close(ctx = nil)
      unless ctx.nil?
        peer = Wrapper::dtls_get_peer(ctx.to_ffi, @session)
        Wrapper::dtls_reset_peer(ctx.to_ffi, peer) unless peer.null?
      end

      Wrapper::dtls_free_session(@session)
      @session = nil
    end
  end
end
