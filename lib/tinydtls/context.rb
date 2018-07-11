module TinyDTLS
  # The class Context stores all per-connection information,
  # it is exclusively used in the `TinyDTLS::CONTEXT_MAP`.
  class Context
    # The method used for sending data on the socket.
    attr_reader :sendfn

    # The queue used for communication with the receive thread.
    attr_reader :queue

    # An instance of the security configuration class.
    attr_reader :secconf

    # Create a new instance of this class with a given function to send
    # message on the transport layer, a queue for storing received
    # messages and a security configuration containing a key to identity
    # mapping.
    def initialize(sendfn, queue, secconf)
      @sendfn  = sendfn
      @queue   = queue
      @secconf = secconf
    end

    # Create a new instance of this class from a pointer to a `struct
    # dtls_context_t`. Such a pointer is, for instance, passed to the
    # various tinydtls callback functions.
    #
    # The `struct dtls_context_t` which the given pointer points to must
    # have been created by TinyDTLS::UDPSocket#initialize.
    def self.from_ptr(ptr)
      obj = Wrapper::DTLSContextStruct.new(ptr)
      return CONTEXT_MAP[Wrapper::dtls_get_app_data(obj).to_i]
    end
  end
end
