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

    def initialize(sendfn, queue, secconf)
      @sendfn  = sendfn
      @queue   = queue
      @secconf = secconf
    end

    def self.from_ptr(ptr)
      obj = Wrapper::DTLSContextStruct.new(ptr)
      return CONTEXT_MAP[Wrapper::dtls_get_app_data(obj).to_i]
    end
  end
end
