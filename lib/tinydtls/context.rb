module TinyDTLS
  # The class Context stores all per-connection information,
  # it is exclusively used in the `TinyDTLS::CONTEXT_MAP`.
  class Context
    # The underlying UDP socket object.
    attr_reader :socket

    # The queue used for communication with the receive thread.
    attr_reader :queue

    def initialize(socket, queue)
      @socket = socket
      @queue  = queue
    end

    def self.from_ptr(ptr)
      obj = Wrapper::DTLSContextStruct.new(ptr)
      return CONTEXT_MAP[Wrapper::dtls_get_app_data(obj).to_i]
    end
  end
end
