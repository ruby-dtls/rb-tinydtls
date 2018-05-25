module TinyDTLS
  # The class Context stores all per-connection information,
  # it is exclusively used in the `TinyDTLS::CONTEXT_MAP`.
  class Context
    # The underlying UDP socket object.
    attr_reader :socket

    # The queue used for communication with the receive thread.
    attr_reader :queue

    # The default key, used when the request didn't contain a hint.
    attr_reader :default_key

    def initialize(socket, queue)
      @socket = socket
      @queue  = queue

      @idmap = Hash.new
      @default_key = nil
    end

    def self.from_ptr(ptr)
      obj = Wrapper::DTLSContextStruct.new(ptr)
      return CONTEXT_MAP[Wrapper::dtls_get_app_data(obj).to_i]
    end

    def add_key(identity, key)
      if identity.nil?
        @default_key = key
      end

      @idmap[identity] = key
    end

    def get_key(identity)
      @idmap[identity]
    end
  end
end
