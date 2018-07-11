module TinyDTLS
  # This class is used to map user identity for pre-shared keys to their
  # actual keys. It provides an implementation of the `get_psk_info`
  # function pointer used in the `dtls_handler_t` struct which is used
  # by tinydtls to retrieve keys and identities.
  #
  # XXX: Currently this function doesn't map IP address to keys/identities.
  class SecurityConfig
    # Implementation of the `get_psk_info` function pointer as used by
    # the `dtls_handler_t` struct.
    #
    # If tinydtls requests a key for a given identity the key is
    # returned if the identity exists. If no identity was specified the
    # #default_key is returned.
    #
    # If tinydtls requests an id the #default_id is always returned.
    #
    # TODO: It would be nice to return an id depending on the
    # `session_t` passad to this callback.
    GetPSKInfo = Proc.new do |ctx, sess, type, desc, dlen, result, rlen|
      secconf = TinyDTLS::Context.from_ptr(ctx).secconf
      if desc.null?
        key = secconf.default_key
      end

      if type == :DTLS_PSK_KEY
        key ||= secconf.get_key(desc.read_string(dlen))
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
        identity = secconf.default_id
        result.put_bytes(0, identity)
        identity.bytesize
      else
        0
      end
    end

    # Create a new instance of this class. A #default_key and a
    # #default_id can be optionally specified. If they are not specified
    # the first key/identity added is used as the default value.
    def initialize(default_id = nil, default_key = nil)
      @default_id  = default_id
      @default_key = default_key

      @identity_map = Hash.new
    end

    # Adds a security configuration for the given identity.
    def add_client(id, key)
      @identity_map[id] = key
    end

    # Retrieves the key associated with the given identity.
    def get_key(id)
      @identity_map[id]
    end

    def default_id
      if @default_id.nil?
        @identity_map.to_a.first.first
      else
        @default_id
      end
    end

    def default_key
      if @default_key.nil?
        @identity_map.to_a.first.last
      else
        @default_key
      end
    end
  end
end
