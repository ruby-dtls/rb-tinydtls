module TinyDTLS
  # This class is used to map user identity for pre-shared keys to their
  # actual keys. It provides an implementation of the `get_psk_info`
  # function pointer used in the `dtls_handler_t` struct which is used
  # by tinydtls to retrieve keys and identities.
  #
  # The API of this class is quite strict and raises lots of exceptions
  # because it is quite annoying to debug errors occuring in the
  # GetPSKInfo callback.
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

    # Creates a new instance of this class. At least one key/identity
    # pair need to be added to the new instance of this class using
    # #add_client otherwise the #default_id and #default_key methods
    # always raise an error causing TinyDTLS handshakes to fail.
    def initialize
      @identity_map = Hash.new
    end

    # Adds a security configuration for the given identity, key must be
    # non-null otherwise a TypeError is raise.
    def add_client(id, key)
      if key.nil?
        raise TypeError.new("Key must be non-nil")
      else
        @identity_map[id] = key
      end
    end

    # Retrieves the key associated with the given identity, nil is
    # returned if no key was specified for the given identity.
    def get_key(id)
      if @identity_map.has_key? id
        @identity_map[id]
      end
    end

    # Retrieves the default identity used for establishing new
    # handshakes. If a #default_id hasn't been explicitly set it returns
    # the first identity added using #add_client.
    #
    # At least one identity must have been added to the instance,
    # otherwise this methods raises a TypeError.
    def default_id
      if @identity_map.empty?
        raise TypeError.new("Cannot retrieve a default identity from an empty store")
      end

      if @default_id.nil?
        @identity_map.to_a.first.first
      else
        @default_id
      end
    end

    # Changes the default identity, the given identity must already
    # exist in the store.
    def default_id=(id)
      if @identity_map.has_key? id
        @default_id = id
      else
        raise TypeError.new("Default identity must already exist")
      end
    end

    # Retrieves the default key used when a call to #GetPSKInfo didn't
    # specify a key. If a #default_key hasn't been explicitly set it
    # returns the first key added using #add_client.
    #
    # At least one key must have been added to the instance,
    # otherwise this methods raises a TypeError.
    def default_key
      if @identity_map.empty?
        raise TypeError.new("Cannot retrieve a default key from an empty store")
      end

      if @default_key.nil?
        @identity_map.to_a.first.last
      else
        @default_key
      end
    end

    # Changes the default key, the given key must already exist in the store.
    def default_key=(key)
      if @identity_map.key(key)
        @default_key = key
      else
        raise TypeError.new("Default key must already exist")
      end
    end

    # Sets the #default_id and #default_key, restrictions mentioned in
    # #default_id= and #default_key= apply.
    def set_defaults(id, key)
      default_id = id
      default_key = key
    end
  end
end
