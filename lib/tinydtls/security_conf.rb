module TinyDTLS
  class SecurityConfig
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

    def initialize(default_id = nil, default_key = nil)
      @default_id  = default_id
      @default_key = default_key

      @identity_map = Hash.new
    end

    def add_client(id, key)
      @identity_map[id] = key
    end

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
