module TinyDTLS
  # This class is used to manage established tinydtls sessions. It
  # stores instances of the TinyDTLS::Session class.
  #
  # While memory allocated for sessions is automatically freed by
  # tinydtls, if it receive an alert from the peer associated with that
  # session, memory isn't freed if the peer doesn't send an alert.
  # Therefore this class starts a background thread automatically
  # freeing memory associated with sessions which haven't been used
  # since a specified duration.
  class SessionManager
    # Default timeout for the cleanup thread in seconds.
    DEFAULT_TIMEOUT = (5 * 60).freeze

    # Timeout used by the cleanup thread. If a session hasn't been used
    # within `timeout * 2` seconds it will be freed automatically.
    attr_reader :timeout

    # Creates a new instance of this class. A tinydtls `context_t`
    # pointer is required to free sessions in the background thread.
    def initialize(ctx, timeout = DEFAULT_TIMEOUT)
      @store = {}
      @mutex = Mutex.new
      @timeout = timeout

      start_thread(ctx)
    end

    # Retrieve a session from the session manager.
    def [](addrinfo, &f)
      unless addrinfo.is_a? Addrinfo
        raise TypeError
      end

      key = addrinfo.getnameinfo
      if @store.has_key? key
        sess, _ = @store[key]
      else
        sess = Session.new(addrinfo)
        @store[key] = [sess, true]
      end

      @mutex.synchronize { f.call(sess) }
    end

    # Frees all ressources associated with this class.
    def destroy!
      @mutex.lock
      @store.clear
      @thread.kill
    end

    private

    # Creates a thread responsible for freeing ressources assigned to
    # stale connection. This thread implements the clock hand algorithm
    # as described in Modern Operating Systems, p. 212.
    #
    # The thread is only created once.
    def start_thread(ctx)
      @thread ||= Thread.new do
        loop do
          sleep @timeout

          @mutex.lock
          @store.transform_values! do |value|
            sess, used = value
            if used
              [sess, !used]
            else # Not used since we've been here last time → free resources
              sess.close(ctx)
              nil
            end
          end

          # We can't delete elements from the map in the #transform_values!
          # block, we just assign nil to them. Thus we need to filter
          # the map again here.
          @store.reject! { |_, v| v.nil? }

          @mutex.unlock
        end
      end
    end
  end
end
