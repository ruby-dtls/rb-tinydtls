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
    #
    # Memory for sessions created using #[] needs to be explicitly freed
    # by calling #close as soons as this class instance is no longer
    # needed.
    def initialize(context, timeout = DEFAULT_TIMEOUT)
      @store = {}
      @mutex = Mutex.new

      @timeout = timeout
      @context = context

      start_thread
    end

    # Retrieve a session from the session manager.
    def [](addrinfo, &f)
      unless addrinfo.is_a? Addrinfo
        raise TypeError
      end

      key = addrinfo.getnameinfo
      @mutex.synchronize do
        if @store.has_key? key
          sess, _ = @store[key]
        else
          sess = Session.new(addrinfo)
          @store[key] = [sess, true]
        end

        f.call(sess)
      end
    end

    # Kills the background thread. All established sessions are closed
    # as well, see Session#close.
    def close
      @mutex.synchronize do
        @thread.kill
        @thread.join
      end

      @store.each_value do |value|
        sess, _ = value
        sess.close(@context)
      end
    end

    private

    # Creates a thread responsible for freeing ressources assigned to
    # stale connection. This thread implements the clock hand algorithm
    # as described in Modern Operating Systems, p. 212.
    #
    # The thread is only created once.
    def start_thread
      @thread ||= Thread.new do
        loop do
          sleep @timeout

          @mutex.lock
          @store.transform_values! do |value|
            sess, used = value
            if used
              [sess, !used]
            else # Not used since we've been here last time → free resources
              sess.close(@context)
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
