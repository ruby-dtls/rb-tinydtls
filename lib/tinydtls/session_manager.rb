module TinyDTLS
  class SessionManager
    # Default timeout for the cleanup thread in seconds.
    DEFAULT_TIMEOUT = (5 * 60).freeze

    attr_accessor :timeout

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

    def destroy!
      @mutex.lock
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
        while true
          # XXX: How does concurrent access to variables work in ruby?
          # as known as: Is this a concurrency problems since the value
          # of @timeout might be changed by a different thread since an
          # attr_accessor for it is declared.
          sleep @timeout

          @mutex.lock
          @store.transform_values! do |value|
            sess, used = value
            if used
              [sess, !used]
            else # Not used since we've been here last time → free resources
              sess.destroy!(ctx)
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
