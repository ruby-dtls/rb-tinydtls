class TestSessionManager < Utility
  TEST_TIMEOUT = 5.freeze

  def setup
    super

    ctx = TinyDTLS::Context.new(nil, nil, nil)
    @sessions = TinyDTLS::SessionManager.new(ctx, TEST_TIMEOUT)
  end

  def test_add_and_check_used
    addrinfo = Addrinfo.getaddrinfo("www.kame.net", 80).first
    @sessions[addrinfo] do |sess|
      assert_equal addrinfo, sess.addrinfo
    end

    sessions = get_session_store
    assert_equal 1, sessions.size
    assert_used sessions.values.first
  end

  def test_marked_as_unused
    addrinfo = Addrinfo.getaddrinfo("www.google.com", 80).first
    @sessions[addrinfo] { |s| nil }

    assert_used get_session_store.values.first
    sleep TEST_TIMEOUT
    assert_unused get_session_store.values.first
  end

  def test_free_unused
    addrinfo = Addrinfo.getaddrinfo("www.ruby-lang.org", 443).first
    @sessions[addrinfo] { |s| nil }

    sleep TEST_TIMEOUT * 2
    assert get_session_store.empty?
  end

  private

  def get_session_store
    @sessions.instance_variable_get("@store")
  end
end
