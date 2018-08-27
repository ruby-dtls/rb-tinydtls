class TestDTLSSocket < TestSocket
  def test_add_client_default
    s = TinyDTLS::UDPSocket.new(TEST_AFAM)
    s.add_client("foobar", "barfoo")

    s.add_client("barfoo", "foobar")
    s.add_client(TEST_ID, TEST_PSK, true)

    teststr = "something"
    s.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_failed_handshake
    s = TinyDTLS::UDPSocket.new(TEST_AFAM)
    s.add_client(TEST_ID + TEST_ID, TEST_PSK)

    assert_raises Errno::ECONNREFUSED do
      s.send("123", 0, TEST_HOST, TEST_SERVER_PORT)
    end
  end

  def test_free_stale_peer
    @client_socket.send("foobar", 0, TEST_HOST, TEST_SERVER_PORT)
    assert_equal 1, get_client_sessions.size

    # We don't really know how long it takes until the thread is
    # actually scheduled so we just add a few seconds for good
    # measure.
    sleep 4 * TEST_TIMEOUT

    assert get_client_sessions.empty?
  end

  def test_close_twice
    # Previously a double-free was performed on #close occassionally
    # causing a segmentation fault, just ensure that this doesn't happen
    # again.

    s = TinyDTLS::UDPSocket.new(TEST_AFAM)
    s.close
    s.close
  end

  private

  def get_client_sessions
    @client_socket.instance_variable_get("@sessions")
      .instance_variable_get("@store")
  end
end
