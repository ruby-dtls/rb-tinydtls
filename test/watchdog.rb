class TestWatchdog < Utility
  # Reduce the watchdog timeout.
  TEST_TIMEOUT = 5

  def setup
    @server_socket = TinyDTLS::UDPSocket.new(TEST_AFAM)
    @server_socket.bind(TEST_HOST, TEST_SERVER_PORT)
    @server_socket.add_key(TEST_PSK, TEST_ID)

    @client_socket = TinyDTLS::UDPSocket.new(TEST_AFAM, TEST_TIMEOUT)
    @client_socket.add_key(TEST_PSK, TEST_ID)
  end

  def teardown
    @server_socket.close
    @client_socket.close
  end

  def test_free_stale_peer
    @client_socket.send("foobar", 0, TEST_HOST, TEST_SERVER_PORT)
    assert_equal 1,
      @client_socket.instance_variable_get("@sess_hash").size

    # We don't really know how long it takes until the thread is
    # actually scheduled so we just add a few seconds for good
    # measure.
    sleep 5 * TEST_TIMEOUT

    assert_equal 0,
      @client_socket.instance_variable_get("@sess_hash").size
  end
end