class TestUDPSocket < Utility
  TEST_TIMEOUT = 5.freeze

  def setup
    super

    @server_socket = TinyDTLS::UDPSocket.new(TEST_AFAM)
    @server_socket.bind(TEST_HOST, TEST_SERVER_PORT)
    @server_socket.add_client(TEST_ID, TEST_PSK)

    @client_socket = TinyDTLS::UDPSocket.new(TEST_AFAM, TEST_TIMEOUT)
    @client_socket.add_client(TEST_ID, TEST_PSK)
  end

  def teardown
    @server_socket.close
    @client_socket.close
  end

  def test_addr
    assert_equal ["AF_INET", TEST_SERVER_PORT, TEST_IPADDR, TEST_IPADDR],
      @server_socket.addr
  end

  def test_addr_reverse_lookup
    addrinfo = Socket.getaddrinfo(
      TEST_HOST, TEST_SERVER_PORT, TEST_AFAM, :DGRAM,
      0, 0, true).first

    assert_equal addrinfo[0..3], @server_socket.addr(true)
  end

  def test_send_and_recvfrom
    teststr = "foobar"

    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_send_sockaddr_to
    teststr = "foo bar foo"

    sockaddr_to = Socket.sockaddr_in(TEST_SERVER_PORT, TEST_IPADDR)
    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0, sockaddr_to)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_connect_send
    teststr = "cheesecake"

    @client_socket.connect(TEST_HOST, TEST_SERVER_PORT)
    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_send_missing_connect
    assert_raises Errno::EDESTADDRREQ do
      @client_socket.send("foobar", 0)
    end
  end

  def test_send_non_ascii
    teststr = "käsekuchen"

    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr.force_encoding("ASCII-8BIT"),
      @server_socket.recvfrom
  end

  def test_send_multiple
    teststrs = ["foo", "bar", "baz", "123"]

    teststrs.each do |teststr|
      assert_equal teststr.bytesize,
        @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

      assert_msg teststr, @server_socket.recvfrom
    end
  end

  def test_recv_with_maxlen
    teststr = "kartoffelsalat"
    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    substr = teststr[0..8] # kartoffel
    assert_msg substr, @server_socket.recvfrom(substr.length)
  end

  def test_recvfrom_nonblock_empty
    assert_raises IO::EAGAINWaitReadable do
      @server_socket.recvfrom_nonblock
    end

    assert_equal :wait_readable,
      @server_socket.recvfrom_nonblock(exception: false)
  end

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
