class TestUDPSocket < Utility
  # TODO:
  #   1. Make it work without TEST_ID

  def setup
    @server_socket = TinyDTLS::UDPSocket.new(TEST_AFAM)
    @server_socket.bind(TEST_HOST, TEST_SERVER_PORT)
    @server_socket.add_key(TEST_PSK, TEST_ID)

    @client_socket = TinyDTLS::UDPSocket.new(TEST_AFAM)
    @client_socket.add_key(TEST_PSK, TEST_ID)
  end

  def teardown
    @server_socket.close
    @client_socket.close
  end

  def test_addr
    ipaddr = Addrinfo.ip(TEST_HOST).ip_address
    assert_equal ["AF_INET", TEST_SERVER_PORT, ipaddr, ipaddr],
      @server_socket.addr
  end

  def test_addr_reverse_lookup
    addrinfo = Socket.getaddrinfo(
      TEST_HOST, TEST_SERVER_PORT, nil, :DGRAM).first

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

    sockaddr_to = Socket.sockaddr_in(TEST_SERVER_PORT, TEST_HOST)
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

  def test_send_non_ascii
    teststr = "käsekuchen"

    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_send_multiple
    teststrs = ["foo", "bar", "baz", "123"]

    teststrs.each do |teststr|
      assert_equal teststr.bytesize,
        @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

      assert_msg teststr, @server_socket.recvfrom
    end
  end
end
