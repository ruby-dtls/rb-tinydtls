class TestUDPSocket < TestSocket
  def test_connect_send
    teststr = "cheesecake"

    @client_socket.connect(TEST_HOST, TEST_SERVER_PORT)
    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0)

    assert_msg teststr, @server_socket.recvfrom
  end

  def test_connect_unsupported_afamily
    assert_raises SocketError do
      @client_socket.connect("::1", TEST_SERVER_PORT)
    end
  end

  def test_send_missing_connect
    assert_raises Errno::EDESTADDRREQ do
      @client_socket.send("foobar", 0)
    end
  end

  def test_recvfrom_nonblock_empty
    assert_raises IO::EAGAINWaitReadable do
      @server_socket.recvfrom_nonblock
    end

    assert_equal :wait_readable,
      @server_socket.recvfrom_nonblock(exception: false)
  end

  def test_recvfrom_nonblock
    teststr = "foobar"

    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
    begin
      msg = @server_socket.recvfrom_nonblock(teststr.bytesize, 0)
    rescue IO::EAGAINWaitReadable
      retry
    end

    assert_msg teststr, msg
  end

  def test_recvfrom_nonblock_peek_empty
    assert_raises IO::EAGAINWaitReadable do
      @server_socket.recvfrom_nonblock(2342, Socket::MSG_PEEK)
    end
  end

  def test_recvfrom_nonblock_peek
    teststr = "foobarbaz"

    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
    begin
      msg = @server_socket.recvfrom_nonblock(teststr.bytesize, Socket::MSG_PEEK)
    rescue IO::EAGAINWaitReadable
      retry
    end

    assert_msg teststr, msg
    assert_msg teststr, @server_socket.recvfrom_nonblock
  end

  def test_recvfrom_nonblock_outbuf
    teststr = "12345678"
    outbuf  = String.new

    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
    begin
      @server_socket.recvfrom_nonblock(teststr.bytesize, 0, outbuf)
    rescue IO::EAGAINWaitReadable
      retry
    end

    assert_equal teststr, outbuf
  end

  def test_recvmsg_nonblock_empty
    assert_raises IO::EAGAINWaitReadable do
      @server_socket.recvmsg_nonblock
    end
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
end
