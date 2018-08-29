class TestIPSocket < TestSocket
  def test_addr
    assert_server_addr @server_socket.addr
    assert_server_addr @server_socket.addr(true), true
  end

  def test_peeraddr
    @client_socket.connect(TEST_HOST, TEST_SERVER_PORT)

    assert_server_addr @client_socket.peeraddr
    assert_server_addr @client_socket.peeraddr(true), true
  end

  def test_recvfrom_with_maxlen
    teststr = "kartoffelsalat"
    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    substr = teststr[0..8] # kartoffel
    assert_msg substr, @server_socket.recvfrom(substr.length)
  end

  def test_recvfrom_peek
    teststr = "schinkenwurst"
    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr, @server_socket
      .recvfrom(teststr.bytesize, Socket::MSG_PEEK)
    assert_msg teststr, @server_socket
      .recvfrom(teststr.bytesize)
  end

  def test_recvfrom_peek_empty
    teststr = "milchbrei"

    Thread.new do
      assert_msg teststr, @server_socket
        .recvfrom(teststr.bytesize, Socket::MSG_PEEK)
    end

    sleep 1
    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
  end
end
