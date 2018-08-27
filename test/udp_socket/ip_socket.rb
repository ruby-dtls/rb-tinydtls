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
end
