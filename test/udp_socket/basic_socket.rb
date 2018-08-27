class TestBasicSocket < TestSocket
  def test_send_and_recvmsg
    teststr = "hurr durr"

    assert_equal teststr.bytesize,
      @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)

    assert_msg teststr, @server_socket.recvmsg
  end

  def test_recvmsg_nonblock_empty
    assert_raises IO::EAGAINWaitReadable do
      @server_socket.recvmsg_nonblock
    end
  end

  def test_recv
    teststr = "wurstbrot"

    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
    assert_equal teststr, @server_socket.recv
  end

  def test_recv_outbuf
    teststr = "schinkensalami"
    outbuf  = String.new

    @client_socket.send(teststr, 0, TEST_HOST, TEST_SERVER_PORT)
    @server_socket.recv(teststr.bytesize, 0, outbuf)

    assert_equal teststr, outbuf
  end

  # TODO: tests for recv_nonblock

  def test_remoteaddr
    @client_socket.connect(TEST_HOST, TEST_SERVER_PORT)
    assert_server_addr @client_socket.remote_address, true
  end
end
