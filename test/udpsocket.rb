require "socket"
require "tinydtls"
require "minitest/autorun"

class TestUDPSocket < Minitest::Test
  # TODO:
  #   1. Make it work with TEST_HOST == "localhost"
  #   2. Make it work without TEST_ID
  #   3. Make it work with UTF8 test strings

  TEST_HOST = "127.0.0.1".freeze
  TEST_PSK  = "foobar".freeze
  TEST_ID   = "default identity".freeze

  TEST_CLIENT_PORT = 2323
  TEST_SERVER_PORT = 4000

  def assert_msg(pay, msg)
    assert_equal pay, msg.first
    assert_equal TEST_HOST, msg.last[3]
  end

  def setup
    @server_socket = TinyDTLS::UDPSocket.new
    @server_socket.bind(TEST_HOST, TEST_SERVER_PORT)
    @server_socket.add_key(TEST_PSK, TEST_ID)

    @client_socket = TinyDTLS::UDPSocket.new
    @client_socket.add_key(TEST_PSK, TEST_ID)
  end

  def teardown
    @server_socket.close
    @client_socket.close
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
end