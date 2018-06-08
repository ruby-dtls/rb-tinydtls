require "socket"
require "tinydtls"
require "minitest/autorun"

class TestUDPSocket < Minitest::Test
  # TODO:
  #   1. Make it work with TEST_HOST == "localhost"
  #   2. Make it work without TEST_ID

  TEST_HOST = "127.0.0.1".freeze
  TEST_AFAM = Socket::AF_INET
  TEST_PSK  = "foobar".freeze
  TEST_ID   = "default identity".freeze

  TEST_CLIENT_PORT = 2323
  TEST_SERVER_PORT = 4000

  # Reduce the timeout for the test_free_stale_peer method.
  TEST_TIMEOUT = 5

  def assert_msg(pay, msg)
    assert_equal pay, msg.first
    assert_equal TEST_HOST, msg.last[3]
  end

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
