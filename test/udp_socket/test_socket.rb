class TestSocket < Minitest::Test
  TEST_TIMEOUT = 5.freeze

  TEST_HOST = "localhost".freeze
  TEST_AFAM = Socket::AF_INET
  TEST_PSK  = "foobar".freeze
  TEST_ID   = "default identity".freeze

  TEST_CLIENT_PORT = 2323
  TEST_SERVER_PORT = 4000

  TEST_IPADDR = Addrinfo
    .getaddrinfo(TEST_HOST, nil, TEST_AFAM, :DGRAM)
    .first.ip_address

  TEST_LOG_LEVEL = TinyDTLS::Wrapper::LogLevel[:DTLS_LOG_EMERG]

  def setup
    TinyDTLS::Wrapper::dtls_set_log_level(TEST_LOG_LEVEL)

    @server_socket = TinyDTLS::UDPSocket.new(TEST_AFAM)
    @server_socket.bind(TEST_HOST, TEST_SERVER_PORT)
    @server_socket.add_client(TEST_ID, TEST_PSK)

    @client_socket = TinyDTLS::UDPSocket.new(TEST_AFAM, TEST_TIMEOUT)
    @client_socket.add_client(TEST_ID, TEST_PSK)
  end

  def teardown
    @client_socket.close
    @server_socket.close
  end

  def assert_msg(exp_msg, args)
    msg, sender = args
    assert_equal exp_msg, msg

    if sender.is_a? Addrinfo
      af, port, host, addr = to_ary(sender)
    else
      afstr, port, host, addr = sender
      af = af_to_i(afstr)
    end

    assert_equal af, TEST_AFAM
    # XXX: There is no way to check port
    assert_equal host, TEST_HOST
    assert_equal addr, TEST_IPADDR
  end

  def assert_server_addr(addr, reverse = false)
    if addr.is_a? Addrinfo
      addr = to_ary(addr)
    else
      addr[0] = af_to_i(addr[0])
    end

    saddr = reverse ? TEST_HOST : TEST_IPADDR
    assert_equal [TEST_AFAM, TEST_SERVER_PORT,
                  saddr, TEST_IPADDR], addr
  end

  private

  def to_ary(addrinfo)
    [
      addrinfo.afamily,
      addrinfo.ip_port,
      addrinfo.getnameinfo.first,
      addrinfo.ip_address
    ]
  end

  def af_to_i(af)
    case af
    when "AF_INET"
      Socket::AF_INET
    when "AF_INET6"
      Socket::AF_INET6
    else
      raise TypeError.new("Unknown address family string '#{af}'")
    end
  end
end
