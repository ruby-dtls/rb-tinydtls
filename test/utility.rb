class Utility < Minitest::Test
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
  end

  def assert_msg(exp_msg, args)
    msg, sender = args
    assert_equal exp_msg, msg

    if sender.is_a? Addrinfo
      af, port, host, addr = [
        sender.afamily,
        sender.ip_port,
        sender.getnameinfo.first,
        sender.ip_address
      ]
    else
      afstr, port, host, addr = sender
      af = af_to_i(afstr)
    end

    assert_equal af, TEST_AFAM
    # XXX: There is no way to check port
    assert_equal host, TEST_HOST
    assert_equal addr, TEST_IPADDR
  end

  def assert_used(session)
    assert session.last
  end

  def assert_unused(session)
    assert !session.last
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
