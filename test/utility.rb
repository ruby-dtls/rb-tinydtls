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

  def assert_msg(pay, msg)
    assert_equal pay, msg.first
    assert_equal TEST_HOST, msg.last[2]
  end

  def assert_used(session)
    assert session.last
  end

  def assert_unused(session)
    assert !session.last
  end
end
