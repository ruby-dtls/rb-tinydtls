class Utility < Minitest::Test
  TEST_HOST = "localhost".freeze
  TEST_AFAM = Socket::AF_INET
  TEST_PSK  = "foobar".freeze
  TEST_ID   = "default identity".freeze

  TEST_CLIENT_PORT = 2323
  TEST_SERVER_PORT = 4000

  def assert_msg(pay, msg)
    assert_equal pay, msg.first
    assert_equal TEST_HOST, msg.last[2]
  end
end
