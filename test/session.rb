class TestSession < Minitest::Test
  def test_new
    addrinfo = Addrinfo.getaddrinfo("www.uni-bremen.de", 443).first
    assert_equal addrinfo, TinyDTLS::Session.new(addrinfo).addrinfo
  end

  def test_new_invalid
    assert_raises TypeError do
      TinyDTLS::Session.new(Socket.getaddrinfo("www.google.com", 80).first)
    end
  end

  def test_addr_from_ptr
    addrinfo = Addrinfo.getaddrinfo("www.example.org", nil).first
    sockaddr = addrinfo.to_sockaddr

    session_ptr = TinyDTLS::Wrapper::dtls_new_session(sockaddr, sockaddr.bytesize)
    assert !session_ptr.null?

    assert_equal addrinfo.ip_address,
      TinyDTLS::Session.addr_from_ptr(session_ptr).ip_address
  end
end

