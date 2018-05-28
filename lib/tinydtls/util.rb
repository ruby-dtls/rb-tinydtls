module TinyDTLS
  module Util
    def self.byteslice(str, len)
      return len >= 0 ? str.byteslice(0, len) : str
    end

    def self.dtls_send(ctx, mesg, addrinfo)
      sess = Wrapper::dtls_new_session(
        addrinfo.afamily, addrinfo.ip_port, addrinfo.ip_address)

      res = Wrapper::dtls_write(ctx, sess, mesg, mesg.bytesize)
      if res == -1
        raise Errno::EIO
      end

      return res
    end
  end
end
