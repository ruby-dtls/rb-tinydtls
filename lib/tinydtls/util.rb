module TinyDTLS
  module Util
    def self.byteslice(str, len)
      return len >= 0 ? str.byteslice(0, len) : str
    end
  end
end
