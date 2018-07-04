require "socket"
require "ffi"

require "tinydtls/wrapper"
require "tinydtls/context"
require "tinydtls/session"
require "tinydtls/udpsocket"

module TinyDTLS
  # Map used to map `object_ids` passed as void pointers to the tinydtls
  # callback functions to actually ruby UDPSockets. This is neccessary
  # since we can't pass pointers to ruby objects to C functions.
  CONTEXT_MAP = Hash.new
end
