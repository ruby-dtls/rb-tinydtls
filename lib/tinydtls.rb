require "socket"
require "ffi"

require "tinydtls/wrapper"
require "tinydtls/context"
require "tinydtls/session"
require "tinydtls/security_conf"
require "tinydtls/session_manager"
require "tinydtls/udp_socket"

module TinyDTLS
  # Map used to map `object_ids` passed as void pointers to the tinydtls
  # callback functions to actually ruby UDPSockets. This is neccessary
  # since we can't pass pointers to ruby objects to C functions.
  CONTEXT_MAP = Hash.new
end
