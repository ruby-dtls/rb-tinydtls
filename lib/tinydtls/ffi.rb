require "ffi"

module TinyDTLS
  # This module provides a low level FFI wrapper for the relevant
  # tinydtls functions. It might be subject to change thus it is highly
  # recommended to use the high level abstraction layer instead.
  module FFI
    extend FFI::Library
    ffi_lib "libtinydtls.so"

    # Constants defined as macros in the tinydtls header files
    DTLS_COOKIE_SECRET_LENGTH = 12
    DTLS_MAX_BUF = 1400

    enum :alert_level, [
      :DTLS_ALERT_LEVEL_WARNING, 1,
      :DTLS_ALERT_LEVEL_FATAL, 2,
    ]

    enum :credential_type, [
      :DTLS_PSK_HINT,
      :DTLS_PSK_IDENTITY,
      :DTLS_PSK_KEY,
    ]

    class DTLSContextStruct < FFI::ManagedStruct
      layout :cookie_secret, [:uchar, DTLS_COOKIE_SECRET_LENGTH],
        :cookie_secret_age, :uint32,
        :peers, :pointer,
        :sendqueue, :pointer,
        :app, :pointer,
        :h, :pointer,
        :readbuf, [:uchar, DTLS_MAX_BUF]

      def self.release(ptr)
        Wrapper.dtls_free_context(ptr)
      end
    end

    class DTLSHandlerStruct < FFI::Struct
      layout :write,
        callback([:pointer, :pointer, :pointer, :size_t], :int),
      :read,
        callback([:pointer, :pointer, :pointer, :size_t], :int),
      :event_function,
        callback([:pointer, :pointer, :alert_level, :ushort], :int),
      :get_psk_info,
        callback([:pointer, :pointer, :credential_type,
                  :uchar, :size_t, :pointer, :size_t], :int),
      :get_ecdsa_key,
        callback([:pointer, :pointer, :pointer], :int),
      :verify_ecdsa_key,
        callback([:pointer, :pointer, :uchar, :uchar, :size_t], :int)
    end

    attach_function :dtls_init, [], :void
    attach_function :dtls_new_context, [:pointer], :pointer
    attach_function :dtls_free_context, [:pointer], :void
    attach_function :dtls_handle_message,
      [:pointer, :pointer, :pointer, :int], :int

    # This type is needed for the `dtls_session_addr` wrapper.
    # See https://github.com/ffi/ffi/wiki/Pointers#passing-by-reference
    class Uint16Ptr < FFI::Struct
      layout :value, :uint16
    end

    # These functions are not available in vanilla tinydtls.
    # They are required to make interaction with the tinydtls `session_t`
    # type possible without creating a ruby wrapper for `struct
    # sockaddr_in{,6}`.
    attach_function :dtls_new_session,
      [:sa_family_t, :uint16, :pointer], :pointer
    attach_function :dtls_session_addr, [:pointer, Uint16Ptr], :strptr

  end
end
