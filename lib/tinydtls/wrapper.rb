module TinyDTLS
  # This module provides a low level FFI wrapper for the relevant
  # tinydtls functions. It might be subject to change thus it is highly
  # recommended to use the high level abstraction layer instead.
  module Wrapper
    extend FFI::Library
    ffi_lib "libtinydtls.so"

    # Constants defined as macros in the tinydtls header files
    DTLS_COOKIE_SECRET_LENGTH = 12
    DTLS_MAX_BUF = 1400

    Alert = enum(
      :DTLS_ALERT_CLOSE_NOTIFY, 0,
      :DTLS_ALERT_UNEXPECTED_MESSAGE, 10,
      :DTLS_ALERT_BAD_RECORD_MAC, 20,
      :DTLS_ALERT_RECORD_OVERFLOW, 22,
      :DTLS_ALERT_DECOMPRESSION_FAILURE, 30,
      :DTLS_ALERT_HANDSHAKE_FAILURE, 40,
      :DTLS_ALERT_BAD_CERTIFICATE, 42,
      :DTLS_ALERT_UNSUPPORTED_CERTIFICATE, 43,
      :DTLS_ALERT_CERTIFICATE_REVOKED, 44,
      :DTLS_ALERT_CERTIFICATE_EXPIRED, 45,
      :DTLS_ALERT_CERTIFICATE_UNKNOWN, 46,
      :DTLS_ALERT_ILLEGAL_PARAMETER, 47,
      :DTLS_ALERT_UNKNOWN_CA, 48,
      :DTLS_ALERT_ACCESS_DENIED, 49,
      :DTLS_ALERT_DECODE_ERROR, 50,
      :DTLS_ALERT_DECRYPT_ERROR, 51,
      :DTLS_ALERT_PROTOCOL_VERSION, 70,
      :DTLS_ALERT_INSUFFICIENT_SECURITY, 71,
      :DTLS_ALERT_INTERNAL_ERROR, 80,
      :DTLS_ALERT_USER_CANCELED, 90,
      :DTLS_ALERT_NO_RENEGOTIATION, 100,
      :DTLS_ALERT_UNSUPPORTED_EXTENSION, 110
    )

    enum :alert_level, [
      :DTLS_ALERT_LEVEL_WARNING, 1,
      :DTLS_ALERT_LEVEL_FATAL, 2,
    ]

    enum :credential_type, [
      :DTLS_PSK_HINT,
      :DTLS_PSK_IDENTITY,
      :DTLS_PSK_KEY,
    ]

    class DTLSContextStruct < FFI::Struct
      layout :cookie_secret, [:uchar, DTLS_COOKIE_SECRET_LENGTH],
        :cookie_secret_age, :uint32,
        :peers, :pointer,
        :sendqueue, :pointer,
        :app, :pointer,
        :h, :pointer,
        :readbuf, [:uchar, DTLS_MAX_BUF]
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
                  :pointer, :size_t, :pointer, :size_t], :int),
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
    attach_function :dtls_write,
      [:pointer, :pointer, :pointer, :size_t], :int
    attach_function :dtls_connect,
      [:pointer, :pointer], :int

    def self.dtls_alert_fatal_create(desc)
      return -((2 << 8) | desc)
    end

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

    def self.dtls_get_app_data(ctx)
      return ctx[:app]
    end

    def self.dtls_set_handler(ctx, handler)
      ctx[:h] = handler
    end
  end
end
