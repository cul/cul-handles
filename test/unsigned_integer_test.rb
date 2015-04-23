# -*- encoding: utf-8 -*-
require 'test_helper'
module Cul
  module Handles
    class UnsignedIntegerTest < Test::Unit::TestCase
      include Hdl
      ASCII_ENCODED = [0,0,0,6,0x66,0x6f,0x6f,0x62,0x61,0x72]
      ASCII_DECODED = "foobar"
      ZERO_ENCODED = [0,0,0,0]
      ZERO_DECODED = ""
      UNICODE_ENCODED = [0,0,0,7,0x66,0x6f,0x6f,0x62,0xc4,0x81,0x72]
      UNICODE_DECODED = "foobār"
      def testUnsignedIntSerialization
        # [ 16777216 , 65536, 256, 1]
        input = [0x60,0xd4,0xee,0x52]
        expected = 1624567378 # 1624567378
        actual = fromBytes(input)
        assert_equal actual, expected
      end
      def testUnsignedIntDeserialization
        # [ 16777216 , 65536, 256, 1]
        expected = [0x60,0xd4,0xee,0x52]
        input = 1624567378 # 1624567378
        actual = asBytes(input)
        assert_equal actual, expected
      end
      def testProtocolStringEncode()
        expected = ASCII_ENCODED
        actual = toProtocolString(ASCII_DECODED)
        assert_equal actual, expected

        expected = ZERO_ENCODED
        actual = toProtocolString(ZERO_DECODED)
        assert_equal actual, expected

        expected = UNICODE_ENCODED
        actual = toProtocolString(UNICODE_DECODED)
        assert_equal actual, expected
      end

      def testProtocolStringDecode()
        expected = ASCII_DECODED
        actual = readProtocolString(ASCII_ENCODED)[1]
        assert_equal actual, expected

        expected = ZERO_DECODED
        actual = readProtocolString(ZERO_ENCODED)[1]
        assert_equal actual, expected

        expected = UNICODE_DECODED
        actual = readProtocolString(UNICODE_ENCODED)[1]
        assert_equal actual, expected
      end

      def stringAsHex(input)
        input = input.unpack("U*")
        bytesAsHex(input)
      end
      def bytesAsHex(input)
        result = ''
        ctr = 0
        input.each { |byteVal|
          result.concat("%02x" % byteVal)
        ctr = ctr + 1
        if ctr % 2 == 0
          result.concat(" ")
        end
   
        }
        result
      end
    end
  end
end