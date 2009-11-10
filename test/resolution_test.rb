require 'test_helper'
module Cul
  module Handles
    class ResolutionTest < Test::Unit::TestCase
      def testRequestPacketFormat
        # expected value taken from output of Java client
        # expiration time is fixed in expected value
        # @expirationTime = [74,88,80,227] # for testing purposes!!!
        # expected = "02010000000000000607010a00000000000000060000000100000000090000000f0f00000a01090f0000000a0000000e01000002020f01030a040a080602000000000000000000000000"
        expected = ["0201000000000000000000000000000000000036000000010000000018000000ffff00004a6189cf0000001a0000000e31303032322f41433a543a383632000000000000000000000000"]
        test = ResolutionRequest.new("10022/AC:T:862")
        test.requestId = 0
    
        test.siteInfoSerial = -1
        test.sessionId = 0
        test.expirationTime= 1247906255
        actual = test.packet.pack('C*').unpack('H*')
        assert_equal actual, expected
      end
      def testResolutionPacket()
        expected = "10022/ba2213"
        @handle_config = YAML::load_file("private/config.yml")

        response = Cul::Handles::Client.new(@handle_config["host"],@handle_config["port"]).resolve(expected)
        assert_equal response.responseCode, 1

        actual = response.handle
        assert_equal actual, expected

        ctr = 0
        expected = "http://www.columbia.edu/~ba2213/changes.txt"
        actual = response.handleValue('URL')
        assert_equal actual, expected
    #    response.packet.each { | byteVal|
    #      actual.concat("%02x" % byteVal)
    #      ctr = ctr + 1
    #      if ctr % 4 == 0
    #        actual.concat(" ")
    #      end
    #    }
    #    puts(actual)
    #    puts(response)
    #    rcode = response.responseCode
      end
    end
  end
end