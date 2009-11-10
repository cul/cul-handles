require "test_helper"

module Cul
  module Handles
    class AuthnTest < Test::Unit::TestCase
      include Hdl
      DEFAULT_ADMIN = "10022/ADMIN"
      def testAdminHandleValueEncoding
        permissions = PERM_ALL
        adminHandle = DEFAULT_ADMIN
        index = 300
        expected = {'permissions' => permissions, 'handle' => adminHandle, 'index' => index}
    
        vbytes = encodeAdminData(adminHandle, permissions, index)
        actual = decodeAdminData(vbytes)
        assert_equal actual.keys, expected.keys
        actual.each_key {|key|
          assert_equal actual[key], expected[key]
        }
      end
      def setup()
        
        @handle_config = YAML::load_file("private/config.yml")
        
        @client = Client.new(@handle_config["host"],@handle_config["port"])
        # from dspace config:
        # handle.auth.handle = 10022/ADMIN
        # handle.auth.index = 300
        # handle.auth.passphrase = #######
        @secret = @handle_config["secret"]
        @handle = "10022/TESTDELETE"
        @admin = "10022/ADMIN"
      end
      def testSessionSetup
        @handle_config = YAML::load_file("private/config.yml")
      
        if 1
          return
        end
        server = @handle_config["host"]
        port = @handle_config["port"]
        sreq = SessionSetupRequest.new(@admin,INDEX_AUTH)
        sreq.requestId=(0)
        sreq.certify=(true)
        cres = ChallengeResponse.new()
        #res = SessionSetupResponse.new()
        sock = TCPSocket.new(server,port)
        cres.send(sreq, sock)
        puts cres
        creq = ChallengeAnswerRequest.new(cres.nonce,@admin,INDEX_AUTH)
        creq.sessionId = cres.sessionId
        creq.requestId = cres.requestId
        sres = SessionSetupResponse.new()
        sres.send(creq,sock)
        sharedSecret = sreq.dh.secret(sres.serverKey)
    
        puts(sres)
        sock.close()
        assert(sres.sessionId != 0, "returned sessionId was zero (0)")
      end
      def test001CreateHandle()
        expectedValue = "http://www.columbia.edu/testCreateHandle/"
        res = @client.createHandle(@secret, @handle, expectedValue)
        if not res.responseCode.eql?1
          puts "unexpected response code: " + res.responseCode.to_s
          puts res
        end
        assert(res.responseCode.eql?(1),"unexpected response code: " + res.responseCode.to_s)
        actualValue = @client.resolve(@handle).handleValue()
        assert_equal(expectedValue, actualValue)
      end
      def test002DeleteValue()
        res = @client.deleteHandleValue(@secret, @handle, "http://www.columbia.edu/testCreateHandle/")
        if not res.responseCode.eql?1
          puts "unexpected response code: " + res.responseCode.to_s
          puts res
        end
        assert(res.responseCode.eql?(1),"unexpected response code: " + res.responseCode.to_s)
        actualValue = @client.resolve(@handle).handleValue()
        assert_nil(actualValue)
      end
      def test003AddValue()
        expectedValue = "http://www.columbia.edu/addValue/"
        res = @client.addHandleValue(@secret, @handle, expectedValue)
        if not res.responseCode.eql?1
          puts "unexpected response code: " + res.responseCode.to_s
          puts res
        end
        assert(res.responseCode.eql?(1),"unexpected response code: " + res.responseCode.to_s)
        actualValue = @client.resolve(@handle).handleValue()
        assert_equal(expectedValue, actualValue)
      end
      def test004DeleteHandle()
        res = @client.deleteHandle(@secret, @handle)
        if not res.responseCode.eql?1
          puts "unexpected response code: " + res.responseCode.to_s
          puts res
        end
        assert(res.responseCode.eql?(1),"unexpected response code: " + res.responseCode.to_s)
        actualResponse = @client.resolve(@handle)
        assert_equal(Hdl::RC_HANDLE_NOT_FOUND,actualResponse.responseCode)
      end
    end
  end
end