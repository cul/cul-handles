module Cul
  module Handles
    class SessionSetupRequest < BaseRequest
      include Hdl
      attr_reader :dh
      KEYMAX = (2**513)-1
      def initialize(authHandle, authIndex)
        super()
        @opCode = asBytes(OC_SESSION_SETUP)
        @sessionId = [0,0,0,0]
        @requestId = [0,0,0,0]
        @siteInfoSerial = [0,0,0,0]
        self.responseCode = 0
        self.authoritative=true
        self.returnRequestDigest=true
        self.encrypt=false
        self.publicOnly=false
        self.certify=true
        self.cacheCertify=true
        self.recursive=true
        self.continuous=false
        self.keepAlive=false
        self.expirationTime=0
        @dh = DH.new(53,5,KEYMAX)
        while(not @dh.valid?)
          @dh.generate
        end
        self.body= getAttributes(authHandle, authIndex)
      end
      def getAttributes(authHandle, authIndex)
        # identity att
        identity = toProtocolString("HS_SESSION_IDENTITIY")
        identity.concat(toProtocolString(authHandle))
        identity.concat(asBytes(authIndex))
        # key exchange att
        exchange = toProtocolString("HS_SESSION_KEY_EXCHANGE")
        exchange.concat(toProtocolString("DIFFIE_HELLMAN"))
        exchange.concat(@dh.encodeKeyParms)
        # timeout att
        timeout = toProtocolString("HS_SESSION_TIMEOUT")
        timeout.concat([0,0,0,120])
        [0,0,0,2].concat(identity).concat(timeout)
      end
      def indexList
        [0,0,0,0] 
      end
      def typeList
        [0,0,0,0]
      end
      def credentialVersion()
        return []
      end
      def credentialReserved()
        return []
      end
      def credentialOptions()
        return []
      end
      def credentialSigner()
        return []
      end
      def credentialType()
        return []
      end
      def credentialDigestAlg()
        return []
      end  
    end
  end
end