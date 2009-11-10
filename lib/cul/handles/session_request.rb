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
    class DH
      include Hdl
      attr_reader :prime, :generator, :maxrand, :publickey
    #  def DH.miller_rabin(a, n)
    #    
    #  end
    #  def DH.prime
    #    
    #  end
      def DH.mod_exp start, e, m
        result = 1
        b = start
        while e > 0
          result = (result * b) % m if e[0] == 1
          e = e >> 1
          b = (b*b) %m
        end
        return result
      end
      def initialize(prime, generator, maxrand)
        @prime = prime
        @generator = generator
        @maxrand = maxrand
        @publickey = 0 #public key
        @key = 0 #shared secret
        @private = 0 #private key
      end
      def generate tries=16 # shared key
        tries.times do
          @private = rand(@maxrand)
          @publickey = DH.mod_exp(@generator, @private, @prime)
          return @publickey if self.valid?
        end
      end
      def secret f # private key
        @key = DH.mod_exp(f,@private,@prime)
        @key
      end
      def valid? _e = self.publickey
        _e and _e.between?(2,self.prime-2) and _e != 0
      end
      def encodeKeyParms
        result = []
        publicBytes = asBytes(@publickey)
        result.concat(asBytes(publicBytes.length))
        result.concat(publicBytes)
        primeBytes = asBytes(@prime)
        result.concat(asBytes(primeBytes.length))
        result.concat(primeBytes)
        genBytes = asBytes(@generator)
        result.concat(asBytes(genBytes.length))
        result.concat(genBytes)
        result
      end
    end
  end
end