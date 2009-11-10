module Cul
  module Handles
    class ChallengeAnswerRequest < BaseRequest
      include Hdl
      def initialize(nonce,digest,keyHandle, keyIndex)
        super()
        @nonce = nonce
        @digest =digest
        @opCode = asBytes(OC_CHALLENGE_RESPONSE)
        @authenticationType = toProtocolString("HS_SECKEY")
        @keyHandle = toProtocolString(keyHandle)
        @keyIndex = asBytes(keyIndex)
        @challengeResponse = []
        @secret = []
        self.responseCode = 0
        self.authoritative=false
        self.returnRequestDigest=false
        self.encrypt=false
        self.publicOnly=false
        self.certify=false
        self.cacheCertify=true
        self.recursive=true
        self.continuous=false
        self.keepAlive=false
        self.expirationTime=0
      end
      def body()
        @body
      end
      def secret=(val)
        @secret = val.unpack('U*').pack('C*')
      end
      def encodeBody()
        digest = Digest::SHA1.new()
        digest.update(@secret)
        digest.update(@nonce.pack('C*'))
        digest.update(@digest.pack('C*'))
        digest.update(@secret)
        prehash = digest.digest()
        @challengeResponse = [0x02].concat(prehash.unpack('C*'))
        @challengeResponse = asBytes(@challengeResponse.length).concat(@challengeResponse)
        @body = [].concat(@authenticationType).concat(@keyHandle).concat(@keyIndex).concat(@challengeResponse)
      end  
    end
  end
end