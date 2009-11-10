module Cul
  module Handles
    class ResolutionRequest < BaseRequest
      def initialize(handle)
        super()
        @opCode = asBytes(OC_RESOLUTION)
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
        @handle = toProtocolString(handle)
      end
      def encodeBody()
        @body= [].concat(@handle).concat(self.indexList).concat(self.typeList) 
      end
      def indexList
        [0,0,0,0] # return all indices
      end
      def typeList
        [0,0,0,0] # return all types
      end
    end
  end
end