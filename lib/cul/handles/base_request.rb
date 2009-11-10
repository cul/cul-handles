module Cul
  module Handles
    class BaseRequest < BaseMessage
      def initialize()
        super()
        @body = []
        @opFlag = [0,0,0,0]
        @recursionCount = [0]
        @messageFlag = [0,0]
        @messageLength = [0,0,0,0]    
        @siteInfoSerial = [0xff,0xff]
        @sessionId = [0,0,0,0]
        @credential = [0,0,0,0]
      end
      def valid?()
        return true
      end
      def opCode=(val)
        @opCode=asBytes(val)
      end
      def opCode()
        @opCode
      end
      def opFlag=(val)
        @opFlag=asBytes(val)
      end
      def opFlag()
        fromBytes(@opFlag)
      end
      def requestId=(val)
        @requestId=asBytes(val)
      end
      def requestId()
        fromBytes(@requestId)
      end
      def sessionId=(val)
        @sessionId=asBytes(val)
      end
      def sessionId()
        @sessionId
      end
      def siteInfoSerial=(val)
        if val < 0
          @siteInfoSerial=asBytes(65536 + val)[-2..-1]
        else
          @siteInfoSerial = asBytes(val)[-2..-1]
        end
      end
      def siteInfoSerial()
        return fromBytes(@siteInfoSerial)
      end
      def sequenceNumber()
        fromBytes(@sequenceNumber)
      end
      def sequenceNumber=(val)
        @sequenceNumber=asBytes(val)
      end
      def recursionCount()
        fromBytes(@recursionCount)
      end
      def recursionCount=(val)
        @recursionCount=asBytes(val)
      end
      def expirationTime()
        fromBytes(@expirationTime)
      end
      def expirationTime=(val)
        @expirationTime=asBytes(val)
      end
      def responseCode=(val)
        @responseCode=asBytes(val)
      end
      def responseCode
        @responseCode
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
      def encodeCredential()
        creds = [].concat(self.credentialVersion).concat(self.credentialReserved).concat(self.credentialOptions()).concat(self.credentialSigner).concat(self.credentialType)
        creds = asBytes(creds.length).concat(creds)
        @credential = creds
      end
      def credential()
        @credential
      end
      def messageFlag=(val)
        @messageFlag = val
      end
      def envelope
        e = [@majorVersion, @minorVersion]
        e.concat(@messageFlag)
        e.concat(@sessionId)
        e.concat(@requestId)
        e.concat(@sequenceNumber)
        e.concat(asBytes(@body.length + 24 + @credential.length))
        e
      end
      def messageFlag
        return @messageFlag
      end
      def messageLength
        @body.length + 24 + @credential.length
      end
      def header
        result = [].concat(self.opCode)
        result.concat(@responseCode)
        result.concat(@opFlag)
        result.concat(@siteInfoSerial)
        result.concat(@recursionCount)
        result.concat([0])
        result.concat(@expirationTime)
        result.concat(asBytes(@body.length))
        return result
      end
      def body
        return @body
      end
      def encodeBody()
        return
      end
      def bodyLength
        return asBytes(@body.length) 
      end
      def digest(data)
        return @SHA1.digest(data.pack('U*')).unpack('c*')
      end
      def packet
        encodeBody()
        encodeCredential()
        result =  envelope().concat(header())
        result.concat(body())
        result.concat(credential())
        return result
      end
    end
  end
end