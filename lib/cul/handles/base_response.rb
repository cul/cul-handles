module Cul
  module Handles

    class BaseResponse < BaseMessage
      include Hdl
      def initialize
        super()
        @packet = []
        @siteInfoSerial = [0,0]
        @requestId = [0,0,0,0]
        @sessionId = [0,0,0,0]
        @opCode = [0,0,0,0]
        @responseCode = [0,0,0,0]
        @opFlag = [0,0,0,0]
        @recursionCount = 0
        @expirationTime = [0,0,0,0]
        @bodyLength = 0
        @debug = false
      end
      def debug=(val)
        if(val)
          @debug = true
        else
          @debug = false
        end
      end
      def send(req,sock)
        if not req.valid?()
          raise "Request invalid: " + req.to_s
        end
        initialize()
        bytes = req.packet
        bctr = 0
        puts "sending \n" + bytes.collect{|byte|
           bctr = bctr + 1
          if byte.nil?
            "nil byte at " + bctr.to_s
          else
          "%02x" % byte
          end
        }.join if @debug
        sent = sock.write(bytes.pack('C*'))
    
        if sent != bytes.length
          puts "Warning: Attempted to send " + bytes.length.to_s + "; actually sent " + sent.to_s
        end
        parseEnvelope(sock.recv(20).unpack('C*'))
        puts "parsed envelope" if @debug
        parseHeader(sock.recv(24).unpack('C*'))
        puts "parsed header" if @debug
        parseBody(sock.recv(@bodyLength).unpack('C*'))
        puts "parsed body" if @debug
        parseCredential(Array.new())
      end
      def parseEnvelope(data)
        "parseEnvelope"
        if(data.length != 20)
          puts("Unexpected envelope length: " + data.length.to_s)
          return
        end
        @packet.concat(data)
        # version info
        @majorVersion = data[0]
        @minorVersion = data[1]
        # message flag
        mflag = data[2] # actually 2 octets, but second octet is reserved
        if ((mflag & Hdl::ENV_FLAG_COMPRESSED) == Hdl::ENV_FLAG_COMPRESSED)
          @compressed = true
        end
        if ((mflag & Hdl::ENV_FLAG_ENCRYPTED) == Hdl::ENV_FLAG_ENCRYPTED)
          @encrypted = true
        end
        if ((mflag & Hdl::ENV_FLAG_TRUNCATED) == Hdl::ENV_FLAG_TRUNCATED)
          @truncated = true
        end
        # session id
        @sessionId = data[4..7]
        # request id
        @requestId = data[8..11]
        # sequence number
        @sequenceNumber = data[12..15]
        # message length
        @messageLength = data[16..19]
      end
      def sessionId
        return fromBytes(@sessionId)
      end
      def requestId
        return fromBytes(@requestId)
      end
      def parseHeader(data)
        @packet.concat(data)
        if(data.length != 24)
          puts("Unexpected header length: " + data.length.to_s)
          return
        end
        @opCode = data[0..3]
        @responseCode = data[4..7]
        @opFlag = data[8..11]
        @siteInfoSerial = data[12..13]
        @recursionCount = data[14]
        @expirationTime = data[16..19]
        @bodyLength = fromBytes(data[20..23])
        if(@bodyLength < 1)
          puts "Unexpected @bodyLength: " + @bodyLength.to_s
        end
      end
      def opCode
        return fromBytes(@opCode)
      end
      def responseCode
        return fromBytes(@responseCode)
      end
      def success?
        return @responseCode.eql?([0,0,0,1])
      end
      def siteInfoSerial
        return fromBytes(@siteInfoSerial)
      end
      def parseBody(data)
        offset = 0
        @packet.concat(data)
        # parse return digest
        if self.returnRequestDigest()
          self.digestAlg = data[offset]
          if (@digestLength)
            @messageDigest = data[1..(@digestLength)]
            offset = 1 + @digestLength
          else
            @messageDigest = []
          end
        end
        @body = data[offset...@bodyLength]
      end
      def body
        @body
      end
      def parseCredential(data)
        offset = 0
        @packet.concat(data)
        # parse credential
        if (data.length > 0)
          @credentialVersion = data[offset]
          offset = offset + 2
          @credentialOptions = data[offset..offset+1]
          offset = offset + 2
          @credential = data[offset...(offset+credentialLength)]
          offset = offset + credentialLength
          pstringData = readProtocolString(data,offset)
          offset = offset + pstringData[0]
          type = pstringData[1]
          signedInfoLength = fromBytes(data[offset...offset+4])
          offset = offset + 4
          signedInfoAlg = nil
          signedInfoData = nil
          if signedInfoLength > 0
            signedInfoEnd = offset + signedInfoLength
            pstringData = readProtocolString(data,offset)
            offset = offset + pstringData[0]
            self.signedInfoAlg = pstringData[1]
            self.signedInfoData = data[offset..-1]
            offset = signedInfoEnd
          end
      
        end
      end
      def credential
        @credential
      end
      def credentialType=(val)
        @credentialType = val
      end
      def signedInfoAlg=(val)
        @signedInfoAlg = val
      end
      def signedInfo=(val)
        @signedInfo=val
      end
      def packet
        @packet
      end
      def to_s
        result = "opCode: " + opCode.to_s + "; responseCode: " + responseCode().to_s + " sessionId: " + fromBytes(@sessionId).to_s + "; requestId: " + fromBytes(@requestId).to_s + "; bodyLength: " + @bodyLength.to_s
        if @bodyLength > 0
          result = result + "; body: " + @packet[44...(44+@bodyLength)].pack('c*')
        end
        result
      end
    end
  end
end