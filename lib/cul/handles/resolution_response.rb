module Cul
  module Handles
    class ResolutionResponse < BaseResponse
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
        arrayInfo = readByteArray(data,offset)
        offset = offset + arrayInfo[0]
        @handle = arrayInfo[1]
        numVals = fromBytes(data[offset...offset+4])
        offset = offset + 4
        @handleValues = []
        for i in (1..numVals)
          valLen = calculateValueLen(data,offset)
          value = HandleValue.new(data[offset...offset+valLen])
          @handleValues.push(value)
          puts value
          offset = offset + valLen
        end
      end
      def handle
        if(@handle)
          return @handle.pack('c*')
        else
          return ''
        end
      end  
      def handleValue(type='URL')
        @handleValues.each{|value|
          if value.type == type
            return value.data
          end
        }
        return nil
      end
    end
  end
end