module Cul
  module Handles
    class SessionSetupResponse < BaseResponse
      attr_reader :serverKey
      def parseBody(data)
        puts "parseBody"
        @digestAlg = data[0]
        if(@digestAlg == 2)
          @digest = data[1..20]
          offset = 21
        else
          @digest =data[1..16]
          offset = 17
        end
        keyLen = fromBytes(data[offset...offset+4])
        offset = offset + 4
        @serverKey = fromBytes(data[offset...offset+keyLen])
        @body = []
      end
      def to_s
        super() + "; serverKey: " + @serverKey.to_s
      end
    end
  end
end