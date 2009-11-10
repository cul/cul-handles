module Cul
  module Handles
    class ChallengeResponse < BaseResponse
      attr_reader :nonce, :digest
      def parseBody(data)
        # read digest
        digestAlg = data[0]
        if (digestAlg == 1)
          @digest = data[1..16]
          offset = 17
        else
          @digest = data[1..20]
          offset = 21
        end
        arrayInfo = readByteArray(data,offset)
        @nonce = arrayInfo[1]
      end
      def nonce
        @nonce
      end
    end
  end
end