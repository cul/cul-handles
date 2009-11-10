module Cul
  module Handles
    class RemoveValueRequest < BaseRequest
      include Hdl
      def initialize(handle)
        super()
        @opCode = asBytes(OC_REMOVE_VALUE)
        self.responseCode = 0
        @handle = toProtocolString(handle)
        @values = []
      end
    end
  end
end