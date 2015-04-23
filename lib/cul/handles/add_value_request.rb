module Cul
  module Handles
    class AddValueRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_ADD_VALUE)
      end
    end
  end
end