module Cul
  module Handles
    class ModifyValueRequest < HandleValueRequest
      def initialize(handle)
        super()
        @opCode = asBytes(Hdl::OC_MODIFY_VALUE)
      end
    end
  end
end