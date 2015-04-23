module Cul
  module Handles
    class ModifyValueRequest < HandleValueRequest
      def initialize(handle)
        super(handle)
        @opCode = asBytes(Hdl::OC_MODIFY_VALUE)
      end
    end
  end
end